package plan9asm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/arm64"
)

const featureAttrBase = 200

type featureAttrRegistry struct {
	order []string
	refs  map[string]string
}

func newFeatureAttrRegistry() *featureAttrRegistry {
	return &featureAttrRegistry{refs: make(map[string]string)}
}

func (r *featureAttrRegistry) ref(features string) string {
	if features == "" {
		return ""
	}
	if ref, ok := r.refs[features]; ok {
		return ref
	}
	ref := fmt.Sprintf("#%d", featureAttrBase+len(r.order))
	r.order = append(r.order, features)
	r.refs[features] = ref
	return ref
}

func (r *featureAttrRegistry) emit(b *strings.Builder) {
	if len(r.order) == 0 {
		return
	}
	for _, features := range r.order {
		fmt.Fprintf(b, "attributes %s = { \"target-features\"=%q }\n", r.refs[features], features)
	}
	b.WriteString("\n")
}

func inferFuncTargetFeatures(arch Arch, fn Func) string {
	return inferFuncTargetFeaturesForGOARCH(arch, "", fn)
}

func inferFuncTargetFeaturesForGOARCH(arch Arch, goarch string, fn Func) string {
	var featureSet []string
	add := func(features ...string) {
		for _, feature := range features {
			if feature == "" {
				continue
			}
			exists := false
			for _, v := range featureSet {
				if v == feature {
					exists = true
					break
				}
			}
			if !exists {
				featureSet = append(featureSet, feature)
			}
		}
	}

	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		switch arch {
		case ArchWASM:
			if strings.HasPrefix(op, "V128") || strings.HasPrefix(op, "I8X16") ||
				strings.HasPrefix(op, "I16X8") || strings.HasPrefix(op, "I32X4") ||
				strings.HasPrefix(op, "I64X2") || strings.HasPrefix(op, "F32X4") || strings.HasPrefix(op, "F64X2") {
				add("+simd128")
			}
		case ArchAMD64:
			switch {
			case goarch == "386" && (op == "MOVOU" || op == "PCMPEQB" || op == "PCMPEQL" || op == "PMOVMSKB"):
				add("+sse2")
			case strings.HasPrefix(op, "CRC32"):
				add("+crc32", "+sse4.2")
			case op == "PCLMULQDQ":
				add("+pclmul", "+sse4.1")
			case op == "PSHUFB" || op == "VPSHUFB":
				add("+ssse3")
			case op == "AESENC" || op == "AESENCLAST" || op == "AESDEC" || op == "AESDECLAST" || op == "AESIMC" || op == "AESKEYGENASSIST":
				add("+aes")
			}
		case ArchARM64:
			if ins.Op == OpWORD && len(ins.Args) == 1 && ins.Args[0].Kind == OpImm &&
				ins.Args[0].ImmRaw == "" && (uint32(ins.Args[0].Imm)>>25)&15 == 2 {
				if decoded, ok := arm64.DecodeRawWord(uint32(ins.Args[0].Imm)); ok {
					op = string(decoded.Op)
					ins = decoded
				}
			}
			if strings.HasPrefix(op, "CRC32") {
				add("+crc")
			}
			if arm64InstrUsesSVE(op, ins) {
				add("+sve")
			}
			if arm64InstrUsesSVE2(op) || (op == "ZTBL" && len(ins.Args) == 3 && len(ins.Args[1].RegList) == 2) {
				add("+sve", "+sve2")
			}
		case ArchARM:
			// Go's ARM runtime keeps VFP save/restore instructions in the
			// GOARM=5 image and guards their execution with goarmsoftfp. LLVM
			// still needs VFP enabled while assembling that otherwise-dead path.
			// Attach the feature only to functions which name VFP state or
			// floating-point registers; this does not raise the target-wide CPU
			// baseline.
			for _, arg := range ins.Args {
				var reg string
				switch arg.Kind {
				case OpReg:
					reg = strings.ToUpper(string(arg.Reg))
				case OpIdent:
					reg = strings.ToUpper(arg.Ident)
				default:
					continue
				}
				if reg == "FPCR" || reg == "FPSR" || strings.HasPrefix(reg, "F") {
					add("+vfp2")
					break
				}
			}
		}
	}

	if len(featureSet) == 0 {
		return ""
	}
	sort.Strings(featureSet)
	return strings.Join(featureSet, ",")
}

func arm64InstrUsesSVE(op string, ins Instr) bool {
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	switch op {
	case "RDVL", "ADDVL", "ADDPL", "CTERMEQ", "CTERMEQW", "CTERMNE", "CTERMNEW",
		"CNTB", "CNTH", "CNTW", "CNTD", "SETFFR",
		"PLDR", "PSTR", "PPFALSE", "PPTRUE", "PWRFFR", "PRDFFR", "PRDFFRS", "PPTEST",
		"PCNTP", "PFIRSTP", "PLASTP", "PINCP", "PDECP", "PREV", "PSEL",
		"PAND", "PANDS", "PBIC", "PBICS", "PEOR", "PEORS", "PNAND", "PNANDS",
		"PNOR", "PNORS", "PORN", "PORNS", "PORR", "PORRS":
		return true
	}
	if strings.HasPrefix(op, "PWHILE") || strings.HasPrefix(op, "PPRF") ||
		strings.HasPrefix(op, "PBRK") || strings.HasPrefix(op, "PSQINC") ||
		strings.HasPrefix(op, "PSQDEC") || strings.HasPrefix(op, "PUQINC") ||
		strings.HasPrefix(op, "PUQDEC") ||
		(len(op) >= 2 && op[0] == 'Z' && op[1] >= 'A' && op[1] <= 'Z') {
		return true
	}
	for _, a := range ins.Args {
		var txt string
		switch a.Kind {
		case OpReg:
			txt = string(a.Reg)
		case OpSym:
			txt = a.Sym
		case OpIdent:
			txt = a.Ident
		case OpRegList:
			for _, r := range a.RegList {
				u := strings.ToUpper(string(r))
				if (len(u) >= 2 && (u[0] == 'Z' || u[0] == 'P') && u[1] >= '0' && u[1] <= '9') ||
					(len(u) >= 3 && strings.HasPrefix(u, "PN") && u[2] >= '0' && u[2] <= '9') {
					return true
				}
			}
			continue
		default:
			continue
		}
		u := strings.ToUpper(strings.TrimSpace(txt))
		if (len(u) >= 2 && (u[0] == 'Z' || u[0] == 'P') && u[1] >= '0' && u[1] <= '9') ||
			(len(u) >= 3 && strings.HasPrefix(u, "PN") && u[2] >= '0' && u[2] <= '9') {
			return true
		}
	}
	return false
}

func arm64InstrUsesSVE2(op string) bool {
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	switch op {
	case "PWHILEGE", "PWHILEGEW", "PWHILEGT", "PWHILEGTW",
		"PWHILEHI", "PWHILEHIW", "PWHILEHS", "PWHILEHSW",
		"PWHILERW", "PWHILEWR", "ZUMULLB":
		return true
	}
	return false
}

var targetFeaturesAttr = regexp.MustCompile(`"target-features"\s*=\s*"([^"]*)"`)

func (r *featureAttrRegistry) merge(attrs, required string) (string, error) {
	if required == "" {
		return attrs, nil
	}
	if attrs == "" {
		return r.ref(required), nil
	}
	match := targetFeaturesAttr.FindStringSubmatchIndex(attrs)
	if match == nil {
		return attrs + " " + r.ref(required), nil
	}
	features := attrs[match[2]:match[3]]
	existing := strings.Split(features, ",")
	for _, want := range strings.Split(required, ",") {
		present := false
		for _, feature := range existing {
			if feature == "-"+want[1:] {
				return "", fmt.Errorf("required target feature %s conflicts with explicit %s", want, feature)
			}
			if feature == want {
				present = true
			}
		}
		if !present {
			if features != "" {
				features += ","
			}
			features += want
		}
	}
	return attrs[:match[2]] + features + attrs[match[3]:], nil
}
