package plan9asm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The original Go programs contain KMOVQ, but their runtime owners execute
// translated LLVM, not the Go machine objects. Observe that actual backend
// output before inferring a BW requirement from a source spelling.
func x86OriginalFloatingOpcodeListing(t *testing.T, profile, triple, level, ir string, masked bool, fmas int) {
	t.Helper()
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("actual floating runtime ISA requires LLVM22 llc and llvm-objdump")
	}
	listing := x86FourSourceNativeObjectListing(t, llc, objdump, triple, level, ir)
	x86OriginalFloatingAuditListing(t, profile, triple, level, listing, masked, fmas)
}

// Native family owners can inspect the exact object they subsequently execute;
// the ordinary object owner and its finite ISA contract use the same auditor.
func x86OriginalFloatingAuditListing(t *testing.T, profile, triple, level, listing string, masked bool, fmas int) {
	t.Helper()
	var violations []string
	if strings.Contains(listing, "<unknown>") || strings.Contains(listing, "invalid") {
		violations = append(violations, "actual object contains an undecoded instruction:\n"+listing)
	}
	rows := regexp.MustCompile(`(?m)^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)([a-z][a-z0-9.]*)`).FindAllStringSubmatch(listing, -1)
	if len(rows) == 0 {
		t.Fatal("actual original floating runtime object has no independent machine instructions", listing)
	}
	seen, kmovw, fmaCount := make(map[string]bool), 0, 0
	for _, row := range rows {
		op := row[2]
		seen[op] = true
		if op == "kmovw" {
			kmovw++
		}
		if strings.HasPrefix(op, "vfm") || strings.HasPrefix(op, "vfnm") {
			fmaCount++
		}
		// BW/DQ opmask transports are not interchangeable with the F-only
		// same-call KMOVW used by these floating native emitters.
		if strings.HasPrefix(op, "k") && !x86OriginalFloatingFMaskOpcode(op) {
			violations = append(violations, "non-F opmask ISA: "+row[0])
		}
		code, err := hex.DecodeString(strings.Join(strings.Fields(row[1]), ""))
		if err != nil || len(code) == 0 {
			violations = append(violations, fmt.Sprintf("incomplete physical bytes: %s: %v", row[0], err))
			continue
		}
		if code[0] == 0x62 && !x86OriginalFloatingEVEXWithinProfile(profile, op, code) {
			violations = append(violations, "EVEX outside actual owner profile: "+row[0])
		}
	}
	if masked && kmovw == 0 || fmaCount != fmas {
		violations = append(violations, fmt.Sprintf("native operation inventory differs: KMOVW=%d masked=%t FMA=%d want=%d", kmovw, masked, fmaCount, fmas))
	}
	var inventory []string
	for op := range seen {
		inventory = append(inventory, op)
	}
	sort.Strings(inventory)
	t.Logf("actual LLVM22 %s %s %s: %d instructions, KMOVW=%d, FMA=%d, opcodes=%s; object evidence, not CPU execution",
		profile, triple, level, len(rows), kmovw, fmaCount, strings.Join(inventory, ","))
	if len(violations) != 0 {
		t.Fatalf("actual %s %s %s has %d ISA/identity violations:\n%s\ncomplete actual opcode inventory: %s",
			profile, triple, level, len(violations), strings.Join(violations, "\n"), strings.Join(inventory, ","))
	}
}

func x86OriginalFloatingFMaskOpcode(op string) bool {
	switch op {
	case "kmovw", "kandw", "kandnw", "korw", "kxorw", "kxnorw", "knotw", "kortestw":
		return true
	}
	return false
}

// This is a deliberately bounded independent ISA contract for these two
// original runtime programs, not a general instruction/CPUID classifier.
// Unknown backend choices require review instead of silently adding a CPU bit.
func x86OriginalFloatingEVEXWithinProfile(profile, op string, code []byte) bool {
	estimate := profile == "estimate14-F" || profile == "estimate14-FVL"
	if !estimate && profile != "scalar-precision" && profile != "fma-caller" || len(code) < 6 || code[0] != 0x62 {
		return false
	}
	known, scalar, fma := false, false, false
	for _, member := range append(go127FMA3PackedOps(), go127FMA3ScalarOps()...) {
		if op == strings.ToLower(member) {
			known, fma = true, true
			scalar = strings.HasSuffix(member, "SS") || strings.HasSuffix(member, "SD")
		}
	}
	switch op {
	case "vcvtsd2ss", "vcvtss2sd", "vmovss", "vmovsd":
		known, scalar = true, true
	case "vmovaps", "vmovapd", "vmovups", "vmovupd",
		"vmovdqa32", "vmovdqa64", "vmovdqu32", "vmovdqu64", "vpxord", "vpxorq",
		"vpandd", "vpandq", "vpandnd", "vpandnq", "vpord", "vporq", "vpternlogd", "vpternlogq",
		"vbroadcastss", "vbroadcastsd", "vextractf32x4", "vextracti32x4", "vextractf64x4", "vextracti64x4",
		"vinsertf32x4", "vinserti32x4", "vinsertf64x4", "vinserti64x4", "vshuff32x4", "vshufi32x4",
		"vshufps", "vshufpd", "vpermilps", "vpermilpd",
		"vpslld", "vpsllq", "vpsrld", "vpsrlq", "vpsrad", "vpsraq",
		"vpsllvd", "vpsllvq", "vpsrlvd", "vpsrlvq", "vpsravd", "vpsravq",
		"vpmovdb", "vpmovdw", "vpmovqb", "vpmovqd", "vpmovqw",
		"vpmovsdb", "vpmovsdw", "vpmovsqb", "vpmovsqd", "vpmovsqw",
		"vpmovusdb", "vpmovusdw", "vpmovusqb", "vpmovusqd", "vpmovusqw":
		known = true
	}
	if estimate {
		if fma {
			return false
		}
		for _, member := range x86Reciprocal14TestMembers {
			if op == strings.ToLower(member.op) {
				known, scalar = true, member.scalar
			}
		}
	}
	if !known {
		return false
	}
	// The disassembler has already validated each complete instruction. LL
	// is ignored by scalar forms, and is RC (not vector width) for packed
	// register FMA with embedded rounding; that latter form is always Z512.
	if scalar || fma && code[3]&0x10 != 0 && code[5]&0xc0 == 0xc0 {
		return true
	}
	length := code[3] >> 5 & 3
	return length == 2 || (profile == "fma-caller" || profile == "estimate14-FVL") && length < 2
}

func TestX86OriginalFloatingRuntimeEVEXProfileBoundaries(t *testing.T) {
	type axis struct {
		op      string
		scalar  bool
		rounder bool
		memory  bool
	}
	rows := []axis{
		{op: "vmovups"}, {op: "vmovdqa64"}, {op: "vpxord"}, {op: "vfmadd132ps"},
		{op: "vcvtsd2ss", scalar: true}, {op: "vcvtss2sd", scalar: true},
		{op: "vfmadd132ss", scalar: true}, {op: "vfmadd132pd", rounder: true},
		{op: "vfmadd132pd", memory: true},
	}
	// Intel SDM Vol.2B PSLL/PSRL/PSRA and Vol.2C VPSLLV/VPSRLV/
	// VPSRAV independently specify all twelve EVEX D/Q shifts as F for
	// Z512 and F+VL for X/Y. Uniform/immediate and per-lane count roles
	// do not turn those into the separate BW word/byte shift operations.
	for _, stem := range []string{"vpsll", "vpsrl", "vpsra"} {
		for _, variable := range []string{"", "v"} {
			for _, lane := range []string{"d", "q"} {
				rows = append(rows, axis{op: stem + variable + lane})
			}
		}
	}
	// SDM Vol.2C 5-577..599 gives all five D/Q-source narrowing ratios
	// with truncation, signed saturation and unsigned saturation. Their LL
	// field measures the source carrier, not the smaller byte/word result.
	for _, saturation := range []string{"", "s", "us"} {
		for _, ratio := range []string{"db", "dw", "qb", "qd", "qw"} {
			rows = append(rows, axis{op: "vpmov" + saturation + ratio})
		}
	}
	if len(rows) != 36 {
		t.Fatal("complete original profile, twelve F shifts or fifteen F narrowing names changed", len(rows))
	}
	for _, profile := range []string{"scalar-precision", "fma-caller"} {
		for length := byte(0); length < 4; length++ {
			for _, row := range rows {
				t.Run(fmt.Sprintf("%s/%s/memory%t/LL%d", profile, row.op, row.memory, length), func(t *testing.T) {
					// Synthetic field projection, not an independent valid-encoding
					// prior. Actual object checks above own complete LLVM decoding.
					code := []byte{0x62, 0xf1, 0x7c, length << 5, 0x10, 0xc0}
					if row.rounder {
						code[3] |= 0x10
					}
					if row.memory {
						code[3] |= 0x10
						code[5] = 0
					}
					want := row.scalar || row.rounder || length == 2 || profile == "fma-caller" && length < 2
					if x86OriginalFloatingEVEXWithinProfile(profile, row.op, code) != want {
						t.Fatal("scalar LLIG or Z512 ER granted VL to a packed transport", code, want)
					}
				})
			}
		}
		for _, op := range []string{
			"vpsllw", "vpsrlw", "vpsraw", "vpsllvw", "vpsrlvw", "vpsravw", "vpslldq", "vpsrldq", "vpmullq",
			"vpmovwb", "vpmovswb", "vpmovuswb",
		} {
			if x86OriginalFloatingEVEXWithinProfile(profile, op, []byte{0x62, 0xf1, 0x7c, 0x48, 0x10, 0xc0}) {
				t.Fatal("F-only D/Q shifts admitted an independent BW word/byte or DQ operation", profile, op)
			}
		}
	}
	for _, op := range []string{"kmovb", "kmovd", "kmovq", "kaddw", "ktestw", "kandq"} {
		if x86OriginalFloatingFMaskOpcode(op) {
			t.Fatal("F-only mask inventory borrowed a BW/DQ opcode", op)
		}
	}
	for _, row := range []struct {
		profile string
		code    []byte
	}{
		{"unknown", []byte{0x62, 0xf1, 0x7c, 0x48, 0x10, 0xc0}},
		{"scalar-precision", []byte{0x62, 0xf1, 0x7c, 0x48, 0x10}},
		{"fma-caller", []byte{0xc4, 0xf1, 0x7c, 0x48, 0x10, 0xc0}},
	} {
		if x86OriginalFloatingEVEXWithinProfile(row.profile, "vmovups", row.code) {
			t.Fatal("profile projection invented a known owner or complete EVEX instruction", row)
		}
	}
}

func x86OriginalFloatingRuntimeObjectPipelines(t *testing.T, profile, triple, ir string, masked bool, fmas int) {
	t.Helper()
	for _, pipeline := range []struct{ name, body, level string }{
		{"O0", ir, "-O0"}, {"O2", ir, "-O2"}, {"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			x86OriginalFloatingOpcodeListing(t, profile, triple, pipeline.level, pipeline.body, masked, fmas)
		})
	}
}

func TestX86OriginalScalarPrecisionRuntimeActualBackendISA(t *testing.T) {
	source := x86ScalarPrecisionOriginalProgram(t)
	if strings.Count(source, "KMOVQ mask+40(FP), K1") != 1 {
		t.Fatal("original Go KMOVQ memory transport changed")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			// Keep the original owner's exact five pointer/one I64 manual ABI0
			// declaration, not a different typed or caller translation route.
			frame := FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				{Offset: 40, Type: I64, Index: 5, Field: -1},
			}}
			ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "amd64", Sigs: map[string]FuncSig{
				"scalarPrecisionConvertSemantics": {Name: "scalarPrecisionConvertSemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
			}})
			if err != nil {
				t.Fatal("original scalar runtime translation failed before actual backend ISA observation", err)
			}
			x86OriginalFloatingRuntimeObjectPipelines(t, "scalar-precision", triple, ir, true, 0)
		})
	}
}

func x86OriginalFMACallerObjectSource(t *testing.T, formats []string, first int) (string, string) {
	t.Helper()
	data, file, set := x86OriginalFloatingPolicyFile(t, "amd64_go_caller_fma3_runtime_test.go")
	batch := x86OriginalFloatingPolicyFunction(t, file, "runX86FMA3GoCallerNumericalBatch")
	if fmt.Sprintf("%x", sha256.Sum256(data[set.Position(batch.Pos()).Offset:set.Position(batch.End()).Offset])) !=
		"671c54ae2be89372425614cf9d9ef893080a25f929ad8e31d3087d69bbb927b7" || len(x86FMA3NamedFormats("amd64")) != 1836 {
		t.Fatal("complete original FMA runtime builder or 1836-format inventory changed")
	}
	var goSource, assembly strings.Builder
	goSource.WriteString("package caller\nimport \"unsafe\"\n")
	for index, instruction := range formats {
		name := fmt.Sprintf("fmacase%d", first+index)
		base := strings.Split(strings.Fields(instruction)[0], ".")[0]
		wide := strings.HasSuffix(base, "PD") || strings.HasSuffix(base, "SD")
		declaration := x86CallerFixtureSource[strings.Index(x86CallerFixtureSource, "//go:noescape"):]
		declaration = strings.ReplaceAll(declaration, "kernel", name)
		declaration = strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1)
		if wide {
			declaration = strings.ReplaceAll(declaration, "float32", "float64")
		}
		goSource.WriteString(declaration)
		bank := "X"
		if strings.Contains(instruction, "Y1") {
			bank = "Y"
		} else if strings.Contains(instruction, "Z1") {
			bank = "Z"
		}
		body := fmt.Sprintf("VMOVUPS (DI),%s0\nVMOVUPS (SI),%s1\nVMOVUPS 64(SI),%s2\nKMOVQ AX,K1\n", bank, bank, bank)
		body += strings.ReplaceAll(instruction, "(AX)", "(DI)") + "\n"
		store := "VMOVSS X2,(DX)"
		if wide {
			store = "VMOVSD X2,(DX)"
		}
		body += store
		machine := strings.ReplaceAll(x86CallerFixtureAssembly, "·kernel", "·"+name)
		machine = strings.Replace(machine, "MOVL $7,AX", "MOVQ (CX),AX", 1)
		assembly.WriteString(strings.Replace(machine, "MOVL AX,(DX)", body, 1))
	}
	return goSource.String(), assembly.String()
}

func TestX86OriginalFMACallerRuntimeActualBackendISA(t *testing.T) {
	for _, op := range []string{
		"vmovdqu8", "vmovdqu16", "vpmovb2m", "vpmovw2m", "vpaddb", "vpsllw",
		"vxorps", "vxorpd", "vextractf64x2", "vinserti64x2", "vfmadd132ph", "vfmadd132sh",
	} {
		if x86OriginalFloatingEVEXWithinProfile("fma-caller", op, []byte{0x62, 0xf1, 0x7c, 0x48, 0x10, 0xc0}) {
			t.Fatal("object opcode contract admitted an independent BW, DQ or FP16 dependency", op)
		}
	}
	formats := make(map[string]bool)
	for _, row := range x86FMA3NamedFormats("amd64") {
		formats[row] = true
	}
	var rows []string
	for _, row := range x86FMA3InitializedAxisRows("amd64") {
		if formats[row] { // Exclude eight high-bank axes absent from the original owner.
			rows = append(rows, row)
		}
	}
	if len(rows) != 170 {
		t.Fatal("original FMA runtime's complete orthogonal physical/transport inventory changed", len(rows))
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			for first := 0; first < len(rows); first += 64 {
				end := first + 64
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch%d", first/64), func(t *testing.T) {
					goSource, source := x86OriginalFMACallerObjectSource(t, rows[first:end], first)
					x86LEAActualTargetGoObject(t, "amd64", triple, source)
					pkg := x86CallerRuntimePackage(t, goSource, source)
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
						FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
						ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
					})
					if err != nil {
						t.Fatal("original FMA caller translation failed before backend ISA observation", err)
					}
					defer translation.Module.Dispose()
					masked := false
					for _, row := range rows[first:end] {
						masked = masked || strings.Contains(row, "K1")
					}
					x86OriginalFloatingRuntimeObjectPipelines(t, "fma-caller", triple, translation.Module.String(), masked, end-first)
				})
			}
		})
	}
	t.Log("170 original-owner orthogonal entries, not a new 1836-format Cartesian matrix or native CPU execution receipt")
}
