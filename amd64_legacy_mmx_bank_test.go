package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

// This census is independent of the implementation. Ordered Go tables,
// opcode prefixes and all opBytes remain available to each comparison.
type x86YMMOriginalRule struct {
	name, table, prefix, opBytes string
}

func x86YMMOriginalRules(t *testing.T) []x86YMMOriginalRule {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	var rules []x86YMMOriginalRule
	pattern := regexp.MustCompile(`\{A([A-Z0-9]+), (ymm|ymmxmm0f38|ymshuf|yps), (\w+), opBytes\{([^}]+)\}\}`)
	for _, row := range pattern.FindAllStringSubmatch(string(source), -1) {
		rules = append(rules, x86YMMOriginalRule{row[1], row[2], row[3], row[4]})
	}
	if len(rules) != 43 {
		t.Fatalf("complete integer MMX-read rule census changed: %d", len(rules))
	}
	return rules
}

func x86YMMReadSource(t *testing.T, row string) Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\n"+row+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestX86YMMExistingDescriptorsOriginalBank(t *testing.T) {
	var names []string
	for _, rule := range x86YMMOriginalRules(t) {
		if strings.HasPrefix(rule.name, "PUNPCK") || rule.name == "PAND" || rule.name == "PANDN" ||
			rule.name == "POR" || rule.name == "PXOR" || rule.table == "yps" && !strings.HasPrefix(rule.name, "PSRA") {
			names = append(names, rule.name)
		}
	}
	sort.Strings(names)
	if len(names) != 16 {
		t.Fatal("logical/unpack/uniform logical-shift descriptor class changed", names)
	}
	for _, name := range names {
		for index, source := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			t.Run(name+"/"+source, func(t *testing.T) {
				ins := x86YMMReadSource(t, name+" "+source+",M1")
				before := fmt.Sprintf("%#v", ins)
				var known bool
				var err error
				var selected Operand
				switch {
				case strings.HasPrefix(name, "PUNPCK"):
					var form x86PackedUnpackForm
					form, known, err = x86PackedUnpackProperties(ins, "amd64")
					selected = form.source
				case strings.HasPrefix(name, "PS"):
					var form x86PackedShiftForm
					form, known, err = x86PackedShiftProperties(ins.Op, ins, "amd64")
					selected = form.countOperand
				default:
					var form x86PackedLogicalForm
					form, known, err = x86PackedLogicalProperties(ins, "amd64")
					selected = form.source
				}
				if !known || err != nil {
					t.Errorf("actual Go MMX-read spelling is absent from pure descriptor: %t/%v", known, err)
				}
				if err == nil && (selected.Kind != OpReg || selected.Reg != Reg(fmt.Sprintf("M%d", index&7))) {
					t.Errorf("family descriptor retained the source GP bank: %+v", selected)
				}
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("pure descriptor mutated original source")
				}
			})
		}
	}
}

func TestX86YMMOriginalGoIntegerReadBanks(t *testing.T) {
	registers := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "M0", "M7"}
	var rows []string
	var expected []x86asm.Reg
	for _, rule := range x86YMMOriginalRules(t) {
		for index, source := range registers {
			prefix := ""
			if rule.table == "ymshuf" {
				prefix = "$27,"
			}
			rows = append(rows, rule.name+" "+prefix+source+",M1")
			bank := index & 7
			if source == "M0" {
				bank = 0
			} else if source == "M7" {
				bank = 7
			}
			expected = append(expected, x86asm.M0+x86asm.Reg(bank))
		}
	}
	// Alias has independent original Go evidence, not a prefix-name inference.
	rows = append(rows, "PADDD AX,M1")
	expected = append(expected, x86asm.M0)
	code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT probe(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n")
	t.Logf("complete original Go bytes=%x SHA256=%x", code, sha256.Sum256(code))
	for index, row := range rows {
		physical, err := x86asm.Decode(code, 64)
		if err != nil {
			t.Fatal("original object cannot be decoded", row, err)
		}
		if physical.Args[0] != x86asm.M1 || physical.Args[1] != expected[index] {
			t.Fatalf("original Go selected different physical register bank: %s bytes=%x operands=%v expected M1/%s",
				row, code[:physical.Len], physical.Args, expected[index])
		}
		decoded, err := decodeX86RawDirectiveGroup(code[:physical.Len], 64, 0, row, map[string]bool{})
		if err != nil || len(decoded) != 1 {
			t.Fatal("actual physical Go instruction did not decode as one typed row", row, decoded, err)
		}
		form, known, err := x86LegacyMMXReadProperties(decoded[0], "amd64")
		if !known || err != nil || form.gpSpelling || form.source.Reg != Reg(expected[index].String()) {
			t.Fatal("raw decoder changed the actual MMX bank into a source spelling", row, decoded, form, known, err)
		}
		code = code[physical.Len:]
	}
	if len(code) == 0 || code[0] != 0xc3 || !bytes.Equal(bytes.Trim(code[1:], "\x00"), nil) {
		t.Fatalf("original complete native instruction sequence has an unexpected tail: %x", code)
	}
	t.Logf("actual Go integer MMX-read rows=%d, physical M input independent of GP spelling", len(rows))
}

func TestX86YMMSelectorReusableDescriptorBanks(t *testing.T) {
	for _, rule := range x86YMMOriginalRules(t) {
		for index, register := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI",
			"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			row := rule.name + " " + register + ",M1"
			if rule.table == "ymshuf" {
				row = rule.name + " $27," + register + ",M1"
			}
			ins := x86YMMReadSource(t, row)
			form, known, err := x86LegacyMMXReadProperties(ins, "amd64")
			if !known || err != nil || !form.gpSpelling || !form.mmx || form.row != 0 ||
				form.source.Reg != Reg(fmt.Sprintf("M%d", index&7)) {
				t.Fatal("complete selector lost physical source bank", row, form, known, err)
			}
			effect, known, err := x86PackedBinaryByteEffect(ins.Op, ins, "amd64")
			if known {
				if err != nil || len(effect.operands) != 2 || effect.operands[0].operand.Reg != form.source.Reg ||
					effect.operands[0].width != 8 || !effect.operands[0].read || effect.operands[0].write {
					t.Fatal("existing byte descriptor does not share encoded bank selection", row, effect, err)
				}
			}
			if strings.HasPrefix(rule.name, "PACK") {
				pack, known, err := x86PackedNarrowProperties(ins, "amd64")
				if !known || err != nil || pack.source.Reg != form.source.Reg {
					t.Fatal("pack descriptor does not share encoded bank selection", row, pack, known, err)
				}
			}
		}
	}
}

func TestX86YMMSelectorContextIsBeforeIRAndKeepsInput(t *testing.T) {
	for _, rule := range x86YMMOriginalRules(t) {
		prefix := ""
		if rule.table == "ymshuf" {
			prefix = "$27,"
		}
		ins := x86YMMReadSource(t, rule.name+" "+prefix+"AX,M1")
		file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before, original := output.String(), fmt.Sprintf("%#v", ins)
		terminated, err := ctx.lowerInstr(0, 0, ins, nil, nil)
		if terminated || !errors.Is(err, ErrProbeNeedsContext) || before != output.String() || original != fmt.Sprintf("%#v", ins) {
			t.Fatal("source-bank Context was late or mutated the source/IR", rule.name, terminated, err)
		}
	}
}

func TestX86YMMSelectorCompleteOriginalOrderedRules(t *testing.T) {
	bytesSource, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(bytesSource)
	if len(x86LegacyMMXReadSpecs) != 43 {
		t.Fatal("selector class does not have exactly 43 canonical names")
	}
	for _, rule := range x86YMMOriginalRules(t) {
		t.Run(rule.name, func(t *testing.T) {
			spec, found := x86LegacyMMXReadSpecs[Op(rule.name)]
			if !found {
				t.Fatal("complete original integer read class lacks a selector")
			}
			table, prefix, opcodeBytes, rows := spec.encoderRows()
			var originalBytes []byte
			for _, token := range strings.Split(rule.opBytes, ",") {
				token = strings.TrimSpace(token)
				if token == "Pe" {
					token = "0x66"
				}
				value, err := strconv.ParseUint(token, 0, 8)
				if err != nil {
					t.Fatal("unknown original opBytes expression", token, err)
				}
				originalBytes = append(originalBytes, byte(value))
			}
			if table != rule.table || prefix != rule.prefix || !bytes.Equal(opcodeBytes, originalBytes) {
				t.Fatalf("selected encoding metadata differs from original Go: %s/%s %x; original=%+v %x",
					table, prefix, opcodeBytes, rule, originalBytes)
			}
			block := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(source)
			if len(block) != 2 {
				t.Fatal("original ordered table was not found", table)
			}
			pattern := regexp.MustCompile(`\{(Z\w+), (\d+), argList\{([^}]+)\}\}`)
			originalRows := pattern.FindAllStringSubmatch(block[1], -1)
			if len(rows) != len(originalRows) {
				t.Fatal("original ordered table row count changed")
			}
			byteOffset, xo := 0, 0
			if originalBytes[0] == 0x0f {
				xo = 1
			}
			for index, original := range originalRows {
				zoffset, _ := strconv.Atoi(original[2])
				classes := strings.Split(strings.ReplaceAll(original[3], " ", ""), ",")
				row := rows[index]
				if row.zcase != original[1] || row.zoffset != zoffset || row.byteOffset != byteOffset ||
					!reflect.DeepEqual(row.classes, classes) {
					t.Fatalf("ordered row %d differs: %+v original=%v offset=%d", index, row, original, byteOffset)
				}
				byteOffset += zoffset + xo
			}
		})
	}
}

func TestX86YMMSelectorCompleteRolesAndImmutability(t *testing.T) {
	for _, rule := range x86YMMOriginalRules(t) {
		for destination := 0; destination < 8; destination++ {
			for source := 0; source < 8; source++ {
				prefix := ""
				if rule.table == "ymshuf" {
					prefix = "$27,"
				}
				ins := x86YMMReadSource(t, fmt.Sprintf("%s %sM%d,M%d", rule.name, prefix, source, destination))
				before := fmt.Sprintf("%#v", ins)
				form, known, err := x86LegacyMMXReadProperties(ins, "amd64")
				if !known || err != nil || !form.mmx || form.gpSpelling || form.row != 0 ||
					form.byteWidth != 8 || form.memoryBytes != 0 || form.source.Reg != Reg(fmt.Sprintf("M%d", source)) {
					t.Fatal("literal MMX source/destination role changed", ins, form, known, err)
				}
				local, err := x86LegacyMMXReadInstruction(ins, "amd64")
				if err != nil || before != fmt.Sprintf("%#v", ins) {
					t.Fatal("selector mutated original", err)
				}
				local.Args[form.sourceIndex].Reg = "M6"
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("normalized operand slice aliases original")
				}
			}
		}
		prefix := ""
		if rule.table == "ymshuf" {
			prefix = "$27,"
		}
		for _, bank := range []string{"M", "X"} {
			if bank == "X" && rule.table == "ymshuf" {
				continue
			}
			ins := x86YMMReadSource(t, rule.name+" "+prefix+"(AX),"+bank+"1")
			form, known, err := x86LegacyMMXReadProperties(ins, "amd64")
			want := 16
			if bank == "M" {
				want = 8
				if strings.HasPrefix(rule.name, "PUNPCKL") {
					want = 4
				}
			}
			if !known || err != nil || form.memoryBytes != want || form.gpSpelling {
				t.Fatal("complete native read shape changed", ins, form, known, err)
			}
			if rule.table == "yps" {
				for _, count := range []int{-128, 0, 127} {
					ins = x86YMMReadSource(t, fmt.Sprintf("%s $%d,%s1", rule.name, count, bank))
					form, known, err = x86LegacyMMXReadProperties(ins, "amd64")
					if !known || err != nil || form.row != 1 && form.row != 3 || form.memoryBytes != 0 || form.gpSpelling {
						t.Fatal("immediate row borrowed a bank read", ins, form, known, err)
					}
				}
			}
		}
	}
}

func TestX86YMMSelectorActualGoModeAndRoleBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, rule := range x86YMMOriginalRules(t) {
			prefix := ""
			if rule.table == "ymshuf" {
				prefix = "$27,"
			}
			row := rule.name + " " + prefix + "AX,M1"
			source := "TEXT probe(SB),4,$0-0\n" + row + "\nRET\n"
			want := arch == "amd64" || rule.table == "ymshuf" || rule.table == "ymmxmm0f38"
			goAssemblerOracleOutput(t, arch, source, "", want)
			form, known, err := x86LegacyMMXReadProperties(x86YMMReadSource(t, row), arch)
			if !known || (err == nil) != want || want && (form.source.Reg != "M0" || !form.gpSpelling) {
				t.Fatal("actual named mode admission differs from selector", arch, row, form, known, err)
			}
			if want {
				code := x86PackedShiftActualGoBytes(t, arch, source)
				mode := 64
				if arch == "386" {
					mode = 32
				}
				physical, err := x86asm.Decode(code, mode)
				if err != nil || physical.Args[0] != x86asm.M1 || physical.Args[1] != x86asm.M0 {
					t.Fatal("actual accepted mode did not select physical MMX", arch, row, physical, err)
				}
			}
		}
	}
	for _, row := range []string{"PAND M0,X1", "PAND X0,M1", "PAND AX,X1", "PAND M0,AX",
		"PAND R8,M1", "PSHUFW $128,M0,M1", "PSHUFW $-129,M0,M1", "PSRLW $128,X1"} {
		arch := "amd64"
		if row == "PAND R8,M1" {
			arch = "386"
		}
		goAssemblerOracleOutput(t, arch, "TEXT probe(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		_, known, err := x86LegacyMMXReadProperties(x86YMMReadSource(t, row), arch)
		if !known || err == nil {
			t.Fatal("original Go rejected row obtained a pure bank form", arch, row, known, err)
		}
	}
}

func TestX86YMMSelectorActualMode32GPSpellings(t *testing.T) {
	for _, name := range []string{"PHADDD", "PSHUFW"} {
		for index, register := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI",
			"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			prefix := ""
			if name == "PSHUFW" {
				prefix = "$27,"
			}
			row := name + " " + prefix + register + ",M1"
			source := "TEXT probe(SB),4,$0-0\n" + row + "\nRET\n"
			want := index < 8
			goAssemblerOracleOutput(t, "386", source, "", want)
			form, known, err := x86LegacyMMXReadProperties(x86YMMReadSource(t, row), "386")
			if !known || (err == nil) != want || want && form.source.Reg != Reg(fmt.Sprintf("M%d", index)) {
				t.Fatal("mode32 original GP class does not match selected MMX bank", row, form, known, err)
			}
		}
	}
}

func TestX86YMMSelectorExcludesRealGPRolesAndPhysicalForgery(t *testing.T) {
	for _, row := range []string{"MOVQ AX,M1", "PINSRB $0,AX,X1", "PINSRD $0,AX,X1", "PINSRQ $0,AX,X1",
		"PEXTRB $0,X1,AX", "PEXTRD $0,X1,AX", "PEXTRQ $0,X1,AX", "CVTPL2PS M0,X1", "CVTPL2PD M0,X1"} {
		_, known, err := x86LegacyMMXReadProperties(x86YMMReadSource(t, row), "amd64")
		if known || err != nil {
			t.Fatal("different ordered GP/x87 role was claimed by integer read selector", row, known, err)
		}
	}
	for _, rule := range x86YMMOriginalRules(t) {
		prefix := ""
		if rule.table == "ymshuf" {
			prefix = "$27,"
		}
		ins := x86YMMReadSource(t, rule.name+" "+prefix+"AX,M1")
		ins.x86Encoded = true
		if _, known, err := x86LegacyMMXReadProperties(ins, "amd64"); !known || err == nil {
			t.Fatal("physical decoder identity acquired source-only GP compatibility", rule.name)
		}
		ins.Args[len(ins.Args)-2].Reg = "M0"
		if form, known, err := x86LegacyMMXReadProperties(ins, "386"); !known || err != nil || form.gpSpelling {
			t.Fatal("actual physical MMX input was changed into a source alias", rule.name, form, known, err)
		}
	}
	for _, row := range []string{"PAND.BAD AX,M1", "PAND AX,M8", "PSHUFW $0,AX,X1"} {
		if _, known, err := x86LegacyMMXReadProperties(x86YMMReadSource(t, row), "amd64"); !known || err == nil {
			t.Fatal("malformed selector identity was accepted", row)
		}
	}
}

func TestX86YMMSelectorDoesNotGrantEmitterOrCallerAuthority(t *testing.T) {
	for _, rule := range x86YMMOriginalRules(t) {
		prefix := ""
		if rule.table == "ymshuf" {
			prefix = "$27,"
		}
		row := rule.name + " " + prefix + "AX,M1"
		ins := x86YMMReadSource(t, row)
		if !errors.Is(x86LegacyMMXReadEmitterContext(ins, "amd64"), ErrProbeNeedsContext) || x86CallerVectorMoveKnown(ins) {
			t.Fatal("bank identity alone acquired transport or caller permission", row)
		}
		ins.Args[len(ins.Args)-2].Reg = "M0"
		state := x86SourceStackState{vectors: map[Reg]uint64{}, masks: map[Reg]bool{}}
		if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &state, &x86GoCallerRegionProof{}) {
			t.Fatal("undefined MMX input acquired a caller value", rule.name)
		}
		pkg := mustGoPackage(t, "probe", "package probe\nfunc probe()\n")
		source := "TEXT ·probe(SB),4,$0-0\n" + row + "\nRET\n"
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"probe": {Ret: Void}},
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("text API granted unproved MMX source transport", row, triple, err)
			}
			context := llvm.NewContext()
			func() {
				defer context.Dispose()
				module, err := TranslateModuleInContext(context, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("module API granted unproved MMX source transport", row, triple, err)
				}
				result, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
					GOARCH: "amd64", TargetTriple: triple, ResolveSym: options.ResolveSym})
				if result != nil && !result.Module.IsNil() {
					defer result.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Go API granted unproved MMX source transport", row, triple, err)
				}
			}()
		}
	}
}

func TestX86YMMSelectorFiveTargetRegisteredXMMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
		"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		arch := "amd64"
		if strings.HasPrefix(triple, "i") {
			arch = "386"
		}
		source := "TEXT ·probe(SB),4,$0-16\nMOVOU value+0(FP),X0\nMOVOU value+0(FP),X1\n"
		count := 0
		for _, rule := range x86YMMOriginalRules(t) {
			if rule.table == "ymshuf" {
				continue // This original row is MMX-only, not an XMM grant.
			}
			source += rule.name + " X0,X1\n"
			count++
		}
		source += "RET\n"
		if count != 42 {
			t.Fatal("complete original XMM subdomain changed", count)
		}
		goAssemblerOracleOutput(t, arch, source, "", true)
		pkg := mustGoPackage(t, "probe", "package probe\nfunc probe(value [16]byte)\n")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := DeriveGoFuncABI0Signature("probe", pkg.Types.Scope().Lookup("probe").(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: arch, TargetTriple: triple,
			Sigs:       map[string]FuncSig{"probe": sig},
			ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
		ir, err := Translate(file, options)
		if err != nil {
			t.Fatal(triple, err)
		}
		x86ResultInitializationObject(t, llc, triple, ir, "ymm-selector-text")
		context := llvm.NewContext()
		func() {
			defer context.Dispose()
			module, err := TranslateModuleInContext(context, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(triple, err)
			}
			x86ResultInitializationObject(t, llc, triple, module.String(), "ymm-selector-module")
			result, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
				GOARCH: arch, TargetTriple: triple, ResolveSym: options.ResolveSym})
			if result != nil && !result.Module.IsNil() {
				defer result.Module.Dispose()
			}
			if err != nil {
				t.Fatal(triple, err)
			}
			x86ResultInitializationObject(t, llc, triple, result.Module.String(), "ymm-selector-go")
		}()
	}
}

func TestX86YMMOriginalGoOrderedGPControls(t *testing.T) {
	for _, row := range []string{"MOVQ AX,M1", "PINSRB $0,AX,X1", "PINSRD $0,AX,X1", "PINSRQ $0,AX,X1",
		"PEXTRB $0,X1,AX", "PEXTRD $0,X1,AX", "PEXTRQ $0,X1,AX"} {
		t.Run(row, func(t *testing.T) {
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT probe(SB),4,$0-0\n"+row+"\nRET\n")
			physical, err := x86asm.Decode(code, 64)
			if err != nil {
				t.Fatal(err)
			}
			for _, arg := range physical.Args {
				if arg == x86asm.M0 {
					t.Fatal("actual transfer/insertion/extraction GP role was changed to MMX", physical)
				}
			}
			if reflect.DeepEqual(physical.Args, x86asm.Args{}) {
				t.Fatal("control has no actual decoded operands")
			}
		})
	}
}
