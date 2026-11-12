package plan9asm

import (
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86SignedPackedFloatRows(arch string) []string {
	var rows []string
	last := 15
	if arch == "386" {
		last = 7
	}
	for _, op := range []string{"CVTPL2PS", "CVTPL2PD"} {
		for _, source := range []string{"X0", "M0", "M7", "3(AX)", "16(AX)(CX*4)", "3(FS)", "16(GS)", "256"} {
			rows = append(rows, fmt.Sprintf("%s %s,X%d", op, source, last))
		}
	}
	for _, op := range []string{"VCVTDQ2PS", "VCVTDQ2PD"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			src := bank
			if op == "VCVTDQ2PD" {
				src = "X"
				if bank == "Z" {
					src = "Y"
				}
			}
			for _, input := range []string{src + "0", "3(AX)", "16(AX)(CX*4)", "3(FS)", "16(GS)", "256"} {
				for _, mode := range []string{"", "K1,", "K7,"} {
					name := op
					if mode == "K7," {
						name += ".Z"
					}
					rows = append(rows, fmt.Sprintf("%s %s,%s%s7", name, input, mode, bank))
				}
			}
			for _, mask := range []string{"", "K1,", "K7,"} {
				name := op + ".BCST"
				if mask == "K7," {
					name += ".Z"
				}
				rows = append(rows, fmt.Sprintf("%s 3(AX),%s%s7", name, mask, bank))
			}
			if arch == "amd64" {
				rows = append(rows, fmt.Sprintf("%s %s31,%s31", op, src, bank), fmt.Sprintf("%s %s20,K3,%s21", op, src, bank))
			}
		}
		rows = append(rows, op+" X0,X0")
		if op == "VCVTDQ2PS" {
			rows = append(rows, op+" Y0,Y0")
		}
	}
	for _, rc := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
		for _, mask := range []string{"", "K1,", "K7,"} {
			name := "VCVTDQ2PS." + rc
			if mask == "K7," {
				name += ".Z"
			}
			rows = append(rows, name+" Z0,"+mask+"Z7")
		}
	}
	return rows
}

func TestX86SignedPackedIntegerFloatCompleteGoTables(t *testing.T) {
	dir := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86")
	legacy, err := os.ReadFile(filepath.Join(dir, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(dir, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"var yxcvm2 = []ytab{\n\t{Zm_r_xm, 2, argList{Yxm, Yxr}},\n\t{Zm_r_xm, 2, argList{Ymm, Yxr}},\n}",
		"{ACVTPL2PD, yxcvm2, Px, opBytes{Pf3, 0xe6, Pe, 0x2a}}", "{ACVTPL2PS, yxcvm2, Pm, opBytes{0x5b, 0, 0x2a, 0}}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatalf("actual Go legacy table changed: %s", row)
		}
	}
	for _, table := range []string{"_yvcvtdq2ps", "_yvcvtdq2pd"} {
		start := strings.Index(string(avx), "var "+table+" = []ytab{")
		if start < 0 {
			t.Fatal(table)
		}
		body := strings.SplitN(string(avx)[start:], "\n}", 2)[0]
		if strings.Count(body, "zcase:") != 8 {
			t.Fatalf("%s rows changed: %s", table, body)
		}
		for _, destination := range []string{"YxrEvex", "YyrEvex", "Yzr"} {
			source := "YxmEvex"
			if table == "_yvcvtdq2ps" && destination == "YyrEvex" || destination == "Yzr" {
				source = "YymEvex"
			}
			if table == "_yvcvtdq2ps" && destination == "Yzr" {
				source = "Yzm"
			}
			for _, row := range []string{fmt.Sprintf("args: argList{%s, %s}", source, destination), fmt.Sprintf("args: argList{%s, Yknot0, %s}", source, destination)} {
				if !strings.Contains(body, row) {
					t.Fatalf("actual %s row changed: %s", table, row)
				}
			}
		}
	}
	for name, expected := range x86SignedPackedFloatGoOpcodeRows {
		if err := x86SignedPackedFloatValidateGoOpcodeRows(string(avx), name, expected); err != nil {
			t.Fatal(err)
		}
	}
	if len(x86SignedPackedFloatSpecs) != 4 {
		t.Fatal("signed dword family namespace incomplete")
	}
}

// Independent full Go encoder rows: tuple agreement alone cannot establish
// W, pp, opcode map, opcode byte or the absence of extra SAE/ER attributes.
// Order is significant because the ytab's zoffset selects these byte groups.
var x86SignedPackedFloatGoOpcodeRows = map[string]string{
	"VCVTDQ2PD": `{as: AVCVTDQ2PD, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0xE6,
		avxEscape | vex256 | vexF3 | vex0F | vexW0, 0xE6,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN8 | evexBcstN4 | evexZeroingEnabled, 0xE6,
		avxEscape | evex256 | evexF3 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xE6,
		avxEscape | evex512 | evexF3 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xE6,
	}},`,
	"VCVTDQ2PS": `{as: AVCVTDQ2PS, ytab: _yvcvtdq2ps, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex0F | vexW0, 0x5B,
		avxEscape | vex256 | vex0F | vexW0, 0x5B,
		avxEscape | evex512 | evex0F | evexW0, evexN64 | evexBcstN4 | evexRoundingEnabled | evexZeroingEnabled, 0x5B,
		avxEscape | evex128 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x5B,
		avxEscape | evex256 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x5B,
	}},`,
}

func x86SignedPackedFloatValidateGoOpcodeRows(source, name, expected string) error {
	marker := "{as: A" + name + ","
	if strings.Count(source, marker) != 1 {
		return fmt.Errorf("actual Go %s opcode entry missing or duplicated", name)
	}
	start := strings.Index(source, marker)
	const end = "\n\t}},"
	length := strings.Index(source[start:], end)
	if length < 0 {
		return fmt.Errorf("actual Go %s opcode entry unterminated", name)
	}
	actual := source[start : start+length+len(end)]
	actualTokens, err := x86SignedPackedFloatGoOpcodeTokens(actual)
	if err != nil {
		return err
	}
	expectedTokens, err := x86SignedPackedFloatGoOpcodeTokens(expected)
	if err != nil {
		return err
	}
	if strings.Join(actualTokens, "\x00") != strings.Join(expectedTokens, "\x00") {
		return fmt.Errorf("actual Go %s complete encoding rows changed:\n%s", name, actual)
	}
	return nil
}

func x86SignedPackedFloatGoOpcodeTokens(source string) ([]string, error) {
	var lexer scanner.Scanner
	var scanError error
	file := token.NewFileSet().AddFile("opcode-rows", -1, len(source))
	lexer.Init(file, []byte(source), func(position token.Position, message string) {
		scanError = fmt.Errorf("Go opcode row %s: %s", position, message)
	}, 0)
	var tokens []string
	for {
		_, kind, literal := lexer.Scan()
		if kind == token.EOF {
			break
		}
		if literal == "" {
			literal = kind.String()
		}
		tokens = append(tokens, literal)
	}
	return tokens, scanError
}

func TestX86SignedPackedIntegerFloatGoOpcodeAttributesCannotChange(t *testing.T) {
	for name, expected := range x86SignedPackedFloatGoOpcodeRows {
		t.Run(name, func(t *testing.T) {
			if err := x86SignedPackedFloatValidateGoOpcodeRows(expected, name, expected); err != nil {
				t.Fatal(err)
			}
			type rowMutation struct{ name, old, replacement string }
			mutations := []rowMutation{
				{"VEX W", "vexW0", "vexW1"},
				{"EVEX W", "evexW0", "evexW1"},
				{"VEX map", "vex0F", "vex0F38"},
				{"EVEX map", "evex0F", "evex0F38"},
				{"VEX pp", "vex128 |", "vex128 | vex66 |"},
				{"EVEX pp", "evex128 |", "evex128 | evex66 |"},
				{"tuple", "evexN16", "evexN8"},
				{"broadcast", "evexBcstN4", "evexBcstN8"},
				{"zero", " | evexZeroingEnabled", ""},
				{"SAE", "evexZeroingEnabled", "evexZeroingEnabled | evexSaeEnabled"},
				{"duplicate entry", expected, expected + "\n" + expected},
			}
			if name == "VCVTDQ2PS" {
				mutations = append(mutations,
					rowMutation{"opcode", "0x5B", "0x5A"},
					rowMutation{"ER", " | evexRoundingEnabled", ""})
			} else {
				mutations = append(mutations,
					rowMutation{"opcode", "0xE6", "0xE7"},
					rowMutation{"ER", "evexZeroingEnabled", "evexZeroingEnabled | evexRoundingEnabled"})
			}
			lines := strings.Split(expected, "\n")
			mutations = append(mutations,
				rowMutation{"missing row", lines[1] + "\n", ""},
				rowMutation{"extra row", lines[1], lines[1] + "\n" + lines[1]},
				rowMutation{"row order", lines[1] + "\n" + lines[2], lines[2] + "\n" + lines[1]})
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					source := strings.Replace(expected, mutation.old, mutation.replacement, 1)
					if source == expected {
						t.Fatal("mutation did not change the original row")
					}
					if err := x86SignedPackedFloatValidateGoOpcodeRows(source, name, expected); err == nil {
						t.Fatal("encoding mutation passed the complete Go row contract")
					}
				})
			}
		})
	}
}

func TestX86SignedPackedIntegerFloatCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			sigs := map[string]FuncSig{}
			rows := x86SignedPackedFloatRows(target.arch)
			contextRows := 0
			for index, row := range rows {
				name := fmt.Sprintf("packed%d", index)
				one, err := Parse(ArchAMD64, "TEXT "+name+"(SB),4,$0-0\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				form, _, err := x86SignedPackedFloatProperties(one.Funcs[0].Instrs[1], target.arch)
				if err != nil {
					t.Fatal(err)
				}
				if form.mmx {
					goAssemblerOracleOutput(t, target.arch, "TEXT "+name+"(SB),4,$0-0\n"+row+"\nRET\n", "", true)
					opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{name: {Ret: Void}}}
					for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
						if _, err := x86SignedPackedFloatTranslate(one, opt, api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unclosed physical MMX caller was authorized", row, api, err)
						}
					}
					contextRows++
					continue
				}
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row)
				sigs[name] = FuncSig{Ret: Void}
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs}
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				ir, err := x86SignedPackedFloatTranslate(file, opt, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("uninitialized original conversion formats acquired vector or native inputs", api, err)
				}
			}
			ir := x86InstructionFormatObjectUnit(t, file, sigs, target.arch, target.triple, 0, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
				return c.lowerSignedPackedIntegerFloat(ins.Op, ins)
			})
			for _, text := range []string{ir, x86SignedIntegerFloatOptimize(t, ir)} {
				if strings.Contains(text, " = sitofp ") || strings.Contains(text, " = call <16 x float> @llvm.experimental.constrained.sitofp") || strings.Count(text, "asm sideeffect") != len(rows)-contextRows {
					t.Fatalf("original conversion format lost/scalarized native effects: native=%d expected%d", strings.Count(text, "asm sideeffect"), len(rows)-contextRows)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, text, level)
				}
			}
			t.Logf("%d actual Go accepted forms: %d emitter-only native objects, %d physical MMX Context rows; initialized public positives have their own complete owner", len(rows), len(rows)-contextRows, contextRows)
		})
	}
}

func x86SignedPackedFloatTranslate(file *File, opt Options, api string) (string, error) {
	if api == "Translate" {
		return Translate(file, opt)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	var module llvm.Module
	var err error
	if api == "TranslateModule" {
		module, err = TranslateModule(file, opt)
	} else {
		module, err = TranslateModuleInContext(ctx, file, opt)
	}
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return module.String(), nil
}

func TestX86SignedPackedIntegerFloatRetainsContextAndInvalidForms(t *testing.T) {
	for _, row := range []string{
		"CVTPL2PS AX,X0", "CVTPL2PD X0,Y1", "CVTPL2PS.Z X0,K1,X1", "VCVTDQ2PS Y0,X1", "VCVTDQ2PD Y0,Y1",
		"VCVTDQ2PD.SAE Y0,Z1", "VCVTDQ2PD.RN_SAE Y0,Z1", "VCVTDQ2PS.SAE Z0,Z1", "VCVTDQ2PS.RU_SAE X0,X1",
		"VCVTDQ2PS.RU_SAE (AX),Z1", "VCVTDQ2PS.BCST X0,X1", "VCVTDQ2PS.Z X0,X1", "VCVTDQ2PS X0,K0,X1",
		"VCVTDQ2PS.BCST.RU_SAE (AX),Z1", "VCVTDQ2PS X0,K1,(AX)",
	} {
		// Go's yxcvm2 also accepts a GP spelling that encodes an MMX
		// register. It is not a typed GP-source numerical contract.
		if row != "CVTPL2PS AX,X0" && row != "VCVTDQ2PS.Z X0,X1" {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); err == nil {
			t.Fatal("accepted invalid", row)
		}
	}
	for _, row := range []string{"CVTPL2PS (SP),X1", "CVTPL2PD (BP),X1", "VCVTDQ2PS (AX)(BP*2),Y1", "VCVTDQ2PS.Z p+0(FP),K1,Z1", "VCVTDQ2PD p+0(FP),X1"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		frame := FrameLayout{}
		args := []LLVMType{}
		for byte := 0; byte < 64; byte++ {
			frame.Params = append(frame.Params, FrameSlot{Offset: int64(byte), Type: I8, Index: byte, Field: -1})
			args = append(args, I8)
		}
		if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": {Ret: Void, Args: args, Frame: frame}}}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("fabricated native backing", row, err)
		}
	}
	for _, row := range []string{"VCVTDQ2PS X8,X0", "VCVTDQ2PS X0,X31", "VCVTDQ2PD X8,Y0", "VCVTDQ2PD Y0,Z8"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "386", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("fabricated mode32 physical bank", row, err)
		}
	}
}

func TestX86SignedPackedIntegerFloatActualGoMasklessZeroBoundary(t *testing.T) {
	asm, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	// The old encoder accepts EVEX.z without a nonzero writemask. Observe
	// its actual source/bytes, rather than guessing from runtime.Version.
	checksMask := strings.Contains(string(asm), "mask register must be specified for .Z instructions")
	const row = "VCVTDQ2PS.Z X0,X1"
	goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", !checksMask)
	if !checksMask {
		listing, err := x86ExtensionGoListing(t, "amd64", row)
		if err != nil {
			t.Fatal(err, listing)
		}
		var code []byte
		for _, line := range strings.Split(listing, "\n") {
			code = append(code, x86InsertExtractListedBytes(line)...)
		}
		if len(code) < 6 || code[0] != 0x62 || code[3]&0x87 != 0x80 {
			t.Fatal("historical maskless zero encoding changed", code)
		}
		if _, _, known, err := decodedX86SameWidthConversionInstruction(code, 64); !known || err == nil {
			t.Fatal("invalid maskless zero machine code accepted", code, known, err)
		}
	}
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); err == nil {
		t.Fatal("maskless zero acquired a valid native contract")
	}
}

func TestX86SignedPackedIntegerFloatGoSuffixOrder(t *testing.T) {
	for _, row := range []string{
		"VCVTDQ2PS.Z.BCST (AX),K1,X1", "VCVTDQ2PD.Z.BCST (AX),K1,Y1",
		"VCVTDQ2PS.Z.RN_SAE Z0,K1,Z1", "VCVTDQ2PS.Z.RD_SAE Z0,K1,Z1",
		"VCVTDQ2PS.Z.RU_SAE Z0,K1,Z1", "VCVTDQ2PS.Z.RZ_SAE Z0,K1,Z1",
	} {
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); err == nil {
			t.Fatal("accepted invalid modifier order", row)
		}
	}
}

func TestX86SignedPackedIntegerFloatMMXUnclosedCallerContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		registers := []string{"M0", "M1", "M7", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
		if arch == "amd64" {
			registers = append(registers, "R8", "R15")
		}
		for _, op := range []string{"CVTPL2PS", "CVTPL2PD"} {
			for _, register := range registers {
				// The caller can observe physical MM0/M1/Tag/TOS after RET,
				// even when f itself contains only a conversion and a return.
				// No body whitelist can certify the absent caller contract.
				source := "TEXT f(SB),4,$0-0\n" + op + " " + register + ",X0\nRET\n" +
					"TEXT caller(SB),4,$0-0\nCALL f(SB)\nFXSAVE (AX)\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				form, known, err := x86SignedPackedFloatProperties(file.Funcs[0].Instrs[1], arch)
				if !known || err != nil || !form.mmx || form.inputBytes != 8 {
					t.Fatal("actual Ymm class missing", arch, op, register, form, err)
				}
				opt := Options{Goarch: arch, Sigs: map[string]FuncSig{"f": {Ret: Void}, "caller": {Ret: Void}}}
				for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					if _, err := x86SignedPackedFloatTranslate(file, opt, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("ordinary API fabricated physical MMX caller closure", arch, op, register, api, err)
					}
				}
			}
		}
	}
}

func TestX86SignedPackedIntegerFloatIdentityAndISAContract(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, tc := range []struct{ row, features string }{
			{"CVTPL2PS X0,X1", "+sse2"}, {"CVTPL2PD X0,X1", "+sse2"},
			{"CVTPL2PS M0,X1", "+mmx,+sse"}, {"CVTPL2PD M0,X1", "+mmx,+sse,+sse2"},
			{"VCVTDQ2PS Y0,Y1", "+avx"}, {"VCVTDQ2PD X0,Y1", "+avx"},
			{"VCVTDQ2PS X0,K1,X1", "+avx512f,+avx512vl"}, {"VCVTDQ2PD Y0,Z1", "+avx512f"},
		} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+tc.row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, fn); got != tc.features {
				t.Fatal("source ISA contract", arch, tc.row, got, tc.features)
			}
			ins := fn.Instrs[1]
			if ins.Args[0].Reg == "M0" {
				continue
			}
			var ir strings.Builder
			ctx := newX86Ctx(&ir, fn, FuncSig{Ret: Void}, testResolveSym("example"), nil, arch, "", false)
			if err := ctx.emitEntryAllocas(); err != nil {
				t.Fatal(err)
			}
			before := ir.Len()
			if _, _, err := ctx.lowerSignedPackedIntegerFloat("VCVTUDQ2PS", ins); err == nil || ir.Len() != before {
				t.Fatal("contradictory source opcode emitted IR", err)
			}
			ins.x86AddressBits = 32
			if _, _, err := ctx.lowerSignedPackedIntegerFloat(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || ir.Len() != before {
				t.Fatal("unbound address identity emitted IR", err)
			}
			ins.x86AddressBits = 0
			ins.Op = Op(strings.ToLower(string(ins.Op)))
			if _, _, err := ctx.lowerSignedPackedIntegerFloat(ins.Op, ins); err != nil {
				t.Fatal("equivalent lowercase helper identity rejected", err)
			}
		}
	}
	for _, row := range []string{"VCVTDQ2PS.SAE Z0,Z1", "VCVTDQ2PS.RU_SAE (AX),Z1", "VCVTDQ2PD.RN_SAE Y0,Z1"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", file.Funcs[0]); got != "" {
			t.Fatal("invalid signed conversion acquired ISA attributes", row, got)
		}
	}
}
