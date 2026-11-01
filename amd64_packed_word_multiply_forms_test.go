package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var x86WordMultiplyNames = []string{
	"PMULLW", "PMULHW", "PMULHUW", "PMULHRSW",
	"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW",
}

// This catalog is derived from the actual Go ymm, yxm_q4 and _yvandnpd
// rows, independently of the production specification. It includes valid
// syntax which requires a different memory or physical input contract.
func x86WordMultiplyForms(arch string) []string {
	var rows []string
	for _, name := range x86WordMultiplyNames[:4] {
		for _, source := range []string{"X0", "X7", "(AX)", "16(AX)(CX*4)", "value+0(FP)", "local-16(SP)", "·data(SB)", "(FS)", "(GS)"} {
			rows = append(rows, name+" "+source+",X1")
		}
		if arch == "amd64" {
			rows = append(rows, name+" X15,X0")
			if name != "PMULHRSW" {
				for _, source := range []string{"M0", "M7", "(AX)", "value+0(FP)", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
					rows = append(rows, name+" "+source+",M1")
				}
			}
		}
	}
	for _, name := range x86WordMultiplyNames[4:] {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{bank + "0", bank + "7", "(AX)", "16(AX)(CX*4)", "value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
				rows = append(rows, fmt.Sprintf("%s %s,%s1,%s2", name, source, bank, bank))
				if arch == "amd64" {
					rows = append(rows, fmt.Sprintf("%s %s,%s31,K1,%s30", name, source, bank, bank),
						fmt.Sprintf("%s.Z %s,%s31,K7,%s30", name, source, bank, bank))
				}
			}
			if arch == "amd64" || bank != "Z" {
				rows = append(rows, fmt.Sprintf("%s %s20,%s21,%s22", name, bank, bank, bank))
			}
		}
	}
	return rows
}

func TestX86PackedWordMultiplyCompleteActualGoAttributes(t *testing.T) {
	if len(x86PackedWordMultiplySpecs) != 8 {
		t.Fatal("complete named packed-word multiply family must contain eight names")
	}
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{APMULLW, ymm, Py1, opBytes{0xd5, Pe, 0xd5}}",
		"{APMULHW, ymm, Py1, opBytes{0xe5, Pe, 0xe5}}",
		"{APMULHUW, ymm, Py1, opBytes{0xe4, Pe, 0xe4}}",
		"{APMULHRSW, yxm_q4, Pq4, opBytes{0x0b}}",
		"{Zm_r_xm, 1, argList{Ymm, Ymr}}", "{Zm_r_xm, 2, argList{Yxm, Yxr}}",
		"{Zm_r, 1, argList{Yxm, Yxr}}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatalf("actual Go complete legacy row changed: %s", row)
		}
	}
	for _, class := range []string{"Yax", "Ycx", "Yrx", "Yrl", "Yrl32", "Ym", "Ymr"} {
		if !strings.Contains(string(legacy), "ycover["+class+"*Ymax+Ymm] = 1") {
			t.Fatal("actual Go MMX source class changed", class)
		}
	}
	for _, classes := range []string{
		"Yxm, Yxr, Yxr", "Yym, Yyr, Yyr",
		"YxmEvex, YxrEvex, YxrEvex", "YxmEvex, YxrEvex, Yknot0, YxrEvex",
		"YymEvex, YyrEvex, YyrEvex", "YymEvex, YyrEvex, Yknot0, YyrEvex",
		"Yzm, Yzr, Yzr", "Yzm, Yzr, Yknot0, Yzr",
	} {
		start := strings.Index(string(avx), "var _yvandnpd =")
		table := strings.SplitN(string(avx)[start:], "\n}", 2)[0]
		if !strings.Contains(table, "argList{"+classes+"}") || strings.Count(table, "argList{") != 8 {
			t.Fatal("actual Go complete VEX/EVEX class rows changed", classes)
		}
	}
	for _, row := range x86PackedWordMultiplyGoRows {
		start := strings.Index(string(avx), "{as: A"+string(row.op)+",")
		if start < 0 {
			t.Fatal("actual Go omitted opcode", row.op)
		}
		record := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if !strings.Contains(record, "ytab: _yvandnpd, prefix: Pavx") ||
			strings.Contains(record, "Bcst") || strings.Contains(record, "Sae") {
			t.Fatal("actual Go opcode-specific attribute changed", record)
		}
		mapName := "0F"
		if row.mapID == 2 {
			mapName = "0F38"
		}
		for _, width := range []string{"128", "256"} {
			want := fmt.Sprintf("avxEscape | vex%s | vex66 | vex%s | vexW0, 0x%02X", width, mapName, row.opcode)
			if !strings.Contains(record, want) {
				t.Fatal("actual Go VEX encoding changed", want)
			}
		}
		for index, width := range []string{"128", "256", "512"} {
			want := fmt.Sprintf("avxEscape | evex%s | evex66 | evex%s | evexW0, evexN%d | evexZeroingEnabled, 0x%02X", width, mapName, 16<<index, row.opcode)
			if !strings.Contains(record, want) {
				t.Fatal("actual Go EVEX encoding changed", want)
			}
		}
	}
	archSource, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range x86WordMultiplyNames {
		if strings.Contains(string(archSource), "instructions[\""+name+"\"]") {
			t.Fatal("new alias requires independent source-form coverage", name)
		}
	}
}

func TestX86PackedWordMultiplyWholeFormatEffectsAndShapes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var batch strings.Builder
		for index, row := range x86WordMultiplyForms(arch) {
			fmt.Fprintf(&batch, "TEXT f%d(SB),4,$64-64\n%s\nRET\n", index, row)
		}
		goAssemblerOracleOutput(t, arch, batch.String(), "", true)
		file, err := Parse(ArchAMD64, batch.String())
		if err != nil {
			t.Fatal(err)
		}
		for index, fn := range file.Funcs {
			ins := fn.Instrs[1]
			before := fmt.Sprintf("%#v", ins)
			form, known, err := x86PackedWordMultiplyProperties(ins.Op, ins, arch)
			high := arch == "386" && strings.Contains(x86WordMultiplyForms(arch)[index], "20")
			if !known || high && !errors.Is(err, ErrProbeNeedsContext) || !high && err != nil {
				t.Fatalf("%s lost actual accepted syntax: %+v %v", ins.Raw, form, err)
			}
			if high {
				continue // Syntax accepted; physical binding is not proved.
			}
			effect, observed, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if form.legacy {
				if !observed || err != nil || len(effect.operands) != 2 ||
					effect.operands[0].width != int64(form.byteWidth) ||
					effect.operands[1].width != int64(form.byteWidth) ||
					!effect.operands[0].read || effect.operands[0].write ||
					!effect.operands[1].read || !effect.operands[1].write ||
					effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatal("legacy byte effect differs from typed form", effect, err)
				}
				if !reflect.DeepEqual(effect.operands[0].operand, form.source) {
					t.Fatal("MMX physical source identity lost")
				}
			}
			for operand := range ins.Args {
				width, write, shape := x86InstructionMemoryShape(ins, operand, arch)
				want := form.memory == operand && !form.mmx
				if shape != want || shape && (width != int64(form.memoryBytes) || write) {
					t.Fatal("typed memory envelope mismatch", ins, width, write, shape)
				}
				if ins.Args[operand].Kind == OpFP {
					width, write, known := X86FPAccessBytes(ins, operand, arch)
					if known != (!form.mmx || form.legacy) || known && (write || width != int64(form.memoryBytes)) {
						t.Fatal("FP observation invented a different native width", ins, width, write, known)
					}
				}
			}
			if before != fmt.Sprintf("%#v", ins) || x86CallerVectorMoveKnown(ins) != !form.mmx {
				t.Fatal("classification altered input or disagreed with source-stack admission", ins)
			}
		}
		t.Logf("%s complete actual Go catalog: %d forms (syntax/context/effect distinct)", arch, len(file.Funcs))
	}
}

func TestX86PackedWordMultiplyMMXActualEncodedBank(t *testing.T) {
	for _, row := range []struct {
		name   string
		opcode byte
	}{{"PMULLW", 0xd5}, {"PMULHW", 0xe5}, {"PMULHUW", 0xe4}} {
		for index, register := range []string{"M0", "M1", "M7", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			source := "TEXT bank(SB),4,$0-0\n" + row.name + " " + register + ",M1\nRET\n"
			code := x86PackedShiftActualGoBytes(t, "amd64", source)
			registerIndex := index
			switch {
			case index == 2:
				registerIndex = 7
			case index >= 3:
				registerIndex = (index - 3) & 7
			}
			if len(code) == 5 && code[0] == 0x41 {
				code = code[1:] // Actual Go's ignored MMX REX.B annotation.
			}
			want := []byte{0x0f, row.opcode, byte(0xc8 | registerIndex), 0xc3}
			if !bytes.Equal(code, want) {
				t.Fatalf("%s actual encoded source bank=%x want=%x", source, code, want)
			}
		}
	}
}

func TestX86PackedWordMultiplyMalformedIdentityAndBanksBeforeIR(t *testing.T) {
	for _, name := range x86WordMultiplyNames {
		vector := strings.HasPrefix(name, "V")
		operands := "X0,X1"
		if vector {
			operands = "X0,X1,X2"
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+name+" "+operands+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		original := file.Funcs[0].Instrs[1]
		for _, identity := range []Op{"", original.Op, Op(strings.ToLower(name)), "MOVQ", Op(name + ".BAD")} {
			ins := original
			ins.Op = identity
			copy := ins
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before, temporary := out.String(), ctx.tmp
			known, term, err := ctx.lowerPackedWordMultiply(original.Op, ins)
			bad := identity != "" && !strings.EqualFold(string(identity), name)
			if !known || term || (err != nil) != bad || bad && (out.String() != before || ctx.tmp != temporary) || !reflect.DeepEqual(ins, copy) {
				t.Fatal("dispatch mismatch/clone contract", name, identity, known, term, err)
			}
		}
		bad := []string{"$1,X1", "Y0,Y1", "X16,X0", "X0,(AX)", "(AX),(BX)", "(AX)(SP*2),X1"}
		if vector {
			bad = []string{"$1,X1,X2", "X0,Y1,Y2", "X0,X1,(AX)", "X0,X1,K0,X2", "(AX)(SP*2),X1,X2", "2147483648(AX),X1,X2"}
		}
		for _, operands := range bad {
			source := "TEXT f(SB),4,$0-0\n" + name + " " + operands + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				continue
			}
			ins := file.Funcs[0].Instrs[1]
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			if known, _, err := ctx.lowerPackedWordMultiply(ins.Op, ins); !known || err == nil || out.String() != before {
				t.Fatal("malformed form emitted IR", ins, err)
			}
		}
		if vector {
			for _, suffix := range []string{".BCST", ".SAE", ".RN_SAE", ".Z"} {
				source := "TEXT f(SB),4,$0-0\n" + name + suffix + " (AX),X1,X2\nRET\n"
				if suffix == ".Z" {
					x86WordMultiplyReservedZeroMaskGoObservation(t, source, name)
				} else {
					goAssemblerOracleOutput(t, "amd64", source, "", false)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					continue
				}
				if _, _, err := x86PackedWordMultiplyProperties(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1], "amd64"); err == nil {
					t.Fatal("opcode attributes leaked from shared ytab", source)
				}
			}
		}
	}
}

func TestX86PackedWordMultiplyThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		arch := "amd64"
		if strings.HasPrefix(triple, "i") {
			arch = "386"
		}
		t.Run(triple, func(t *testing.T) {
			var source, declarations strings.Builder
			declarations.WriteString("package oracle\n")
			for i, row := range x86WordMultiplyForms(arch) {
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$64-64\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				form, _, err := x86PackedWordMultiplyProperties(ins.Op, ins, arch)
				if errors.Is(err, ErrProbeNeedsContext) || form.mmx {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if form.legacy && form.memory >= 0 && (form.source.Kind == OpFP ||
					form.source.Kind == OpMem && form.source.Mem.Base == SP) {
					continue
				}
				fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$64-64\n%s\nRET\n", i, row)
				fmt.Fprintf(&declarations, "func F%d(value [64]byte)\n", i)
			}
			goAssemblerOracleOutput(t, arch, source.String(), "", true)
			pkg := mustGoPackage(t, "oracle", declarations.String())
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{}
			for _, fn := range file.Funcs {
				name := strings.TrimPrefix(fn.Sym, "·")
				sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
				if err != nil {
					t.Fatal(err)
				}
				sigs[name] = sig
			}
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), pkg, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original word-multiply formats invented register or native inputs", api, err)
				}
			}
			// Keep every old format/function in its original Go object and in
			// emitter-only objects. Initialized public positives live in the
			// complete-family value matrix, not these uninitialized probes.
			ir := x86WordMultiplyFormatObjectUnit(t, file, sigs, arch, triple, 64)
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			}
		})
	}
}

func TestX86PackedWordMultiplyMode32PhysicalAndSourceBoundaries(t *testing.T) {
	for _, name := range x86WordMultiplyNames[4:] {
		for _, bank := range []string{"X", "Y"} {
			for _, index := range []int{8, 15, 16, 31} {
				for operand := 0; operand < 3; operand++ {
					args := []string{bank + "0", bank + "1", bank + "2"}
					args[operand] = fmt.Sprintf("%s%d", bank, index)
					source := "TEXT f(SB),4,$0-0\n" + name + " " + strings.Join(args, ",") + "\nRET\n"
					goAssemblerOracleOutput(t, "386", source, "", true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					if _, _, err := x86PackedWordMultiplyProperties(ins.Op, ins, "386"); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("named high bank lost physical Context", ins, err)
					}
				}
			}
		}
		for _, source := range []string{
			name + " Z8,Z1,Z2", name + " Z0,Z8,Z2", name + " Z0,Z1,Z8",
			name + " X0,X1,K1,X2", name + ".Z Z0,Z1,K1,Z2",
		} {
			assembly := "TEXT f(SB),4,$0-0\n" + source + "\nRET\n"
			goAssemblerOracleOutput(t, "386", assembly, "", false)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				continue
			}
			ins := file.Funcs[0].Instrs[1]
			if _, _, err := x86PackedWordMultiplyProperties(ins.Op, ins, "386"); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("Go rejected a source format, not merely an unknown physical identity", source, err)
			}
		}
	}
	for _, row := range x86PackedWordMultiplyGoRows {
		for _, width := range []int{0, 1, 2} {
			for _, zero := range []bool{false, true} {
				code := encodeX86EVEXPackedWordMultiply(row.mapID, row.opcode, width, 1, false, zero, 2, 1, 0)
				ins, n, known, err := decodedX86PackedMultiplyInstruction(code, 32)
				if !known || err != nil || n != len(code) || !ins.x86Encoded {
					t.Fatal("actual low physical mode32 EVEX decode lost its origin", ins, err)
				}
				if _, _, err := x86PackedWordMultiplyProperties(ins.Op, ins, "386"); err != nil {
					t.Fatal("physical grammar borrowed textual operand limit", err)
				}
				textual := ins
				textual.x86Encoded = false
				textual.Raw = fmt.Sprintf("BYTE %x genuine-looking text is not a decoder", code)
				if _, _, err := x86PackedWordMultiplyProperties(textual.Op, textual, "386"); err == nil {
					t.Fatal("raw text manufactured a decoder identity")
				}
				encoded, err := json.Marshal(ins)
				if err != nil {
					t.Fatal(err)
				}
				var restored Instr
				if err := json.Unmarshal(encoded, &restored); err != nil {
					t.Fatal(err)
				}
				if restored.x86Encoded {
					t.Fatal("public JSON manufactured a decoder marker")
				}
				if _, _, err := x86PackedWordMultiplyProperties(restored.Op, restored, "386"); err == nil {
					t.Fatal("JSON-restored source bypassed Go's named limit")
				}
			}
		}
	}
}

func TestX86PackedWordMultiplyLegacyResultBytesAndUnknownInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range x86WordMultiplyNames[:4] {
			for _, first := range []string{"X0", "a+0(FP)", "value-16(SP)"} {
				for _, complete := range []bool{true, false} {
					move := "MOVOU"
					if !complete {
						move = "MOVSS"
					}
					body := move + " a+0(FP),X0\nMOVOU b+16(FP),X1\n" + move + " X0,value-16(SP)\n" + name + " " + first + ",X1\nMOVSD X1,ret0+32(FP)\nRET"
					if !complete {
						// Memory MOVSS zeros X[127:32]; its register form instead
						// preserves the destination's genuinely undefined bytes.
						body = strings.Replace(body, "MOVSS a+0(FP),X0", "MOVSS a+0(FP),X2\nMOVSS X2,X0", 1)
					}
					_, _, sig, source := x86ResultInitializationFixture(t, arch, "func Value(a,b [16]byte) uint64", body)
					source = strings.Replace(source, ",$0-", ",$32-", 1)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					goAssemblerOracleOutput(t, arch, source, "", true)
					err = CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
					wantContext := !complete && first != "a+0(FP)"
					if wantContext && !errors.Is(err, ErrProbeNeedsContext) || !wantContext && err != nil {
						t.Fatal("legacy result byte proof invented unknown word input", name, first, complete, err)
					}
				}
			}
		}
	}
}

func TestX86PackedWordMultiplyVirtualLegacyMemoryRemainsContext(t *testing.T) {
	for _, name := range x86WordMultiplyNames[:4] {
		for _, address := range []string{"value+0(FP)", "(SP)", "(BP)", "(AX)(BP*2)"} {
			for _, target := range x86RawReturnTargets {
				source := "TEXT ·f(SB),4,$64-64\nPXOR X0,X0\n" + name + " " + address + ",X0\nRET\n"
				declaration := "func f(value [64]byte)"
				if address != "value+0(FP)" {
					source = x86OrdinaryBPNativeSource(target.arch, "f", name+" "+address+",X0", address, 64)
					declaration = "func f(p *byte)"
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+name+"/"+address+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						x86RequireOrdinaryBPNativeOutcome(t, target.arch, address, ir, err)
					})
				}
			}
		}
	}
}

func TestX86PackedWordMultiplyMode32LowZActualGo(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, name := range x86WordMultiplyNames[4:] {
		for _, first := range []string{"Z0", "(AX)"} {
			row := name + " " + first + ", Z1, Z2"
			t.Run(row, func(t *testing.T) {
				source := "TEXT wordmul(SB),4,$0-0\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, "386", source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func wordmul()", "386", "i386-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original low-Z format invented native or register inputs", api, err)
					}
				}
				ir := x86WordMultiplyFormatObjectUnit(t, file, map[string]FuncSig{
					"wordmul": {Name: "wordmul", Ret: Void},
				}, "386", "i386-unknown-linux-gnu", 0)
				x86ResultInitializationObject(t, llc, "i386-unknown-linux-gnu", ir, "word-multiply-low-z")

				initialized := "TEXT wordmul(SB),4,$0-4\nMOVL p+0(FP),AX\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, "386", initialized, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, initialized, "func wordmul(p *byte)", "386", "i386-unknown-linux-gnu", api)
					if err != nil {
						t.Fatal("initialized low-bank Z source rejected", api, err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, "i386-unknown-linux-gnu", ir, level)
					}
				}
			})
		}
	}
}

func TestX86PackedWordMultiplyLegacyByteEffectActualGo(t *testing.T) {
	for _, name := range x86WordMultiplyNames[:4] {
		for _, arch := range []string{"386", "amd64"} {
			row := name + " X0, X1"
			t.Run(arch+"/"+name, func(t *testing.T) {
				source := "TEXT wordmul(SB),4,$0-0\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 {
					t.Fatalf("accepted legacy format lacks complete typed byte effect: known=%t err=%v effect=%+v", known, err, effect)
				}
				if !effect.operands[0].read || effect.operands[0].write || !effect.operands[1].read ||
					!effect.operands[1].write || effect.operands[0].width != 16 || effect.operands[1].width != 16 ||
					effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatal(fmt.Sprintf("incorrect read/modify/write/flags effect: %+v", effect))
				}
			})
		}
	}
}
