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

	"github.com/xgo-dev/llvm"
)

func x86MADDOfficialRows(t *testing.T, arch string) []string {
	t.Helper()
	byOpcode := x86OfficialPackedBinaryWitnesses(t)
	var rows []string
	for _, name := range []string{"VPMADDWD", "VPMADDUBSW"} {
		if len(byOpcode[name]) == 0 {
			t.Fatal("official MADD table missing", name)
		}
		for _, row := range byOpcode[name] {
			if arch != "386" || strings.Count(row, ",") != 3 {
				rows = append(rows, row)
			}
		}
	}
	return rows
}

// Full Go source classes, including valid forms lacking native backing or
// physical mode32 identity. These are not all object/runtime positives.
func x86MADDWholeFormats(t *testing.T, arch string) []string {
	rows := x86MADDOfficialRows(t, arch)
	for _, name := range []string{"PMADDWL", "PMADDUBSW"} {
		for _, source := range []string{"X0", "X7", "(AX)", "16(AX)(CX*2)", "value+0(FP)", "local-16(SP)", "data(SB)", "(FS)", "(GS)"} {
			rows = append(rows, name+" "+source+",X1")
		}
		if arch == "amd64" {
			rows = append(rows, name+" X15,X0")
		}
	}
	if arch == "amd64" {
		for _, source := range []string{"M0", "M7", "(AX)", "value+0(FP)", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			rows = append(rows, "PMADDWL "+source+",M1")
		}
	}
	for _, name := range []string{"VPMADDWD", "VPMADDUBSW"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{"value+0(FP)", "local-64(SP)", "data(SB)", "(FS)", "(GS)"} {
				rows = append(rows, name+" "+source+","+bank+"1,"+bank+"2")
			}
			if arch != "386" || bank != "Z" {
				rows = append(rows, name+" "+bank+"20,"+bank+"21,"+bank+"22")
			}
		}
	}
	return rows
}

func TestX86MADDTypedCompleteGoAttributes(t *testing.T) {
	if len(x86PackedMultiplyAddSpecs) != 4 {
		t.Fatal("MADD source family must have four canonical Go names")
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
		"{APMADDWL, ymm, Py1, opBytes{0xf5, Pe, 0xf5}}",
		"{APMADDUBSW, yxm_q4, Pq4, opBytes{0x04}}",
		"{Zm_r_xm, 1, argList{Ymm, Ymr}}", "{Zm_r_xm, 2, argList{Yxm, Yxr}}",
		"{Zm_r, 1, argList{Yxm, Yxr}}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("actual legacy opcode/class row changed", row)
		}
	}
	for _, class := range []string{"Yax", "Ycx", "Yrx", "Yrl", "Yrl32", "Ym", "Ymr"} {
		if !strings.Contains(string(legacy), "ycover["+class+"*Ymax+Ymm] = 1") {
			t.Fatal("actual MMX source class changed", class)
		}
	}
	for _, item := range []struct{ name, mapName, opcode string }{
		{"VPMADDWD", "0F", "F5"}, {"VPMADDUBSW", "0F38", "04"},
	} {
		start := strings.Index(string(avx), "{as: A"+item.name+",")
		if start < 0 {
			t.Fatal("actual AVX opcode missing", item.name)
		}
		row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if !strings.Contains(row, "ytab: _yvandnpd, prefix: Pavx") || strings.Contains(row, "Bcst") || strings.Contains(row, "Sae") {
			t.Fatal("actual opcode-specific attributes changed", row)
		}
		for _, width := range []string{"128", "256"} {
			want := fmt.Sprintf("avxEscape | vex%s | vex66 | vex%s | vexW0, 0x%s", width, item.mapName, item.opcode)
			if !strings.Contains(row, want) {
				t.Fatal("actual VEX opcode attributes changed", want)
			}
		}
		for i, width := range []string{"128", "256", "512"} {
			want := fmt.Sprintf("avxEscape | evex%s | evex66 | evex%s | evexW0, evexN%d | evexZeroingEnabled, 0x%s", width, item.mapName, 16<<i, item.opcode)
			if !strings.Contains(row, want) {
				t.Fatal("actual EVEX opcode attributes changed", want)
			}
		}
	}
}

func TestX86MADDTypedWholeFormatsEffectsAndShapes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86MADDWholeFormats(t, arch)
		var batch strings.Builder
		for index, row := range rows {
			fmt.Fprintf(&batch, "TEXT f%d(SB),4,$64-64\n%s\nRET\n", index, row)
		}
		goAssemblerOracleOutput(t, arch, batch.String(), "", true)
		file, err := Parse(ArchAMD64, batch.String())
		if err != nil {
			t.Fatal(err)
		}
		for index, function := range file.Funcs {
			ins := function.Instrs[1]
			before := fmt.Sprintf("%#v", ins)
			form, known, err := x86PackedMultiplyAddProperties(ins.Op, ins, arch)
			high := arch == "386" && strings.Contains(rows[index], "20")
			if !known || high && !errors.Is(err, ErrProbeNeedsContext) || !high && err != nil {
				t.Fatal("actual Go-accepted format lost its exact classification", arch, rows[index], err)
			}
			if high {
				continue
			}
			if form.legacy {
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 || effect.flagsDefined != 0 || effect.flagsKilled != 0 ||
					!effect.operands[0].read || effect.operands[0].write || !effect.operands[1].read || !effect.operands[1].write ||
					effect.operands[0].width != int64(form.byteWidth) || effect.operands[1].width != int64(form.byteWidth) ||
					!reflect.DeepEqual(effect.operands[0].operand, form.source) {
					t.Fatal("legacy native bytes/physical bank diverged from descriptor", rowLabel(arch, ins), effect, err)
				}
			}
			for operand, arg := range ins.Args {
				width, write, valid := x86InstructionMemoryShape(ins, operand, arch)
				if valid != (form.memory == operand && !form.mmx) || valid && (write || width != int64(form.memoryBytes)) {
					t.Fatal("memory-shape consumer diverged from complete typed grammar", ins, width, write, valid)
				}
				if arg.Kind == OpFP {
					width, write, valid := X86FPAccessBytes(ins, operand, arch)
					if !valid || write || width != int64(form.memoryBytes) {
						t.Fatal("FP native width observer disagrees", ins, width, write, valid)
					}
				}
			}
			if before != fmt.Sprintf("%#v", ins) || x86CallerVectorMoveKnown(ins) != !form.mmx {
				t.Fatal("grammar changed input or lost registered caller family", ins)
			}
		}
		t.Logf("%s: %d actual Go source formats; classification/effects are not runtime or backing permission", arch, len(rows))
	}
}

func rowLabel(arch string, ins Instr) string { return arch + "/" + ins.Raw }

func TestX86MADDTypedMMXActualEncodedBank(t *testing.T) {
	registers := []string{"M0", "M1", "M7", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for index, register := range registers {
		source := "TEXT f(SB),4,$0-0\nPMADDWL " + register + ",M1\nRET\n"
		code := assembleX87ControlBytes(t, "amd64", source)
		physical := index
		if index == 2 {
			physical = 7
		} else if index >= 3 {
			physical = (index - 3) & 7
		}
		if len(code) == 5 && code[0] == 0x41 {
			code = code[1:] // Actual Go's ignored MMX REX.B annotation.
		}
		if want := []byte{0x0f, 0xf5, byte(0xc8 | physical), 0xc3}; !bytes.Equal(code, want) {
			t.Fatalf("actual MMX physical bank changed: %s %x want%x", register, code, want)
		}
		if index >= 3 {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			context, ir := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := ir.String()
			if _, _, err := context.lowerPackedWordMultiplyAdd("PMADDWL", file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) || ir.String() != before {
				t.Fatal("GP spelling fabricated an initialized MMX source", register, err)
			}
		}
	}
}

func TestX86MADDTypedRetainsRejectedFormsAndVirtualMemory(t *testing.T) {
	for _, row := range []string{
		"PMADDWD X0,X1", "PMADDWL X0,Y1", "PMADDWL M0,AX", "PMADDUBSW M0,M1",
		"PMADDUBSW X0,(AX)", "PMADDUBSW.Z X0,X1", "VPMADDWD X0,Y1,Y2",
		"VPMADDUBSW.BCST (AX),X0,K1,X1", "VPMADDWD.SAE Z0,Z1,Z2",
		"VPMADDUBSW X0,X1,K0,X2", "VPMADDWD $1,X1,X2", "VPMADDUBSW X0,X1,(AX)",
	} {
		source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", false)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			continue
		}
		if err := ProbeInstruction(ArchAMD64, "amd64", file.Funcs[0].Instrs[1]); err == nil {
			t.Fatal("Go-rejected MADD form obtained lowering", row)
		}
	}
	for _, row := range []string{"PMADDUBSW source+0(FP),X1", "PMADDUBSW (SP),X1", "PMADDUBSW (BP),X1", "PMADDUBSW (AX)(BP*2),X1"} {
		source := "TEXT f(SB),4,$0-64\n" + row + "\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		context, ir := newAMD64CtxWithFuncForTest(t, file.Funcs[0], x86WordMaddFPType(t), nil)
		before := ir.String()
		if _, _, err := context.lowerPackedWordMultiplyAdd("PMADDUBSW", file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) || ir.String() != before {
			t.Fatal("virtual storage became an original native m128 pointer", row, err)
		}
	}
}

func TestX86MADDTypedByteCallerRetainsUnknownAndPartialInputs(t *testing.T) {
	for name, body := range map[string]string{
		"unknown source":       "VMOVUPS (DI),Z1\nVPMADDUBSW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"unknown second":       "VMOVUPS (DI),Z0\nVPMADDUBSW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"partial pair":         "MOVSS (DI),X0\nMOVSS (SI),X1\nVPMADDUBSW Y0,Y1,Y2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":         "VMOVUPS (DI),Z0\nVPMADDUBSW.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":        "VMOVUPS (DI),Z0\nMOVL $1,AX\nKMOVQ AX,K1\nVPMADDUBSW Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown address":      "VMOVUPS (DI),Z0\nVPMADDUBSW (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"zero still full read": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPMADDUBSW.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"private SP":           "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPMADDUBSW (BX),X0\nVMOVSS X0,(DX)",
		"join missing source":  "VMOVUPS (DI),Z1\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z0\njoined:\nVPMADDUBSW Z0,Z1,Z2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("typed byte-MADD grammar became input/address permission", err)
			}
		})
	}
}

func TestX86MADDTypedMalformedIdentityAndPhysicalBanks(t *testing.T) {
	for _, name := range []string{"PMADDWL", "PMADDUBSW", "VPMADDWD", "VPMADDUBSW"} {
		operands := "X0,X1"
		if strings.HasPrefix(name, "V") {
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
			before := fmt.Sprintf("%#v", ins)
			context, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			ir, temporary := out.String(), context.tmp
			known, terminated, err := context.lowerPackedWordMultiplyAdd(original.Op, ins)
			bad := identity != "" && !strings.EqualFold(string(identity), string(original.Op))
			if !known || terminated || (err != nil) != bad || bad && (out.String() != ir || context.tmp != temporary) || before != fmt.Sprintf("%#v", ins) {
				t.Fatal("dispatch identity changed input or emitted before rejection", name, identity, err)
			}
		}
	}
	for _, opcode := range []string{"VPMADDWD", "VPMADDUBSW"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			row := opcode + " " + bank + "20," + bank + "21," + bank + "22"
			accepted := bank != "Z"
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", accepted)
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = x86PackedMultiplyAddProperties(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1], "386")
			if accepted && !errors.Is(err, ErrProbeNeedsContext) || !accepted && err == nil {
				t.Fatal("Go syntax is not physical mode32 permission", row, err)
			}
		}
		code := encodeX86RawEVEXPackedMADD(Op(opcode), 2, 1, 2, 0, 1, true, true)
		decoded, _, _, err := decodedX86EVEXPackedMADDInstruction(code, 32)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		var detached Instr
		if err := json.Unmarshal(data, &detached); err != nil {
			t.Fatal(err)
		}
		if _, _, err := x86PackedMultiplyAddProperties(detached.Op, detached, "386"); err == nil {
			t.Fatal("JSON/raw text fabricated physical mode32 mask provenance")
		}
		for _, address := range []int{16, 32, 64} {
			changed := decoded
			changed.x86AddressBits = address
			if _, _, err := x86PackedMultiplyAddProperties(changed.Op, changed, "386"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound address-size marker became memory permission", err)
			}
		}
	}
}

func TestX86MADDTypedNamedAndPhysicalThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, raw := range []bool{false, true} {
		for _, target := range []struct{ arch, triple string }{
			{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
			{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
		} {
			t.Run(fmt.Sprintf("raw=%t/%s", raw, target.triple), func(t *testing.T) {
				rows := x86MADDOfficialRows(t, target.arch)
				if raw {
					rows = nil
					for _, row := range x86MADDOfficialRows(t, "amd64") {
						code := assembleX87ControlBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
						code = code[:len(code)-1]
						for w := 0; w < 2; w++ {
							physical := append([]byte(nil), code...)
							if physical[0] == 0xc5 {
								physical = append([]byte{0xc4, physical[1]&0x80 | 0x61, physical[1] & 0x7f}, physical[2:]...)
							}
							physical[2] |= byte(w << 7)
							var bytes strings.Builder
							for _, value := range physical {
								fmt.Fprintf(&bytes, "BYTE $%d\n", value)
							}
							rows = append(rows, bytes.String())
						}
					}
				} else {
					rows = append(rows, "PMADDWL X0,X1", "PMADDWL (AX),X1", "PMADDUBSW X0,X1", "PMADDUBSW (AX),X1")
				}
				var source, declarations strings.Builder
				declarations.WriteString("package madd\n")
				for index, row := range rows {
					fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$0-0\n%s\nRET\n", index, row)
					fmt.Fprintf(&declarations, "func F%d()\n", index)
				}
				if !raw {
					file, sigs := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
					ir := x86ScalarFormatObjectUnit(t, file, sigs, target.arch, target.triple, 0)
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
					t.Logf("%d original named formats: Go objects, three public Context controls and emitter-only objects", len(rows))
					return
				}
				goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
				pkg := mustGoPackage(t, "example.invalid/madd", declarations.String())
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				sigs := map[string]FuncSig{}
				for index := range rows {
					name := fmt.Sprintf("F%d", index)
					sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), target.arch, types.SizesFor("gc", target.arch))
					if err != nil {
						t.Fatal(err)
					}
					sigs[name] = sig
				}
				resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
				options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs, ResolveSym: resolve}
				ir, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "madd-text.ll", "madd-text.o", ir)
				context := llvm.NewContext()
				defer context.Dispose()
				module, err := TranslateModuleInContext(context, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "madd-module.ll", "madd-module.o", module.String())
				result, err := translateGoModuleInContext(context, pkg, []byte(source.String()), GoModuleOptions{
					GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve,
				})
				if result != nil && !result.Module.IsNil() {
					defer result.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "madd-go.ll", "madd-go.o", result.Module.String())
				t.Logf("%d named/actual-Go-derived physical forms, three APIs/object axes; no caller or native runtime grant", len(rows))
			})
		}
	}
}
