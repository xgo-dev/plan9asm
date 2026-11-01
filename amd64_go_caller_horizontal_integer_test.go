package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This first-party caller closes its own source/ABI boundary. The horizontal
// operation has no exemption from the original raw-return stack certificate.
func TestX86GoCallerHorizontalIntegerOriginalSourceThreeAPIs(t *testing.T) {
	for _, body := range []string{
		"VMOVDQU (DI),Y0\nVMOVDQU (SI),Y1\nVPHADDD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"VMOVDQU (SI),Y1\nVPHADDD (DI),Y1,Y2\nVMOVSS X2,(DX)",
	} {
		t.Run(strings.Split(body, "\n")[1], func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: sigs, ResolveSym: resolve}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM22 llc required")
			}
			if ir, err := Translate(file, options); err != nil {
				t.Error("text", err)
			} else {
				compileLLVMToObject(t, llc, options.TargetTriple, "horizontal-caller-text.ll", "horizontal-caller-text.o", ir)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Error("module", err)
			} else {
				compileLLVMToObject(t, llc, options.TargetTriple, "horizontal-caller-module.ll", "horizontal-caller-module.o", module.String())
			}
			if err := x86CallerCoreTranslate(t, pkg, assembly, options.TargetTriple); err != nil {
				t.Error("selected Go caller", err)
			}
		})
	}
}

func TestX86GoCallerHorizontalIntegerCompleteNamedAndRawThreeAPIs(t *testing.T) {
	for _, raw := range []bool{false, true} {
		var body strings.Builder
		for _, op := range x86HorizontalIntegerOpcodes {
			rows := []string{op + " X0,X1"}
			for _, bank := range []string{"X", "Y"} {
				rows = append(rows, fmt.Sprintf("V%s %s0,%s1,%s2", op, bank, bank, bank), fmt.Sprintf("V%s (DI),%s1,%s2", op, bank, bank))
			}
			for _, row := range rows {
				body.WriteString("VMOVDQU (DI),Y0\nVMOVDQU (SI),Y1\n")
				if raw {
					code := assembleX87ControlBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if len(code) < 2 || code[len(code)-1] != 0xc3 {
						t.Fatal("original Go horizontal bytes have no exact near RET", row, code)
					}
					for _, value := range code[:len(code)-1] {
						fmt.Fprintf(&body, "BYTE $0x%02x\n", value)
					}
				} else {
					body.WriteString(row + "\n")
				}
				result := "X2"
				if !strings.HasPrefix(row, "V") {
					result = "X1"
				}
				fmt.Fprintf(&body, "VMOVSS %s,(DX)\n", result)
			}
		}
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body.String(), 1)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM22 llc required")
		}
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(fmt.Sprint(raw, "/", triple), func(t *testing.T) {
				options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
				ir, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "horizontal-caller-text.ll", "horizontal-caller-text.o", ir)
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "horizontal-caller-module.ll", "horizontal-caller-module.o", module.String())
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestX86GoCallerHorizontalIntegerCompleteMemoryCertificates(t *testing.T) {
	for _, op := range x86HorizontalIntegerOpcodes {
		for _, bank := range []string{"X", "Y"} {
			row := fmt.Sprintf("V%s (DI),%s0,%s1", op, bank, bank)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "VMOVDQU (SI),Y0\n"+row+"\nVMOVSS X1,(DX)", 1)
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: sigs, ResolveSym: resolve})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ins := range normalized.Funcs[0].Instrs {
				form, known, err := x86HorizontalIntegerProperties(ins, "amd64")
				if !known || err != nil || form.memory < 0 {
					continue
				}
				found = true
				access, exists := ins.x86CallerMemory[form.memory]
				if !exists || access.width != int64(form.byteWidth) || access.write || !x86CallerMemoryCertified(ins, form.memory) {
					t.Fatal("full horizontal source envelope lost its instruction identity", row)
				}
				for _, change := range []string{"opcode", "source", "destination", "width", "address", "direction", "address size"} {
					access := access
					local := ins
					local.Args = append([]Operand(nil), ins.Args...)
					local.x86CallerMemory = map[int]x86CallerMemoryAccess{form.memory: access}
					switch change {
					case "opcode":
						local.Op = "VPHADDSW"
						if local.Op == ins.Op {
							local.Op = "VPHSUBSW"
						}
					case "source":
						local.Args[form.second].Reg = Reg(bank + "7")
					case "destination":
						local.Args[form.destination].Reg = Reg(bank + "7")
					case "width":
						access.width--
						local.x86CallerMemory[form.memory] = access
					case "address":
						local.Args[form.memory].Mem.Off++
					case "direction":
						access.write = true
						local.x86CallerMemory[form.memory] = access
					case "address size":
						local.x86AddressBits = 32
					}
					if x86CallerMemoryCertified(local, form.memory) {
						t.Fatal("edited horizontal instruction borrowed stale memory identity", row, change)
					}
				}
			}
			if !found {
				t.Fatal("fixture did not consume horizontal memory", row)
			}
		}
	}
}

func TestX86GoCallerHorizontalIntegerRetainsContextBoundaries(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":                     "VMOVDQU (DI),Y1\nVPHADDD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown second":                    "VMOVDQU (DI),Y0\nVPHSUBW Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown destructive destination":   "VMOVDQU (DI),X0\nPHADDSW X0,X1\nVMOVSS X1,(DX)",
		"unknown same subtract":             "VPHSUBD Y0,Y0,Y2\nVMOVSS X2,(DX)",
		"partial upper input":               "MOVUPS (DI),X0\nVMOVDQU (SI),Y1\nVPHADDW Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown pointer":                   "VMOVDQU (SI),Y0\nVPHADDD (BX),Y0,Y1\nVMOVSS X1,(DX)",
		"full width length envelope":        "VMOVDQU (SI),Y0\nVPHADDW (CX),Y0,Y1\nVMOVSS X1,(DX)",
		"full width scalar result envelope": "VMOVDQU (SI),Y0\nVPHSUBSW (DX),Y0,Y1\nVMOVSS X1,(DX)",
		"physical SP":                       "VMOVDQU (SI),Y0\nVPHADDD (SP),Y0,Y1\nVMOVSS X1,(DX)",
		"physical BP":                       "VMOVDQU (SI),Y0\nVPHSUBD (BP),Y0,Y1\nVMOVSS X1,(DX)",
		"private stack alias":               "MOVQ SP,BX\nVMOVDQU (SI),Y0\nVPHADDW (BX),Y0,Y1\nVMOVSS X1,(DX)",
		"g memory":                          "VMOVDQU (SI),Y0\nVPHADDSW (R14),Y0,Y1\nVMOVSS X1,(DX)",
		"FP pointer data":                   "VMOVDQU (SI),X0\nVPHADDD a+0(FP),X0,X1\nVMOVSS X1,(DX)",
		"legacy native alignment":           "VMOVDQU (SI),X0\nPHADDW (DI),X0\nVMOVSS X0,(DX)",
		"MMX state":                         "PHADDD M0,M1\nMOVL AX,(DX)",
		"pointer input write":               "VMOVDQU (DI),Y0\nVPHADDD Y0,Y0,Y1\nVMOVSS X1,(DI)",
		"wide result write":                 "VMOVDQU (DI),Y0\nVPHADDD Y0,Y0,Y1\nVMOVDQU Y1,(DX)",
		"unrestored SP":                     "VMOVDQU (DI),Y0\nVPHADDD Y0,Y0,Y1\nVMOVSS X1,(DX)",
		"CFG missing source":                "VMOVDQU (DI),Y0\nCMPQ AX,$0\nJE join\nVMOVDQU (SI),Y1\njoin:\nVPHADDD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown effect":                    "VMOVDQU (DI),Y0\nVPHADDD Y0,Y0,Y1\nXCHGL AX,(DI)\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			if name == "unrestored SP" {
				assembly = strings.Replace(assembly, "BYTE $0xc3", "SUBQ $8,SP\nBYTE $0xc3", 1)
			}
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved %s acquired source/caller privilege: %v", name, err)
			}
		})
	}
	ins := x86YMMReadSource(t, "PHADDD M0,M1")
	state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0)}}
	state = x86CloneCallerState(state)
	before := x86CloneCallerState(state)
	if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(before, state) {
		t.Fatal("MMX grammar inherited a physical caller state proof")
	}
}
