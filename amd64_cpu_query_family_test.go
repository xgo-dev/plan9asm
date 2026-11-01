package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86CPUQueryCompleteOfficialRowsAndImplicitRegisters(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}") {
		t.Fatal("complete Go zero-operand table changed")
	}
	for _, form := range []struct {
		op        Op
		row       string
		encoding  []byte
		registers []Reg
	}{
		{OpCPUID, "{ACPUID, ynone, Pm, opBytes{0xa2}}", []byte{0x0f, 0xa2, 0xc3}, []Reg{AX, BX, CX, DX}},
		{OpXGETBV, "{AXGETBV, ynone, Pm, opBytes{01, 0xd0}}", []byte{0x0f, 0x01, 0xd0, 0xc3}, []Reg{AX, CX, DX}},
	} {
		if !strings.Contains(string(table), form.row) {
			t.Fatal("complete Go CPU-query encoding changed", form.op)
		}
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+string(form.op), func(t *testing.T) {
				source := "TEXT query(SB),4,$0-0\n" + string(form.op) + "\nRET\n"
				if actual := assembleX87ControlBytes(t, arch, source); !bytes.Equal(actual, form.encoding) {
					t.Fatalf("original Go CPU-query identity: %x", actual)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ctx, _ := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				for _, register := range form.registers {
					if ctx.regSlot[register] == "" {
						t.Errorf("implicit CPU-query register %s has no allocated slot", register)
					}
				}
			})
		}
	}
}

func TestX86CPUQueryBareAcceptedSourceAcrossThreeAPIs(t *testing.T) {
	pkg := mustGoPackage(t, "cpuquery", "package cpuquery\nfunc query()\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{OpCPUID, OpXGETBV} {
			source := "TEXT ·query(SB),4,$0-0\n" + string(op) + "\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+string(op)+"/"+api, func(t *testing.T) {
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: arch, ResolveSym: resolve, Sigs: signatures}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					var ir string
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						module, translateErr := TranslateModuleInContext(ctx, file, options)
						err = translateErr
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
					case "Go":
						translated, translateErr := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: arch, ResolveSym: resolve})
						err = translateErr
						if translated != nil && !translated.Module.IsNil() {
							defer translated.Module.Dispose()
							ir = translated.Module.String()
						}
					}
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("Go-accepted syntax supplied missing implicit inputs to %s: %v\n%s", api, err, ir)
					}
				})
			}
		}
	}
}

func TestX86CPUQueryConstructedInvalidOperandsRejectBeforeIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{OpCPUID, OpXGETBV} {
			for _, operand := range []string{"AX", "(AX)", "$1", "AX,DX"} {
				t.Run(arch+"/"+string(op)+"/"+operand, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT query(SB),4,$0-0\n"+string(op)+" "+operand+"\nRET\n", "", false)
					// Parse already rejects these source forms. Constructed File/helper
					// callers must not bypass that grammar and silently emit a query.
					args, err := parseOperandsCSV(ArchAMD64, op, operand)
					if err != nil {
						t.Fatal(err)
					}
					fn := Func{Instrs: []Instr{{Op: OpMOVL, Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}}}, {Op: OpMOVL, Args: []Operand{{Kind: OpReg, Reg: DX}, {Kind: OpReg, Reg: AX}}}}}
					ctx, output := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before, temporary := output.String(), ctx.tmp
					known, terminated, err := ctx.lowerArith(op, Instr{Op: op, Args: args, Raw: string(op) + " " + operand})
					if !known || terminated || err == nil || before != output.String() || temporary != ctx.tmp {
						t.Fatalf("invalid CPU-query form emitted IR: %t/%t/%v", known, terminated, err)
					}
				})
			}
		}
	}
}
