package plan9asm

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86VSIBDataRowsRequireProofWithoutResults(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86IndexedMemoryRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	dataRows, hintRows := 0, 0
	for _, row := range rows {
		ins := x86ScalarLaneInstruction(t, row.Witnesses[0].Instruction)
		form, known, err := x86VSIBProperties(ins, "amd64")
		if !known || err != nil {
			t.Fatal("original official VSIB row", row.ID, err)
		}
		if form.prefetch {
			hintRows++
			continue // Elided hints have no numerical continuation to prove.
		}
		dataRows++
		ins = x86VSIBModeRoleInstruction(t, ins, 2, 1)
		for _, arch := range []string{"amd64", "386"} {
			t.Run(row.ID+"/"+arch, func(t *testing.T) {
				fn := Func{Sym: "Value", Instrs: []Instr{ins}}
				for _, result := range []LLVMType{Void, I32} {
					if !x86TypedFPResultNeedsProof(fn, FuncSig{Name: "Value", Ret: result}, arch) {
						t.Fatal("dead VSIB output bypassed index, mask, data and address obligations", result)
					}
				}
			})
		}
	}
	if dataRows != 64 || hintRows != 16 {
		t.Fatal("incomplete official VSIB closure", dataRows, hintRows)
	}
}

func TestX86VSIBVoidUnknownInputsThreeAPIs(t *testing.T) {
	rows := []string{
		"VGATHERDPS X1,(AX)(X0*1),X2",
		"VGATHERDPS (AX)(X0*1),K1,X2",
		"VPSCATTERDD X2,K1,(AX)(X0*1)",
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range rows {
			for _, raw := range []bool{false, true} {
				kind, body := "named", row+"\n"
				if raw {
					kind, body = "raw", x86RawNumericalInstruction(t, target.arch, row)
				}
				t.Run(target.triple+"/"+row+"/"+kind, func(t *testing.T) {
					source := "TEXT Value(SB),4,$0-0\n" + body + "RET\n"
					requireX86GoAssemblerResult(t, target.arch, source, true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("implementation slots supplied unknown VSIB inputs", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86VSIBElidedHintsNeedNoDataProof(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range []string{"VGATHERPF0DPS K1,(AX)(Z0*1)", "VSCATTERPF1QPD K1,(AX)(Z0*1)"} {
			t.Run(target.triple+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				fn := Func{Sym: "Value", Instrs: []Instr{ins}}
				if x86TypedFPResultNeedsProof(fn, FuncSig{Name: "Value", Ret: Void}, target.arch) {
					t.Fatal("elided hint acquired a numerical input obligation")
				}
				source := "TEXT Value(SB),4,$0-0\n" + row + "\nRET\n"
				requireX86GoAssemblerResult(t, target.arch, source, true)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
					if err != nil || !strings.Contains(ir, "ret void") {
						t.Fatal("elided hint lost its ordinary continuation", api, err)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				}
			})
		}
	}
}
