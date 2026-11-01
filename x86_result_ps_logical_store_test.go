package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func TestX86PSLogicalParameterStoreCompleteByteEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		pkg := mustGoPackage(t, "pseffects", "package pseffects\nfunc view(x,y,z,w byte) uint32\n")
		sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		context := amd64Ctx{sig: sig, fpResults: sig.Frame.Results, goarch: arch}
		for _, op := range []string{"EXTRACTPS", "VEXTRACTPS"} {
			first, last := 0, 3
			if op == "VEXTRACTPS" {
				first, last = -128, 255 // Complete signed/unsigned Go imm8 rows.
			}
			for immediate := first; immediate <= last; immediate++ {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, op, immediate), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,X0,x+0(FP)", op, immediate))
					owned := []bool{true, true, true, true}
					state := x86ResultState{fp: make([]bool, 4), flags: x86ByteFlagsAll}
					selected := uint(immediate&3) * 4
					state.xmm[0] = 0xf << selected
					state.xmm[1], state.vectorUpper[0] = 0xabcd, ^uint64(0xffff)
					want := state.clone()
					for offset := range want.fp {
						want.fp[offset] = true
					}
					if ok, known := context.scalarPSLogicalFPWriteTransfer(ins, &state, owned, arch); !known || !ok || !reflect.DeepEqual(state, want) {
						t.Fatal("PS store lost exact source/field/FLAGS/alias effects", ok, known)
					}
					for byteIndex := uint(0); byteIndex < 4; byteIndex++ {
						bad := state.clone()
						bad.xmm[0] &^= 1 << (selected + byteIndex)
						before := bad.clone()
						if ok, known := context.scalarPSLogicalFPWriteTransfer(ins, &bad, owned, arch); !known || ok || !reflect.DeepEqual(bad, before) {
							t.Fatal("PS store manufactured a missing selected byte", byteIndex)
						}
					}
				})
			}
		}
	}
}

func TestX86PSLogicalParameterStoreThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, layout := range []struct {
				name, params string
				width        int
			}{
				{"bytes", "x,y,z,w byte", 4},
				{"words", "x,y uint16", 4},
				{"integer", "x uint32", 4},
				{"float", "x float32", 4},
				{"wide-integer", "x uint64", 8},
				{"wide-float", "x float64", 8},
			} {
				word := goWordSize(target.arch)
				result := (layout.width + word - 1) / word * word
				for _, op := range []string{"EXTRACTPS", "VEXTRACTPS"} {
					for lane := 0; lane < 4; lane++ {
						name := fmt.Sprintf("view%d", count)
						count++
						fmt.Fprintf(&declarations, "func %s(%s) uint32\n", name, layout.params)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOVL $0x87654321,AX\nMOVL AX,X0\n%s $%d,X0,x+0(FP)\nMOVBLZX x+0(FP),AX\nMOVL AX,ret+%d(FP)\nRET\n", name, result+4, op, lane, result)
					}
				}
			}
			if got := strings.Count(declarations.String(), "func "); got != 48 {
				t.Fatalf("incomplete PS source/layout/selector union: %d", got)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			pkg := mustGoPackage(t, "psfields", "package psfields\n"+declarations.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), pkg, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					if got := strings.Count(ir, "define i32 @"); got != 48 {
						t.Fatalf("lost PS functions: %d", got)
					}
					for _, optimizeIR := range []bool{false, true} {
						input := ir
						if optimizeIR {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						compileLLVMToObject(t, findLLVM22Tool("llc"), target.triple, "ps-fields.ll", "ps-fields.o", input)
					}
				})
			}
		})
	}
}

func TestX86PSLogicalParameterStoreKeepsIndependentRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"EXTRACTPS", "VEXTRACTPS"} {
			for _, row := range []struct {
				name, declaration, setup, destination string
			}{
				{"unknown-source", "func view(x uint64) uint32", "", "x+0(FP)"},
				{"missing-selected-byte", "func view(x uint64) uint32", "MOVL $1,AX\nPINSRB $0,AX,X0\n", "x+0(FP)"},
				{"pointer", "func view(x *byte) uint32", "PXOR X0,X0\n", "x+0(FP)"},
				{"bool", "func view(x bool,y,z,w byte) uint32", "PXOR X0,X0\n", "x+0(FP)"},
				{"padding", "func view(x byte,y uint32) uint32", "PXOR X0,X0\n", "x+0(FP)"},
			} {
				t.Run(arch+"/"+op+"/"+row.name, func(t *testing.T) {
					pkg := mustGoPackage(t, "psnegative", "package psnegative\n"+row.declaration+"\n")
					sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
					if err != nil {
						t.Fatal(err)
					}
					result := sig.Frame.Results[0].Offset
					source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s%s $0,X0,%s\nMOVL $1,ret+%d(FP)\nRET\n", result+4, row.setup, op, row.destination, result)
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration+"\n", arch, testTargetTriple("linux", arch), api)
						// The existing complete-span binder diagnoses an absent
						// field before the result observer; this is still an error,
						// not numerical initialization or storage permission.
						if err == nil || ir != "" || row.name != "padding" && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("%s unsupported storage/source acquired permission: %v, IR bytes %d", api, err, len(ir))
						}
					}
				})
			}
			// Standalone declaration checks have no paired logical field writer.
			source := "TEXT view(SB),4,$0-12\nPXOR X0,X0\n" + op + " $0,X0,x+0(FP)\nMOVL $1,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, "psdecl", "package psdecl\nfunc view(x uint64) uint32\n")
			sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("declaration-only query borrowed paired PS writes: %v", err)
			}
		}
	}
}
