package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86LegacyAlternatingRoundMemoryCase struct {
	op, instruction string
	scalar          bool
	bytes           []byte
}

func x86LegacyAlternatingRoundMemoryCases() []x86LegacyAlternatingRoundMemoryCase {
	return []x86LegacyAlternatingRoundMemoryCase{
		{"ADDSUBPS", "ADDSUBPS (BX),X1", false, []byte{0xf2, 0x0f, 0xd0, 0x0b}},
		{"ADDSUBPD", "ADDSUBPD (BX),X1", false, []byte{0x66, 0x0f, 0xd0, 0x0b}},
		{"ROUNDPS", "ROUNDPS $9,(BX),X1", false, []byte{0x66, 0x0f, 0x3a, 0x08, 0x0b, 9}},
		{"ROUNDPD", "ROUNDPD $9,(BX),X1", false, []byte{0x66, 0x0f, 0x3a, 0x09, 0x0b, 9}},
		{"ROUNDSS", "ROUNDSS $9,(BX),X1", true, []byte{0x66, 0x0f, 0x3a, 0x0a, 0x0b, 9}},
		{"ROUNDSD", "ROUNDSD $9,(BX),X1", true, []byte{0x66, 0x0f, 0x3a, 0x0b, 0x0b, 9}},
	}
}

// Manual opaque Ptr fields deliberately carry no array/pointee extent. The
// same explicit ABI0 layout is supplied to all three public APIs.
func x86LegacyAlternatingRoundMemoryAPI(t *testing.T, source, declarations, arch, triple, api string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declarations)
	word := int64(goWordSize(arch))
	manualCalls := 0
	manual := func(name string) (FuncSig, bool) {
		manualCalls++
		return FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: word, Type: Ptr, Index: 1, Field: -1},
				{Offset: 2 * word, Type: Ptr, Index: 2, Field: -1},
			}}}, true
	}
	ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, arch, triple, api, manual)
	if manualCalls == 0 {
		t.Fatal("opaque-pointer fixture did not consume its explicit manual ABI0 signature")
	}
	return ir, err
}

func x86LegacyAlternatingRoundMemoryAssembly(arch, name string, row x86LegacyAlternatingRoundMemoryCase, wide bool, change string) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	base := fmt.Sprintf("%s input+%d(FP),BX\n", move, word)
	if change == "missing-base" {
		base = ""
	} else if change == "numeric-base" {
		base = move + " $1,BX\n"
	}
	bank := "X"
	if wide {
		bank = "Z"
	}
	seed := "VMOVUPS (CX)," + bank + "1\n"
	if change == "missing-old" {
		seed = ""
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),AX\n%s%s old+%d(FP),CX\n%s%s\nVMOVUPS %s1,(AX)\nRET\n",
		name, 3*word, move, base, move, 2*word, seed, row.instruction, bank)
	return source, "func " + name + "(out,input,old *byte)\n"
}

func TestX86LegacyAlternatingMemoryNativeFeature(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"ADDSUBPS", "ADDSUBPD"} {
			for _, source := range []string{"(BX)", "input+0(FP)", "X0"} {
				ins := x86ScalarLaneInstruction(t, op+" "+source+",X1")
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}})
				if strings.Contains(features, "+sse3") != (source == "(BX)") {
					t.Fatal("only the original native memory opcode requires SSE3", arch, ins, features)
				}
			}
		}
	}
}

func TestX86LegacyAlternatingRoundMemoryActualGoBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LegacyAlternatingRoundMemoryCases() {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				got := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$0-0\n"+row.instruction+"\nRET\n")
				want := append(append([]byte(nil), row.bytes...), 0xc3)
				if !bytes.Equal(got, want) {
					t.Fatalf("original legacy memory opcode/control changed: got=%x want=%x", got, want)
				}
			})
		}
	}
}

func TestX86LegacyAlternatingRoundMemoryRejectsForeignBackendBeforeEmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, triple := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, row := range x86LegacyAlternatingRoundMemoryCases() {
				t.Run(arch+"/"+row.op+"/"+triple, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.instruction)
					ctx, body := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
					ctx.goarch, ctx.targetTriple = arch, triple
					before := body.String()
					var known, terminated bool
					var err error
					if strings.HasPrefix(row.op, "ADDSUB") {
						known, terminated, err = ctx.lowerAlternatingFloatingAddSubtract(ins.Op, ins)
					} else {
						known, terminated, err = ctx.lowerRound(ins.Op, ins)
					}
					if !known || terminated || !errors.Is(err, ErrProbeNeedsContext) || body.String() != before {
						t.Fatal("foreign/default legacy memory backend emitted partial IR or acquired native permission", err)
					}
				})
			}
			// A fully initialized public control avoids an earlier missing-input
			// rejection being misreported as native backend enforcement.
			row := x86LegacyAlternatingRoundMemoryCases()[2]
			source, declaration := x86LegacyAlternatingRoundMemoryAssembly(arch, "LegacyMemoryForeign", row, false, "complete")
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/public/"+triple+"/"+api, func(t *testing.T) {
					ir, err := x86LegacyAlternatingRoundMemoryAPI(t, source, declaration, arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("foreign/default public target acquired a native legacy memory function", api, err)
					}
				})
			}
		}
	}
}

// These matching-x86 objects are not portable/native runtime acceptance.
// Observe all64 aliases while keeping the tested source as an opaque Ptr.
func TestX86LegacyAlternatingRoundOpaquePointerMemoryObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for _, row := range x86LegacyAlternatingRoundMemoryCases() {
				one, declaration := x86LegacyAlternatingRoundMemoryAssembly(target.arch, "LegacyMemory"+row.op, row, true, "complete")
				source.WriteString(one)
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86LegacyAlternatingRoundMemoryAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete opaque-pointer legacy source rejected", err)
					}
					for _, row := range x86LegacyAlternatingRoundMemoryCases() {
						if !strings.Contains(ir, "asm sideeffect \""+strings.ToLower(row.op)+" ") {
							t.Fatal("legacy memory operation lost its original observable instruction", row.op)
						}
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}
}

func TestX86LegacyAlternatingRoundMemoryRequiresActualInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86LegacyAlternatingRoundMemoryCases() {
			changes := []string{"complete", "missing-base", "numeric-base"}
			if row.scalar || strings.HasPrefix(row.op, "ADDSUB") {
				changes = append(changes, "missing-old")
			}
			for _, change := range changes {
				t.Run(arch+"/"+row.op+"/"+change, func(t *testing.T) {
					source, declaration := x86LegacyAlternatingRoundMemoryAssembly(arch, "LegacyMemoryInputs", row, false, change)
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86LegacyAlternatingRoundMemoryAPI(t, source, declaration, arch, triple, api)
						if change == "complete" {
							if err != nil || ir == "" {
								t.Fatal("complete manual Ptr inputs rejected", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("missing address/old input borrowed implementation bytes", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86LegacyRoundNativeMemoryOnlyNeedsCopiedOldUpper(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, bits := range []int{32, 64} {
			op := "ROUNDSS"
			if bits == 64 {
				op = "ROUNDSD"
			}
			ins := x86ScalarLaneInstruction(t, op+" $9,(BX),X1")
			low := x86CallerVectorByteMask(int64(bits / 8))
			before := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
			base, _, _ := x86ResultGP(BX, int64(goWordSize(arch)), arch)
			before.pointerGP[base] = true
			before.writeVector(1, 64, ^low, false) // Old active bytes are deliberately unknown.
			for _, native := range []bool{false, true} {
				state := before.clone()
				accepted, known := x86ResultRoundStep(ins, &state, nil, arch, native)
				if !known || accepted != native {
					t.Fatal("paired legacy scalar read required overwritten old low bytes", arch, op, native, accepted)
				}
				want := before.clone()
				if native {
					want.writeVector(1, 16, 0xffff, true)
				}
				if !reflect.DeepEqual(state, want) {
					t.Fatal("legacy scalar read changed upper aliases, pointer or FLAGS", arch, op, native)
				}
			}
		}
	}
}
