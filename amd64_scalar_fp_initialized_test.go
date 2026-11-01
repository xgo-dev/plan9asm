package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarFPBitViewsMaskedParameterLoadsRequireDefinedInputs(t *testing.T) {
	for _, bits := range []int{32, 64} {
		op := "MOVSS"
		if bits == 64 {
			op = "MOVSD"
		}
		for name, before := range map[string]string{
			"unknown mask":     "",
			"partial GP mask":  "MOVB $1,AX\nKMOVD AX,K1\n",
			"branch-only mask": "MOVL $1,AX\nCMPL AX,$0\nJE joined\nKMOVD AX,K1\njoined:\n",
			"unknown merge":    "MOVL $0,AX\nKMOVD AX,K1\n",
			"partial merge":    "MOVSS x+0(FP),X1\nMOVSS X1,X7\nMOVL $0,AX\nKMOVD AX,K1\n",
		} {
			for _, zeroing := range []bool{false, true} {
				// Partial X initialization matters only to an eight-byte merge;
				// zeroing does not read the old low destination lane.
				if name == "partial merge" && (bits == 32 || zeroing) || name == "unknown merge" && zeroing {
					continue
				}
				suffix := ""
				if zeroing {
					suffix = ".Z"
				}
				fixture := x86ScalarFPBitFixture{
					name:        fmt.Sprintf("%d/%s/zero%t", bits, name, zeroing),
					declaration: fmt.Sprintf("func view(x uint64) uint%d\n", bits),
					body:        before + fmt.Sprintf("V%s%s x+0(FP),K1,X7\n%s X7,ret+8(FP)", op, suffix, op),
				}
				x86ScalarFPInitializationContextFixture(t, fixture)
			}
		}
	}
}

func TestX86ScalarFPBitViewsWholeNumericStoresRequireDefinedSource(t *testing.T) {
	for _, fixture := range []x86ScalarFPBitFixture{
		{name: "integer32", declaration: "func view() uint32\n", body: "MOVSS X7,ret+0(FP)"},
		{name: "integer64", declaration: "func view() uint64\n", body: "MOVSD X7,ret+0(FP)"},
		{name: "two-integers", declaration: "func view() (a,b uint32)\n", body: "VMOVSD X7,a+0(FP)"},
		{name: "mixed", declaration: "func view() (a float32,b uint32)\n", body: "MOVSD X7,a+0(FP)"},
		{name: "partial-register", declaration: "func view(x uint64) uint64\n", body: "MOVSS x+0(FP),X1\nMOVSS X1,X7\nVMOVSD X7,ret+8(FP)"},
		{name: "branch-only-register", declaration: "func view(x uint64) uint32\n", body: "MOVL $1,AX\nCMPL AX,$0\nJE joined\nMOVSS x+0(FP),X7\njoined:\nMOVSS X7,ret+8(FP)"},
	} {
		x86ScalarFPInitializationContextFixture(t, fixture)
	}
}

func x86ScalarFPInitializationContextFixture(t *testing.T, fixture x86ScalarFPBitFixture) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
			source := x86ScalarFPBitAssembly(t, fixture, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Errorf("%s unknown numeric input acquired a value: %v\n%s", api, err, ir)
				}
			}
		})
	}
}

func TestX86ScalarFPBitViewsKnownMaskedLoadControls(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, bits := range []int{32, 64} {
		op := "MOVSS"
		if bits == 64 {
			op = "MOVSD"
		}
		for _, zeroing := range []bool{false, true} {
			for _, active := range []int{0, 1} {
				suffix, initialize := "", op+" y+8(FP),X7\n"
				if zeroing {
					suffix, initialize = ".Z", ""
				}
				fixture := x86ScalarFPBitFixture{
					name:        fmt.Sprintf("%d/mask%d/zero%t", bits, active, zeroing),
					declaration: fmt.Sprintf("func view(x,y uint64) uint%d\n", bits),
					body:        initialize + fmt.Sprintf("MOVL $%d,AX\nKMOVD AX,K1\nV%s%s x+0(FP),K1,X7\n%s X7,ret+16(FP)", active, op, suffix, op),
				}
				for _, target := range x86RawReturnTargets {
					t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
						source := x86ScalarFPBitAssembly(t, fixture, target.arch)
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
							if err != nil {
								t.Fatalf("%s initialized control: %v", api, err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, ir, level)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86ScalarFPBitViewsMaskedHelperCannotUseMissingSourceProof(t *testing.T) {
	for _, bits := range []int{32, 64} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			var ir strings.Builder
			ctx := newAMD64Ctx(&ir, Func{}, FuncSig{
				Args: []LLVMType{I64}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			}, nil, nil, false)
			if _, err := ctx.loadX86ScalarMemoryIf(Operand{Kind: OpFP}, bits, "false"); !errors.Is(err, ErrProbeNeedsContext) || ir.Len() != 0 {
				t.Fatalf("masked helper manufactured a source or emitted a branch: %v\n%s", err, ir.String())
			}
		})
	}
}
