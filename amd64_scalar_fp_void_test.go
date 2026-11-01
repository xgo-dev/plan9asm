package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// The declaration supplies logical ABI0 fields only. It does not supply a
// native incoming-frame pointer, a caller certificate or an allocation extent.
func x86ScalarFPVoidSource(t *testing.T, declaration, body, arch string) (*File, FuncSig, string) {
	t.Helper()
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
	sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	if sig.Ret != Void || len(sig.Frame.Results) != 0 {
		t.Fatal("fixture must derive an actual typed void signature")
	}
	end := int64(0)
	for _, slot := range sig.Frame.Params {
		if current := slot.Offset + x86FrameScalarBytes(slot.Type, arch); current > end {
			end = current
		}
	}
	source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s\nRET\n", end, body)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file, sig, source
}

func TestX86ScalarFPBitViewsVoidOriginalObjectsAndThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, shape := range []struct {
		name, declaration string
		offset32          int
	}{
		{"scalar", "func view(x uint64)\n", 2},
		{"bytes", "func view(x [8]byte)\n", 1},
		{"nested", "type Words struct { A [2]uint16; B uint32 }\nfunc view(x Words)\n", 2},
	} {
		for _, move := range []string{"MOVSS", "MOVSD", "VMOVSS", "VMOVSD"} {
			offset := 0
			if strings.HasSuffix(move, "SS") {
				offset = shape.offset32
			}
			body := fmt.Sprintf("%s x+%d(FP),X1", move, offset)
			for _, target := range x86RawReturnTargets {
				t.Run(shape.name+"/"+move+"/"+target.triple, func(t *testing.T) {
					file, sig, source := x86ScalarFPVoidSource(t, shape.declaration, body, target.arch)
					receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					t.Logf("actual original typed-void source object: %+v", receipt)
					if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
						t.Errorf("private input/effect query requires a fabricated result: %v", err)
					}
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("private void query expanded public result admission: %v", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, shape.declaration, target.arch, target.triple, api)
						if err != nil {
							t.Errorf("%s rejected defined typed-void parameter bytes: %v", api, err)
							continue
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

func TestX86ScalarFPBitViewsVoidUnknownInputsRemainContext(t *testing.T) {
	for _, fixture := range []x86ScalarFPBitFixture{
		{name: "unknown-mask", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nVMOVSS.Z x+2(FP),K1,X0"},
		{name: "unknown-merge", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nMOVL $1,AX\nKMOVD AX,K1\nVMOVSS x+2(FP),K1,X0"},
		{name: "partial-lane", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nMOVSS X1,X0\nVMOVSD X0,X1,X2"},
		{name: "branch-only", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nMOVL $1,AX\nCMPL AX,$0\nJE joined\nMOVSS X1,X7\njoined:\nVMOVSS X7,X1,X0"},
		{name: "native-address", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nMOVL $1,AX\nMOVSS (AX),X0"},
		{name: "readonly-input", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nMOVSS X1,x+2(FP)"},
		{name: "pointer-bytes", declaration: "func view(x *uint64)\n", body: "MOVSS x+0(FP),X1"},
		{name: "alignment-hole", declaration: "func view(a byte,x uint64)\n", body: "MOVSS a+0(FP),X1"},
		{name: "unknown-call", declaration: "func view(x uint64)\n", body: "MOVSS x+2(FP),X1\nCALL ·other(SB)"},
	} {
		for _, target := range x86RawReturnTargets {
			t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
				file, sig, source := x86ScalarFPVoidSource(t, fixture.declaration, fixture.body, target.arch)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("void discarded an unknown input/effect: %v", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Errorf("%s void manufactured byte/address authority: %v\n%s", api, err, ir)
					}
				}
			})
		}
	}
}

func TestX86ScalarFPBitViewsVoidKnownMaskedMergeControls(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, move := range []string{"MOVSS", "MOVSD"} {
		for _, active := range []int{0, 1} {
			for _, zero := range []bool{false, true} {
				suffix := ""
				if zero {
					suffix = ".Z"
				}
				body := fmt.Sprintf("%s x+0(FP),X0\nMOVL $%d,AX\nKMOVD AX,K1\nV%s%s x+0(FP),K1,X0", move, active, move, suffix)
				for _, target := range x86RawReturnTargets {
					t.Run(fmt.Sprintf("%s/active%d/zero%t/%s", move, active, zero, target.triple), func(t *testing.T) {
						declaration := "func view(x [8]byte)\n"
						_, _, source := x86ScalarFPVoidSource(t, declaration, body, target.arch)
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil {
								t.Errorf("%s lost initialized masked-void control: %v", api, err)
								continue
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

func TestX86ScalarFPBitViewsVoidLayoutAndEveryByteStayBound(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		file, sig, _ := x86ScalarFPVoidSource(t, "func view(x [8]byte)\n", "MOVSD x+0(FP),X0", arch)
		for missing := range sig.Frame.Params {
			t.Run(fmt.Sprintf("%s/missing-%d", arch, missing), func(t *testing.T) {
				changed := sig
				changed.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
				changed.Frame.Params = append(changed.Frame.Params[:missing], changed.Frame.Params[missing+1:]...)
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], changed, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("void read invented missing byte %d: %v", missing, err)
				}
			})
		}
		for name, mutate := range map[string]func(*Func, *FuncSig){
			"nonvoid-return-without-result": func(_ *Func, sig *FuncSig) { sig.Ret = I64 },
			"void-with-result": func(_ *Func, sig *FuncSig) {
				sig.Frame.Results = []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}}
			},
			"short-argument-extent":     func(fn *Func, _ *FuncSig) { fn.ArgSize = 7 },
			"missing-argument-extent":   func(fn *Func, _ *FuncSig) { fn.ArgSize = 0 },
			"oversized-argument-extent": func(fn *Func, _ *FuncSig) { fn.ArgSize = 4097 },
			"overlapping-parameters": func(_ *Func, sig *FuncSig) {
				sig.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
				sig.Frame.Params[1].Offset = 0
			},
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				fn, changed := file.Funcs[0], sig
				mutate(&fn, &changed)
				if err := checkX86ScalarFPResultInitialization(fn, changed, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("void source/type/layout mutation acquired facts: %v", err)
				}
			})
		}
	}
}
