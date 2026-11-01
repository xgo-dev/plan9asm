package plan9asm

import (
	"go/types"
	"testing"
)

type arm64PaddingChangedSizes struct {
	types.Sizes
	change string
}

func (s arm64PaddingChangedSizes) Sizeof(typ types.Type) int64 {
	if s.change == "narrow-size" && typ == types.Typ[types.Int16] {
		return 4
	}
	return s.Sizes.Sizeof(typ)
}

func (s arm64PaddingChangedSizes) Alignof(typ types.Type) int64 {
	if s.change == "narrow-align" && typ == types.Typ[types.Int16] {
		return 4
	}
	return s.Sizes.Alignof(typ)
}

func (s arm64PaddingChangedSizes) Offsetsof(fields []*types.Var) []int64 {
	offsets := append([]int64(nil), s.Sizes.Offsetsof(fields)...)
	if s.change == "aggregate-offset" && len(offsets) > 1 {
		offsets[1]++
	}
	return offsets
}

func TestARM64FPPaddingWholeTypedSizesAreRequired(t *testing.T) {
	pkg := mustGoPackage(t, "padbits", "package padbits\ntype Row struct { a byte; b uint64 }\nfunc Narrow(row Row, rhs int16) (res uint64)\n")
	declaration := pkg.Types.Scope().Lookup("Narrow").(*types.Func)
	gc := types.SizesFor("gc", "arm64")
	sig, err := DeriveGoFuncABI0Signature("Narrow", declaration, "arm64", gc)
	if err != nil || sig.arm64FPReadDeclaration == nil {
		t.Fatalf("complete actual GC declaration: %v", err)
	}
	for _, change := range []string{"narrow-size", "narrow-align", "aggregate-offset"} {
		changed := arm64PaddingChangedSizes{Sizes: gc, change: change}
		for _, layouts := range [][2]types.Sizes{{changed, gc}, {gc, changed}} {
			if got := arm64FPReadDeclarationForGo(sig, declaration.Type().(*types.Signature), layouts[0], layouts[1]); got != nil {
				t.Fatalf("%s custom typed/frame layout obtained padding authority", change)
			}
		}
	}
}

func TestARM64FPPaddingModifiedConstantDependencies(t *testing.T) {
	forms := append(arm64RawMOVIMVNIForms(), arm64RawORRBICForms()...)
	for _, form := range forms {
		for _, immediate := range []byte{0, 1, 0x55, 0x80, 0xff} {
			word := encodeARM64RawModifiedImmediate(form.opBit, form.cmode, form.q, immediate, 0)
			decoded, ok := decodeARM64RawModifiedImmediate(word)
			if !ok {
				t.Fatal("existing typed constant grammar rejected its complete fixture")
			}
			old := arm64PaddingBits{0xffffffffffffffff, 0xffffffffffffffff}
			state := arm64PaddingState{"V0": old}
			ins := Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
			if !state.transferPaddingRawConstant(ins) {
				t.Fatal("registered constant family was not consumed")
			}
			want := arm64PaddingBits{}
			if form.op == "VORR" || form.op == "VBIC" {
				for lane := 0; lane < form.arrangement.lanes; lane++ {
					want.setElement(form.arrangement.elementBits, lane, arm64PaddingMask(form.arrangement.elementBits)&^decoded.value)
				}
			}
			if got := state.read("V0"); got != want {
				t.Fatalf("%s cmode=%d Q=%d immediate=%#x: dependency=%#v want=%#v", form.op, form.cmode, form.q, immediate, got, want)
			}
		}
	}
	for _, operand := range []Operand{
		{Kind: OpImm, Imm: 0xffffffff},
		{Kind: OpImm, Imm: 0x4f000400, ImmRaw: "unresolved"},
		{Kind: OpImm, Imm: 0x4f000400, ImmIsFloat: true},
		{Kind: OpReg, Reg: "R0"},
	} {
		state := arm64PaddingState{"V0": {1, 1}}
		if state.transferPaddingRawConstant(Instr{Op: OpWORD, Args: []Operand{operand}}) || state.read("V0") != (arm64PaddingBits{1, 1}) {
			t.Fatal("unknown/unresolved raw constant washed away a dependency")
		}
	}
}
