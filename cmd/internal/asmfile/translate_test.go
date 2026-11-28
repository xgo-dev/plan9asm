package asmfile

import (
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestFallbackSigUsesTargetWordSize(t *testing.T) {
	fn := plan9asm.Func{Instrs: []plan9asm.Instr{{
		Op: "MOVW",
		Args: []plan9asm.Operand{
			{Kind: plan9asm.OpFP, FPName: "x", FPOffset: 0},
			{Kind: plan9asm.OpFP, FPName: "ret", FPOffset: 4},
		},
	}}}
	for _, tc := range []struct {
		goarch string
		want   plan9asm.LLVMType
	}{
		{goarch: "arm", want: plan9asm.I32},
		{goarch: "386", want: plan9asm.I32},
		{goarch: "arm64", want: plan9asm.I64},
		{goarch: "amd64", want: plan9asm.I64},
		{goarch: "wasm", want: plan9asm.I64},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			got := fallbackSigForAsmFunc(fn, "example.f", tc.goarch)
			if len(got.Args) != 1 || got.Args[0] != tc.want || got.Ret != tc.want {
				t.Fatalf("fallback signature = %#v, want arg and return %s", got, tc.want)
			}
		})
	}
}

func TestLikelyResultSlotUsesExplicitResultPrefix(t *testing.T) {
	if !isLikelyResultSlot("MOVW", 0, 2, "ret0") {
		t.Fatal("ret-prefixed FP slot was not classified as a result")
	}
	for _, name := range []string{"roundTripRet", "r_ret", "request"} {
		if isLikelyResultSlot("MOVW", 0, 2, name) {
			t.Errorf("parameter FP slot %q was classified as a result", name)
		}
	}
}

func TestWasmWordSize(t *testing.T) {
	if got := wordSize("wasm"); got != 8 {
		t.Fatalf("wordSize(wasm) = %d, want official Go wasm word size 8", got)
	}
}

func TestTailLocalHelperKeepsLocalIdentityAndCallerReturn(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM, `TEXT ·caller(SB),NOSPLIT,$0-1
	MOVB $1, ret+0(FP)
	B helper<>(SB)

TEXT helper<>(SB),NOSPLIT,$0-1
	MOVB R0, ret+0(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("example", "example")
	result := types.NewVar(token.NoPos, pkgTypes, "ret", types.Typ[types.Bool])
	caller := types.NewFunc(token.NoPos, pkgTypes, "caller", types.NewSignature(nil, nil, types.NewTuple(result), false))
	pkgTypes.Scope().Insert(caller)
	pkg := plan9asm.GoPackage{Types: pkgTypes}
	sizes := types.SizesFor("gc", "arm")
	sigs, err := sigsForAsmFile(pkg, sizes, file, resolveSymFunc("example"), "arm")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := sigs["example.helper$local"]
	if !ok {
		t.Fatalf("local helper signature missing: %#v", sigs)
	}
	if got.Ret != plan9asm.I1 || len(got.Frame.Results) != 1 || got.Frame.Results[0].Type != plan9asm.I1 {
		t.Fatalf("local helper signature = %#v, want i1 return and result slot", got)
	}
}

func TestPackageQualifiedAsmSymbolUsesLocalDeclaration(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM, `TEXT runtime·pipe2(SB),NOSPLIT,$0-16
	MOVW $r+4(FP), R0
	MOVW flags+0(FP), R1
	MOVW R0, errno+12(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("runtime", "runtime")
	params := types.NewTuple(types.NewVar(token.NoPos, pkgTypes, "flags", types.Typ[types.Int32]))
	results := types.NewTuple(
		types.NewVar(token.NoPos, pkgTypes, "r", types.Typ[types.Int32]),
		types.NewVar(token.NoPos, pkgTypes, "w", types.Typ[types.Int32]),
		types.NewVar(token.NoPos, pkgTypes, "errno", types.Typ[types.Int32]),
	)
	pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "pipe2", types.NewSignature(nil, params, results, false)))
	pkg := plan9asm.GoPackage{Types: pkgTypes}
	sizes := types.SizesFor("gc", "arm")
	sigs, err := sigsForAsmFile(pkg, sizes, file, resolveSymFunc("runtime"), "arm")
	if err != nil {
		t.Fatal(err)
	}
	got := sigs["runtime.pipe2"]
	if len(got.Frame.Results) != 3 || got.Frame.Results[0].Offset != 4 || got.Frame.Results[2].Offset != 12 {
		t.Fatalf("pipe2 signature = %#v, want result slots at 4, 8, 12", got)
	}
}

func TestUndeclaredEntryTailCallInheritsDeclaredVoidReturn(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, `TEXT _rt0_386(SB),NOSPLIT,$8
	JMP runtime·rt0_go(SB)

TEXT runtime·rt0_go(SB),NOSPLIT,$0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pkgTypes := types.NewPackage("runtime", "runtime")
	pkgTypes.Scope().Insert(types.NewFunc(token.NoPos, pkgTypes, "rt0_go", types.NewSignature(nil, nil, nil, false)))
	pkg := plan9asm.GoPackage{Types: pkgTypes}
	sizes := types.SizesFor("gc", "386")
	sigs, err := sigsForAsmFile(pkg, sizes, file, resolveSymFunc("runtime"), "386")
	if err != nil {
		t.Fatal(err)
	}
	if got := sigs["_rt0_386"].Ret; got != plan9asm.Void {
		t.Fatalf("_rt0_386 return = %s, want void from its declared tail target", got)
	}
}

func TestLLVMTypeForGoPointerLikeValues(t *testing.T) {
	for name, typ := range map[string]types.Type{
		"func": types.NewSignature(nil, nil, nil, false),
		"map":  types.NewMap(types.Typ[types.String], types.Typ[types.Int]),
		"chan": types.NewChan(types.SendRecv, types.Typ[types.Int]),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := llvmTypeForGo(typ, "arm"); err != nil || got != plan9asm.Ptr {
				t.Fatalf("llvmTypeForGo(%s) = (%s, %v), want ptr", typ, got, err)
			}
		})
	}
}

func TestZeroSizedTupleValueHasNoFrameSlot(t *testing.T) {
	empty := types.NewStruct(nil, nil)
	tuple := types.NewTuple(types.NewVar(token.NoPos, nil, "marker", empty))
	args, slots, next, err := llvmArgsAndFrameSlotsForTuple(tuple, "arm", types.SizesFor("gc", "arm"), 0, false)
	if err != nil || len(args) != 0 || len(slots) != 0 || next != 0 {
		t.Fatalf("zero-sized tuple = (%v, %v, %d, %v), want empty layout", args, slots, next, err)
	}
}

func TestInterfaceTupleUsesTwoPhysicalFrameSlots(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil).Complete()
	tuple := types.NewTuple(types.NewVar(token.NoPos, nil, "value", iface))
	args, slots, next, err := llvmArgsAndFrameSlotsForTuple(tuple, "386", types.SizesFor("gc", "386"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != plan9asm.LLVMType("{ ptr, ptr }") || len(slots) != 2 || next != 8 {
		t.Fatalf("interface tuple = (%v, %#v, %d), want one aggregate and two pointer slots", args, slots, next)
	}
	if slots[0].Offset != 0 || slots[0].Field != 0 || slots[1].Offset != 4 || slots[1].Field != 1 {
		t.Fatalf("interface frame slots = %#v, want offsets 0/4 and fields 0/1", slots)
	}
}

func Test386AddressedABISuffixedDeclaration(t *testing.T) {
	p := types.NewPackage("pkg", "pkg")
	result := types.NewTuple(types.NewVar(token.NoPos, p, "", types.Typ[types.Int32]))
	p.Scope().Insert(types.NewFunc(token.NoPos, p, "callee", types.NewSignature(nil, nil, result, false)))
	pkg := plan9asm.GoPackage{Types: p}
	sizes := types.SizesFor("gc", "386")
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, "TEXT ·f(SB),4,$0\n MOVL $·callee<ABI0>(SB),AX\n RET")
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := sigsForAsmFile(pkg, sizes, file, func(s string) string { return strings.ReplaceAll(s, "·", "pkg.") }, "386")
	if err != nil || sigs["pkg.callee"].Ret != plan9asm.I32 {
		t.Fatalf("callee signature: %v, %v", sigs, err)
	}
}

func TestLLVMArgsAndFrameSlotsForTupleSliceParam(t *testing.T) {
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "b", types.NewSlice(types.Typ[types.Byte])))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"{ ptr, i64, i64 }"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: 0},
		{Offset: 8, Type: plan9asm.I64, Index: 0, Field: 1},
		{Offset: 16, Type: plan9asm.I64, Index: 0, Field: 2},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 24 {
		t.Fatalf("nextOff mismatch: got=%d want=24", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForTupleSliceResultFlatten(t *testing.T) {
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "r", types.NewSlice(types.Typ[types.Byte])))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{plan9asm.Ptr, plan9asm.I64, plan9asm.I64}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: plan9asm.I64, Index: 1, Field: -1},
		{Offset: 16, Type: plan9asm.I64, Index: 2, Field: -1},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 24 {
		t.Fatalf("nextOff mismatch: got=%d want=24", nextOff)
	}
}

func TestLLVMArgsAndFrameSlotsForTupleInterfaceParam(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil)
	iface.Complete()
	tup := types.NewTuple(types.NewVar(token.NoPos, nil, "v", iface))
	sz := types.SizesFor("gc", "amd64")
	args, slots, nextOff, err := llvmArgsAndFrameSlotsForTuple(tup, "amd64", sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(args, []plan9asm.LLVMType{"{ ptr, ptr }"}) {
		t.Fatalf("args mismatch: %#v", args)
	}
	wantSlots := []plan9asm.FrameSlot{
		{Offset: 0, Type: plan9asm.Ptr, Index: 0, Field: 0},
		{Offset: 8, Type: plan9asm.Ptr, Index: 0, Field: 1},
	}
	if !reflect.DeepEqual(slots, wantSlots) {
		t.Fatalf("slots mismatch: got=%#v want=%#v", slots, wantSlots)
	}
	if nextOff != 16 {
		t.Fatalf("nextOff mismatch: got=%d want=16", nextOff)
	}
}
