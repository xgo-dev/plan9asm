package plan9asm

import (
	"bytes"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

func TestGoHelperDeclNameAndLinkname(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "pkg.go", `package p
//go:linkname cmp runtime.cmp
func cmp()
`, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	linknames := goLinknameRemoteToLocal([]*ast.File{f})
	if got := linknames["runtime.cmp"]; got != "cmp" {
		t.Fatalf("runtime.cmp => %q, want cmp", got)
	}

	got, err := goDeclNameForSymbol("·Compare", linknames)
	if err != nil || got != "Compare" {
		t.Fatalf("goDeclNameForSymbol local = (%q, %v), want Compare", got, err)
	}

	got, err = goDeclNameForSymbol("runtime·cmp", linknames)
	if err != nil || got != "cmp" {
		t.Fatalf("goDeclNameForSymbol linkname = (%q, %v), want cmp", got, err)
	}

	if _, err := goDeclNameForSymbol("runtime·missing", linknames); err == nil {
		t.Fatalf("expected missing go:linkname mapping error")
	}
}

func TestGoHelperArchTupleAndSymParsing(t *testing.T) {
	if got, err := goArchFor("amd64"); err != nil || got != ArchAMD64 {
		t.Fatalf("goArchFor amd64 = (%q, %v), want %q", got, err, ArchAMD64)
	}
	if got, err := goArchFor("arm"); err != nil || got != ArchARM {
		t.Fatalf("goArchFor arm = (%q, %v), want %q", got, err, ArchARM)
	}
	if got, err := goArchFor("arm64"); err != nil || got != ArchARM64 {
		t.Fatalf("goArchFor arm64 = (%q, %v), want %q", got, err, ArchARM64)
	}
	if got, err := goArchFor("wasm"); err != nil || got != ArchWASM {
		t.Fatalf("goArchFor wasm = (%q, %v), want %q", got, err, ArchWASM)
	}

	if got := goTupleRetType(nil); got != Void {
		t.Fatalf("goTupleRetType(nil) = %q, want %q", got, Void)
	}
	if got := goTupleRetType([]LLVMType{I64}); got != I64 {
		t.Fatalf("goTupleRetType(single) = %q, want %q", got, I64)
	}
	if got := goTupleRetType([]LLVMType{I64, Ptr}); got != "{ i64, ptr }" {
		t.Fatalf("goTupleRetType(tuple) = %q", got)
	}

	base, off := goSplitSymPlusOff("runtime·foo+16")
	if base != "runtime·foo" || off != 16 {
		t.Fatalf("goSplitSymPlusOff(+16) = (%q, %d)", base, off)
	}
	base, off = goSplitSymPlusOff("runtime·foo-8")
	if base != "runtime·foo" || off != -8 {
		t.Fatalf("goSplitSymPlusOff(-8) = (%q, %d)", base, off)
	}

	base, tail, ok := goReferencedFunc(Instr{
		Op: "JMP",
		Args: []Operand{{
			Kind: OpSym,
			Sym:  "indexbody<>(SB)",
		}},
	})
	if !ok || !tail || base != "indexbody<>" {
		t.Fatalf("goReferencedFunc tail jump = (%q, %v, %v)", base, tail, ok)
	}

	base, tail, ok = goReferencedFunc(Instr{
		Op: "CALL",
		Args: []Operand{{
			Kind: OpSym,
			Sym:  "runtime·cmp(SB)",
		}},
	})
	if !ok || tail || base != "runtime·cmp" {
		t.Fatalf("goReferencedFunc call = (%q, %v, %v)", base, tail, ok)
	}
}

func TestGoExpandConsts(t *testing.T) {
	pkg := types.NewPackage("test/pkg", "pkg")
	addIntConst(pkg, "Local", 7)
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "Big", types.Typ[types.UntypedInt], constant.MakeUint64(^uint64(0))))
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "Text", types.Typ[types.UntypedString], constant.MakeString("test")))
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "Bool", types.Typ[types.UntypedBool], constant.MakeBool(true)))

	runtimePkg := types.NewPackage("runtime", "runtime")
	addIntConst(runtimePkg, "Const", 3)

	src := []byte(`MOVD $const_Local, R0
MOVD foo+const_Local(SB), R1
MOVD runtime.foo+const_Const(SB), R2
MOVD runtime/foo+const_Const(SB), R3
MOVD missing+const_Missing(SB), R4
DATA big(SB)/8, $const_Big
DATA text(SB)/4, $const_Text
MOVD $const_Bool, R5
`)
	got := string(goExpandConsts(src, pkg, map[string]*types.Package{
		"runtime": runtimePkg,
	}))

	for _, want := range []string{
		"MOVD $7, R0",
		"MOVD foo+7(SB), R1",
		"MOVD runtime.foo+3(SB), R2",
		"MOVD runtime/foo+3(SB), R3",
		"MOVD missing+const_Missing(SB), R4",
		"DATA big(SB)/8, $18446744073709551615",
		`DATA text(SB)/4, $"test"`,
		"MOVD $const_Bool, R5",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expanded consts missing %q in:\n%s", want, got)
		}
	}
	if _, err := dataStmtPayload(DataStmt{Sym: "·wide", Width: 1, Payload: []byte("xx")}); err == nil {
		t.Fatal("oversized DATA payload unexpectedly accepted")
	}
}

func TestGoAsmHeaderDataConstants(t *testing.T) {
	pkg := types.NewPackage("test/pkg", "pkg")
	genericName := types.NewTypeName(token.NoPos, pkg, "generic", nil)
	typeParamName := types.NewTypeName(token.NoPos, pkg, "T", nil)
	typeParam := types.NewTypeParam(typeParamName, types.NewInterfaceType(nil, nil).Complete())
	generic := types.NewNamed(genericName, types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "value", typeParam, false),
	}, nil), nil)
	generic.SetTypeParams([]*types.TypeParam{typeParam})
	pkg.Scope().Insert(genericName)
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "smallInt", types.Typ[types.UntypedInt], constant.MakeInt64(42)))
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "bigInt", types.Typ[types.UntypedInt], constant.MakeUint64(^uint64(0))))
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "stringVal", types.Typ[types.UntypedString], constant.MakeString("test")))
	long := "this_is_a_string_constant_longer_than_seventy_characters_which_used_to_fail_see_issue_50253"
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, "longStringVal", types.Typ[types.UntypedString], constant.MakeString(long)))
	fields := []*types.Var{
		types.NewField(token.NoPos, pkg, "a", types.Typ[types.Uint64], false),
		types.NewField(token.NoPos, pkg, "b", types.NewArray(types.Typ[types.Uint8], 100), false),
		types.NewField(token.NoPos, pkg, "c", types.Typ[types.Uint8], false),
		types.NewField(token.NoPos, pkg, "_", types.Typ[types.Uint64], false),
	}
	typName := types.NewTypeName(token.NoPos, pkg, "typ", nil)
	types.NewNamed(typName, types.NewStruct(fields, nil), nil)
	pkg.Scope().Insert(typName)
	intName := types.NewTypeName(token.NoPos, pkg, "word", nil)
	types.NewNamed(intName, types.Typ[types.Int], nil)
	pkg.Scope().Insert(intName)

	unchanged := []byte("MOVD $typ__size, R0")
	if got := goExpandAsmHeaderTypes(unchanged, nil, "arm64"); !bytes.Equal(got, unchanged) {
		t.Fatalf("nil-package expansion changed source: %q", got)
	}
	if got := goExpandAsmHeaderTypes(unchanged, pkg, "unsupported"); !bytes.Equal(got, unchanged) {
		t.Fatalf("unsupported-arch expansion changed source: %q", got)
	}
	genericRef := []byte("MOVD $generic__size, R0")
	if got := goExpandAsmHeaderTypes(genericRef, pkg, "arm64"); !bytes.Equal(got, genericRef) {
		t.Fatalf("uninstantiated generic struct macro unexpectedly expanded: %q", got)
	}
	nonStructPkg := types.NewPackage("test/nonstruct", "nonstruct")
	nonStructPkg.Scope().Insert(types.NewVar(token.NoPos, nonStructPkg, "value", types.Typ[types.Int]))
	if got := goExpandAsmHeaderTypes(unchanged, nonStructPkg, "arm64"); !bytes.Equal(got, unchanged) {
		t.Fatalf("package without struct macros changed source: %q", got)
	}

	src := goExpandConsts([]byte(`TEXT ·dummy(SB),NOSPLIT,$0-0
RET
DATA ·small(SB)/8, $const_smallInt
DATA ·big(SB)/8, $const_bigInt
DATA ·text(SB)/4, $const_stringVal
DATA ·long(SB)/91, $const_longStringVal
`), pkg, nil)
	src = goExpandAsmHeaderTypes(append(src, []byte(`DATA ·typSize(SB)/8, $typ__size
DATA ·typA(SB)/8, $typ_a
DATA ·typB(SB)/8, $typ_b
DATA ·typC(SB)/8, $typ_c
DATA ·blank(SB)/8, $typ__
`)...), pkg, "arm64")
	file, err := Parse(ArchARM64, string(src))
	if err == nil {
		t.Fatal("blank struct field macro unexpectedly expanded")
	}
	src = bytes.ReplaceAll(src, []byte("DATA ·blank(SB)/8, $typ__\n"), nil)
	file, err = Parse(ArchARM64, string(src))
	if err != nil {
		t.Fatalf("Parse(expanded asmhdr) error = %v\n%s", err, src)
	}
	want := map[string][]byte{
		"·small":   {42, 0, 0, 0, 0, 0, 0, 0},
		"·big":     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"·text":    []byte("test"),
		"·long":    []byte(long),
		"·typSize": {120, 0, 0, 0, 0, 0, 0, 0},
		"·typA":    {0, 0, 0, 0, 0, 0, 0, 0},
		"·typB":    {8, 0, 0, 0, 0, 0, 0, 0},
		"·typC":    {108, 0, 0, 0, 0, 0, 0, 0},
	}
	for _, data := range file.Data {
		got, err := dataStmtPayload(data)
		if err != nil {
			t.Fatalf("dataStmtPayload(%s) error = %v", data.Sym, err)
		}
		expect, ok := want[data.Sym]
		if !ok {
			t.Fatalf("unexpected DATA symbol %q", data.Sym)
		}
		if !bytes.Equal(got, expect) {
			t.Fatalf("DATA %s payload = %v, want %v", data.Sym, got, expect)
		}
		delete(want, data.Sym)
	}
	if len(want) != 0 {
		t.Fatalf("missing DATA symbols: %v", want)
	}

	translation, err := TranslateGoModule(GoPackage{Path: pkg.Path(), Types: pkg}, []byte(`#include "go_asm.h"
DATA ·typSize(SB)/8, $typ__size
GLOBL ·typSize(SB), RODATA, $8
`), GoModuleOptions{GOARCH: "arm64"})
	if err != nil {
		t.Fatalf("TranslateGoModule(go_asm.h) error = %v", err)
	}
	defer translation.Module.Dispose()
	if ir := translation.Module.String(); !strings.Contains(ir, `c"x\00\00\00\00\00\00\00"`) {
		t.Fatalf("TranslateGoModule(go_asm.h) did not expand typ__size:\n%s", ir)
	}
}

func TestGoLLVMHelpers(t *testing.T) {
	iface := types.NewInterfaceType(nil, nil)
	iface.Complete()
	namedSlice := types.NewNamed(
		types.NewTypeName(token.NoPos, nil, "Bytes", nil),
		types.NewSlice(types.Typ[types.Byte]),
		nil,
	)

	cases := []struct {
		name string
		typ  types.Type
		want LLVMType
	}{
		{name: "bool", typ: types.Typ[types.Bool], want: I1},
		{name: "uintptr", typ: types.Typ[types.Uintptr], want: I64},
		{name: "string", typ: types.Typ[types.String], want: "{ ptr, i64 }"},
		{name: "slice", typ: types.NewSlice(types.Typ[types.Byte]), want: "{ ptr, i64, i64 }"},
		{name: "interface", typ: iface, want: "{ ptr, ptr }"},
		{name: "named", typ: namedSlice, want: "{ ptr, i64, i64 }"},
	}
	for _, tc := range cases {
		got, err := goLLVMTypeForType(tc.typ, "arm64")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	if got, err := goLLVMTypeForType(types.NewMap(types.Typ[types.String], types.Typ[types.Int]), "arm64"); err != nil || got != Ptr {
		t.Fatalf("map handle type = (%q, %v), want ptr", got, err)
	}

	sz := types.SizesFor("gc", "arm64")
	tup := types.NewTuple(
		types.NewVar(token.NoPos, nil, "s", types.Typ[types.String]),
		types.NewVar(token.NoPos, nil, "b", types.NewSlice(types.Typ[types.Byte])),
		types.NewVar(token.NoPos, nil, "v", iface),
	)

	args, slots, next, err := goLLVMArgsAndFrameSlotsForTuple(tup, "arm64", sz, sz, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(args), 3; got != want {
		t.Fatalf("flatten=false args len = %d, want %d", got, want)
	}
	if got, want := len(slots), 7; got != want {
		t.Fatalf("flatten=false slots len = %d, want %d", got, want)
	}
	if next != 56 {
		t.Fatalf("flatten=false next = %d, want 56", next)
	}
	if slots[0].Field != 0 || slots[1].Field != 1 || slots[2].Field != 0 {
		t.Fatalf("unexpected slot field mapping: %#v", slots[:3])
	}

	args, slots, next, err = goLLVMArgsAndFrameSlotsForTuple(tup, "arm64", sz, sz, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(args), 7; got != want {
		t.Fatalf("flatten=true args len = %d, want %d", got, want)
	}
	if got, want := len(slots), 7; got != want {
		t.Fatalf("flatten=true slots len = %d, want %d", got, want)
	}
	if next != 56 {
		t.Fatalf("flatten=true next = %d, want 56", next)
	}
}

func TestGoFuncSigForDeclaredFuncRejectsUnsupportedForms(t *testing.T) {
	sz := types.SizesFor("gc", "arm64")
	recvType := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Receiver", nil), types.NewStruct(nil, nil), nil)
	recv := types.NewVar(token.NoPos, nil, "r", recvType)

	methodSig := types.NewSignature(recv, types.NewTuple(), types.NewTuple(), false)
	method := types.NewFunc(token.NoPos, nil, "Method", methodSig)
	if _, err := goFuncSigForDeclaredFunc("pkg.Method", method, "arm64", sz, sz, true); err == nil || !strings.Contains(err.Error(), "methods in asm not supported") {
		t.Fatalf("expected method rejection, got %v", err)
	}

	variadicSig := types.NewSignature(
		nil,
		types.NewTuple(types.NewVar(token.NoPos, nil, "args", types.NewSlice(types.Typ[types.Int]))),
		types.NewTuple(),
		true,
	)
	variadic := types.NewFunc(token.NoPos, nil, "Variadic", variadicSig)
	if _, err := goFuncSigForDeclaredFunc("pkg.Variadic", variadic, "arm64", sz, sz, true); err == nil || !strings.Contains(err.Error(), "variadic asm not supported") {
		t.Fatalf("expected variadic rejection, got %v", err)
	}
}

func addIntConst(pkg *types.Package, name string, v int64) {
	pkg.Scope().Insert(types.NewConst(token.NoPos, pkg, name, types.Typ[types.Int], constant.MakeInt64(v)))
}
