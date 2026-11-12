package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"testing"
)

func TestDeriveGoFuncABI0SignatureUsesActualTargetGCSizes(t *testing.T) {
	const source = `package replay
type Value uint16
type Alias = Value
const (
	_ = iota
	Width
	Count = Width + 2
)
type Row struct {
	Pad byte
	Payload [Count]Alias
	Tail uintptr
}
func Probe(a uint8, r Row) (answer uintptr, ok bool)
`
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			set := token.NewFileSet()
			file, err := parser.ParseFile(set, "replay.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", arch)
			pkg, err := (&types.Config{Sizes: sizes}).Check("example.invalid/replay", set, []*ast.File{file}, nil)
			if err != nil {
				t.Fatal(err)
			}
			function := pkg.Scope().Lookup("Probe").(*types.Func)
			actual, err := DeriveGoFuncABI0Signature("example.invalid/replay.Probe", function, arch, sizes)
			if err != nil {
				t.Fatal(err)
			}
			word, wordType := int64(4), I32
			rowType := LLVMType("{ i8, [3 x i16], i32 }")
			if arch == "amd64" || arch == "arm64" || arch == "wasm" {
				word, wordType = 8, I64
				rowType = "{ i8, [3 x i16], i64 }"
			}
			result := word + 8 + word
			want := FuncSig{
				Name: "example.invalid/replay.Probe",
				Args: []LLVMType{I8, rowType},
				Ret:  LLVMType("{ " + string(wordType) + ", i1 }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I8, Index: 0, Field: -1},
						{Offset: word, Type: I8, Index: 1, Field: 0},
						{Offset: word + 2, Type: I16, Index: 1, Field: 1, Fields: []int{1, 0}},
						{Offset: word + 4, Type: I16, Index: 1, Field: 1, Fields: []int{1, 1}},
						{Offset: word + 6, Type: I16, Index: 1, Field: 1, Fields: []int{1, 2}},
						{Offset: word + 8, Type: wordType, Index: 1, Field: 2},
					},
					Results: []FrameSlot{
						{Offset: result, Type: wordType, Index: 0, Field: -1, Name: "answer"},
						{Offset: result + word, Type: I1, Index: 1, Field: -1, Name: "ok"},
					},
				},
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("actual typed %s ABI0 signature:\n%#v\nwant:\n%#v", arch, actual, want)
			}
			ordinary, err := goFuncSigForDeclaredFunc(want.Name, function, arch, sizes, sizes, true)
			if err != nil || !reflect.DeepEqual(actual, ordinary) {
				t.Fatalf("thin replay API changed the ordinary builder: %v", err)
			}
		})
	}
}

func TestDeriveGoFuncABI0SignatureRejectsMissingOrUnsupportedDeclaration(t *testing.T) {
	if _, err := DeriveGoFuncABI0Signature("", nil, "arm64", nil); err == nil {
		t.Fatal("missing actual declaration supplied an ABI")
	}
	if _, err := DeriveGoFuncABI0Signature("Probe", types.NewFunc(token.NoPos, nil, "Probe", nil), "arm64", nil); err == nil {
		t.Fatal("untyped function supplied an ABI")
	}
	pkg := mustGoPackage(t, "example.invalid/replay", "package replay\nfunc Probe(args ...uint64)\n")
	if _, err := DeriveGoFuncABI0Signature("example.invalid/replay.Probe", pkg.Types.Scope().Lookup("Probe").(*types.Func), "arm64", nil); err == nil {
		t.Fatal("variadic declaration supplied an ordinary assembly ABI")
	}
	pkg = mustGoPackage(t, "example.invalid/replay", "package replay\nfunc Probe()\n")
	if _, err := DeriveGoFuncABI0Signature("example.invalid/replay.Probe", pkg.Types.Scope().Lookup("Probe").(*types.Func), "unknown", nil); err == nil {
		t.Fatal("unknown target supplied a Go gc ABI")
	}
}
