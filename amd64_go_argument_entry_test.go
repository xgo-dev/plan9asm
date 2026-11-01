package plan9asm

import (
	"errors"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This is an independent comparison model, not a live compiler/source token.
func amd64ArgumentEntryModel(t *testing.T, parameters string) amd64GoArgumentEntryInput {
	t.Helper()
	typed := amd64ArgumentTestSignature(t, parameters)
	pkg := types.NewPackage("example.invalid/carriers", "carriers")
	fn := types.NewFunc(token.NoPos, pkg, "Entry", typed)
	pkg.Scope().Insert(fn)
	native := pkg.Path() + ".Entry"
	sig, err := DeriveGoFuncABI0Signature(native, fn, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	text := gostaticstorage.TextRecord{Name: native, ABI: 1, Kind: 1,
		Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Size: 1, Code: []byte{0xc3}}
	return amd64GoArgumentEntryInput{Package: pkg, Declaration: fn, Signature: sig,
		Native: native, Target: "linux/amd64", Goarch: "amd64", GOAMD64: "v1", GOEXPERIMENT: "", GOFLAGS: "",
		SymABI: []byte("def " + native + " ABIInternal\n"), Original: text, Expanded: text}
}

func TestAMD64GoArgumentEntryCompleteCompilerAssociation(t *testing.T) {
	for _, parameters := range []string{
		"a,b string", "a,b []byte", "a float64, b bool, c struct { X byte; Y [1]float32; P *byte }",
		"a,b,c,d,e,f,g,h,i uint64", "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o float64",
	} {
		t.Run(parameters, func(t *testing.T) {
			input := amd64ArgumentEntryModel(t, parameters)
			plan, err := amd64GoArgumentEntryPlan(input)
			if err != nil || plan == nil || plan.requireRegisters() != nil || len(plan.Arguments) != len(input.Signature.Args) {
				t.Fatalf("complete declared compiler-derived transport: %#v, %v", plan, err)
			}
		})
	}
	for _, standard := range []bool{false, true} {
		input := amd64ArgumentEntryModel(t, "a,b string")
		alias := numericalCompilerAliasModel(standard)
		input.Native, input.Signature.Name, input.Standard = alias.Native, alias.Native, standard
		input.Original.Name, input.Expanded.Name, input.SymABI = alias.Native, alias.Native, alias.SymABI
		input.Aliases, _ = numericalCompilerAliasIndex(alias.SymABI, alias.Generated, alias.Selected)
		if _, err := amd64GoArgumentEntryPlan(input); err != nil {
			t.Fatal("complete separately observed foreign compiler association did not join", err)
		}
		input.Aliases = nil
		if plan, err := amd64GoArgumentEntryPlan(input); plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("foreign spelling/SymABI without original compiler alias acquired arguments", err)
		}
	}
}

func TestAMD64GoArgumentEntryLanguageRoleDoesNotWidenOrdinaryFrame(t *testing.T) {
	sizes := types.SizesFor("gc", "amd64")
	for _, parameters := range []string{"a float32", "a float64", "a string", "a struct { S [1]string; F float64 }"} {
		t.Run(parameters, func(t *testing.T) {
			typ := amd64ArgumentTestSignature(t, parameters).Params().At(0).Type()
			if _, err := goAMD64FrameLanguageTypeRole(typ, sizes, true); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ordinary frame language query acquired the private argument transport", err)
			}
			first, err := goAMD64LanguageTypeRole(typ, sizes, true, true)
			if err != nil || first == "" {
				t.Fatal("bounded argument language comparison rejected its declared type", err)
			}
			secondType := amd64ArgumentTestSignature(t, strings.ReplaceAll(parameters, "float64", "uint64")).Params().At(0).Type()
			second, err := goAMD64LanguageTypeRole(secondType, sizes, true, true)
			if strings.Contains(parameters, "float64") && (err != nil || first == second) {
				t.Fatal("same-size integer/FP typegraph drift was erased", err)
			}
		})
	}
	for _, result := range []types.Type{types.Typ[types.Float64], types.NewPointer(types.Typ[types.Byte]), types.NewStruct(nil, nil)} {
		input := amd64ArgumentEntryModel(t, "a string")
		declaration := types.NewSignatureType(nil, nil, nil, input.Declaration.Type().(*types.Signature).Params(),
			types.NewTuple(types.NewVar(token.NoPos, nil, "", result)), false)
		pkg := types.NewPackage(input.Package.Path(), input.Package.Name())
		input.Declaration = types.NewFunc(token.NoPos, pkg, "Entry", declaration)
		pkg.Scope().Insert(input.Declaration)
		input.Package = pkg
		input.Signature, _ = DeriveGoFuncABI0Signature(input.Native, input.Declaration, "amd64", sizes)
		if plan, err := amd64GoArgumentEntryPlan(input); plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("argument type comparison silently widened result transport", err)
		}
	}
}

func TestAMD64GoArgumentEntryRejectsChangedSourceTypeABIProfile(t *testing.T) {
	for name, mutate := range map[string]func(*amd64GoArgumentEntryInput){
		"missing-package": func(v *amd64GoArgumentEntryInput) { v.Package = nil },
		"foreign-package": func(v *amd64GoArgumentEntryInput) { v.Package = types.NewPackage(v.Package.Path(), v.Package.Name()) },
		"shadowed-declaration": func(v *amd64GoArgumentEntryInput) {
			v.Declaration = types.NewFunc(token.NoPos, v.Package, "Entry", v.Declaration.Type().(*types.Signature))
		},
		"foreign-native":   func(v *amd64GoArgumentEntryInput) { v.Native = "runtime.other" },
		"missing-def":      func(v *amd64GoArgumentEntryInput) { v.SymABI = []byte("ref " + v.Native + " ABIInternal\n") },
		"ABI0-def":         func(v *amd64GoArgumentEntryInput) { v.SymABI = []byte("def " + v.Native + " ABI0\n") },
		"duplicate-def":    func(v *amd64GoArgumentEntryInput) { v.SymABI = append(v.SymABI, v.SymABI...) },
		"unknown-row":      func(v *amd64GoArgumentEntryInput) { v.SymABI = append(v.SymABI, []byte("garbage\n")...) },
		"native-ABI0":      func(v *amd64GoArgumentEntryInput) { v.Original.ABI = 0 },
		"changed-expanded": func(v *amd64GoArgumentEntryInput) { v.Expanded.Flags ^= 1 },
		"missing-code":     func(v *amd64GoArgumentEntryInput) { v.Original.Code = nil },
		"private-TEXT":     func(v *amd64GoArgumentEntryInput) { v.Original.Namespace = gostaticstorage.TextSymbolSelf },
		"wrong-target":     func(v *amd64GoArgumentEntryInput) { v.Target = "linux/386" },
		"wrong-mode":       func(v *amd64GoArgumentEntryInput) { v.Goarch = "386" },
		"feature-profile":  func(v *amd64GoArgumentEntryInput) { v.GOAMD64 = "v3" },
		"experiment":       func(v *amd64GoArgumentEntryInput) { v.GOEXPERIMENT = "regabiargs" },
		"flags":            func(v *amd64GoArgumentEntryInput) { v.GOFLAGS = "-N" },
		"argument-group":   func(v *amd64GoArgumentEntryInput) { v.Signature.Args = []LLVMType{Ptr, I64, Ptr, I64} },
		"result-width":     func(v *amd64GoArgumentEntryInput) { v.Signature.Ret = I32 },
		"manual-registers": func(v *amd64GoArgumentEntryInput) { v.Signature.ArgRegs = []Reg{AX, BX} },
		"frame-layout":     func(v *amd64GoArgumentEntryInput) { v.Signature.Frame.Params[0].Offset++ },
	} {
		t.Run(name, func(t *testing.T) {
			input := amd64ArgumentEntryModel(t, "a,b string")
			mutate(&input)
			if plan, err := amd64GoArgumentEntryPlan(input); plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed association gained a carrier plan: %#v, %v", plan, err)
			}
		})
	}
	for _, parameters := range []string{
		"a,b,c,d,e,f,g,h uint64, s string, last uint64",
		"a,b,c,d,e,f,g,h,i,j,k,l,m,n float64, z complex128, last float64",
		"a [2]uint32", "a struct{}",
	} {
		t.Run("stack/"+strings.ReplaceAll(parameters, "/", "_"), func(t *testing.T) {
			if plan, err := amd64GoArgumentEntryPlan(amd64ArgumentEntryModel(t, parameters)); plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("spill homes or true stack arguments became entry authority: %#v, %v", plan, err)
			}
		})
	}
}
