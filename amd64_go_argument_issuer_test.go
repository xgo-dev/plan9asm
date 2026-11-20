package plan9asm

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"testing"
)

func TestAMD64GoArgumentIssuerDoesNotExtendResultLanguage(t *testing.T) {
	sizes := types.SizesFor("gc", "amd64")
	for _, parameter := range []string{"byte", "uint16", "uint32", "uint64", "*byte"} {
		for _, result := range []struct{ name, declarations, spelling string }{
			{"float32", "", "float32"},
			{"float64", "", "float64"},
			{"complex64", "", "complex64"},
			{"complex128", "", "complex128"},
			{"struct-float", "", "struct { Value float64 }"},
			{"array-complex", "", "[1]complex128"},
			{"pointer-float", "", "*float64"},
			{"slice-float", "", "[]float32"},
			{"named-float", "type Result float64\n", "Result"},
			{"alias-complex", "type Result = complex64\n", "Result"},
		} {
			t.Run(parameter+"/"+result.name, func(t *testing.T) {
				pkg := mustGoPackage(t, "example.invalid/issuer",
					"package issuer\n"+result.declarations+fmt.Sprintf("func Entry(a %s) %s\n", parameter, result.spelling))
				fn := pkg.Types.Scope().Lookup("Entry").(*types.Func)
				sig, err := DeriveGoFuncABI0Signature("example.invalid/issuer.Entry", fn, "amd64", sizes)
				if err != nil {
					t.Fatal("valid original Go language declaration did not derive", err)
				}
				if amd64GoArgumentNeedsBinding(sig) {
					t.Fatal("fixture no longer covers the scalar-only issuer branch")
				}
				if _, err := numericalSDKDeclarationLanguage(fn, sizes, false); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("the original result-language role unexpectedly accepted this fixture", err)
				}
				if _, err := numericalSDKDeclarationLanguage(fn, sizes, true); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("argument-only issuer extended result language while its result entry guard was skipped", err)
				}
			})
		}
	}
}

func TestAMD64GoArgumentIssuerKeepsParameterAndResultRolesIndependent(t *testing.T) {
	sizes := types.SizesFor("gc", "amd64")
	for _, parameter := range []string{"byte", "uint16", "uint32", "uint64", "*byte"} {
		for _, result := range []string{"bool", "uint8", "uint16", "uint32", "uint64"} {
			t.Run("old-scalar/"+parameter+"/"+result, func(t *testing.T) {
				pkg := mustGoPackage(t, "example.invalid/issuer", fmt.Sprintf("package issuer\nfunc Entry(a %s) %s\n", parameter, result))
				fn := pkg.Types.Scope().Lookup("Entry").(*types.Func)
				original, err := numericalSDKDeclarationLanguage(fn, sizes, false)
				if err != nil {
					t.Fatal("the original scalar language role was lost", err)
				}
				actual, err := numericalSDKDeclarationLanguage(fn, sizes, true)
				if err != nil || actual != original {
					t.Fatal("argument role changed the old scalar/result identity", err)
				}
			})
		}
	}
	for _, parameter := range []string{"a bool", "a float32", "a float64", "a complex64", "a complex128",
		"a string", "a []byte", "a [1]float64", "a struct { F float32; N uint64 }"} {
		t.Run("argument-only/"+parameter, func(t *testing.T) {
			input := amd64ArgumentEntryModel(t, parameter)
			if _, err := numericalSDKDeclarationLanguage(input.Declaration, sizes, true); err != nil {
				t.Fatal("the separately validated parameter language role was removed", err)
			}
			if _, err := amd64GoArgumentEntryPlan(input); err != nil {
				t.Fatal("original integer result and register-only argument model were lost", err)
			}
		})
	}
	for _, result := range []string{"bool", "uint8", "uint16", "uint32", "uint64"} {
		t.Run("named-scalar-result/"+result, func(t *testing.T) {
			input := amd64ArgumentEntryModel(t, "a float64")
			pkg := mustGoPackage(t, input.Package.Path(), fmt.Sprintf("package args\ntype Result %s\nfunc Entry(a float64) Result\n", result))
			input.Package = pkg.Types
			input.Declaration = pkg.Types.Scope().Lookup("Entry").(*types.Func)
			var err error
			input.Signature, err = DeriveGoFuncABI0Signature(input.Native, input.Declaration, "amd64", sizes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := numericalSDKDeclarationLanguage(input.Declaration, sizes, true); err != nil {
				t.Fatal("the original named scalar language identity was lost", err)
			}
			if _, err := amd64GoArgumentEntryPlan(input); err != nil {
				t.Fatal("named scalar result was confused with an aggregate transport", err)
			}
		})
	}
	for _, result := range []string{"*byte", "string", "[]byte", "struct { N uint64 }", "[1]uint64",
		"struct { B bool }", "[1]bool", "(uint64, uint64)"} {
		t.Run("language-is-not-result-transport/"+result, func(t *testing.T) {
			input := amd64ArgumentEntryModel(t, "a float64")
			pkg := mustGoPackage(t, input.Package.Path(), fmt.Sprintf("package args\nfunc Entry(a float64) %s\n", result))
			input.Package = pkg.Types
			input.Declaration = pkg.Types.Scope().Lookup("Entry").(*types.Func)
			var err error
			input.Signature, err = DeriveGoFuncABI0Signature(input.Native, input.Declaration, "amd64", sizes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := numericalSDKDeclarationLanguage(input.Declaration, sizes, true); err != nil {
				t.Fatal("old result language identity was confused with entry transport", err)
			}
			if _, err := amd64GoArgumentEntryPlan(input); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a language comparison granted a pointer/aggregate/multiple result transport", err)
			}
		})
	}
}

func TestAMD64GoArgumentIssuerRejectsResultCallbacksBeforeSampling(t *testing.T) {
	for _, role := range []string{"language", "entry"} {
		t.Run(role, func(t *testing.T) {
			calls := 0
			result := &amd64ArgumentCallbackType{calls: &calls}
			input := amd64ArgumentEntryModel(t, "a uint64")
			signature := types.NewSignatureType(nil, nil, nil,
				input.Declaration.Type().(*types.Signature).Params(),
				types.NewTuple(types.NewVar(token.NoPos, nil, "r", result)), false)
			pkg := types.NewPackage(input.Package.Path(), input.Package.Name())
			input.Declaration = types.NewFunc(token.NoPos, pkg, "Entry", signature)
			pkg.Scope().Insert(input.Declaration)
			input.Package = pkg
			var err error
			if role == "language" {
				value, failure := numericalSDKDeclarationLanguage(input.Declaration, types.SizesFor("gc", "amd64"), true)
				err = failure
				if value != "" {
					t.Fatal("caller-controlled type gained language identity", value)
				}
			} else {
				plan, failure := amd64GoArgumentEntryPlan(input)
				err = failure
				if plan != nil {
					t.Fatal("caller-controlled result acquired an entry plan", plan)
				}
			}
			if !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
				t.Fatalf("result type reached a callback before rejection: err=%v, calls=%d", err, calls)
			}
		})
	}
}
