//go:build go1.22

package plan9asm

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"testing"
)

// Go1.22 exposes Alias but not its immediate RHS. Underlying/Unalias cannot
// replace the independently bounded complete chain observed by these roles.
func amd64ArgumentAliasHasActualRHS(typ types.Type) bool {
	_, available := typ.(interface{ Rhs() types.Type })
	return goAMD64FrameIsAlias(typ) && available
}

func TestAMD64GoArgumentAliasConsumersRequireActualRHS(t *testing.T) {
	sizes := types.SizesFor("gc", "amd64")
	named := types.NewNamed(types.NewTypeName(token.NoPos, nil, "NamedWord", nil), types.Typ[types.Uint32], nil)
	for _, count := range []int{1, 2, 32} {
		for _, scalar := range []types.Type{types.Typ[types.Bool], types.Typ[types.Uint32],
			types.Typ[types.Float32], types.Typ[types.Float64], named} {
			t.Run(fmt.Sprintf("%s/depth-%d", scalar, count), func(t *testing.T) {
				typ := amd64ArgumentAlias(scalar, count)
				available := amd64ArgumentAliasHasActualRHS(typ)
				check := func(role string, expectConcrete, complete bool, err error) {
					t.Helper()
					if expectConcrete {
						if !complete || err != nil {
							t.Fatal("actual concrete alias RHS was lost", role, complete, err)
						}
					} else if complete || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("alias acquired an unobserved or over-depth RHS contract", role, complete, err)
					}
				}
				plan, err := planAMD64GoArguments(amd64ArgumentAliasSignature(typ))
				check("argument layout", available, plan != nil, err)
				// A language identity retains the Named node and its underlying
				// node separately. After 32 aliases, the latter is depth 33;
				// the argument layout's scalar shape does not add that node.
				languageAvailable := available && (scalar != named || count < 32)
				language, err := goAMD64LanguageTypeRole(typ, sizes, true, true)
				check("argument language", languageAvailable, language != "", err)
				language, err = goAMD64NumericalScalarLanguageType(typ, sizes, true)
				check("ordinary numerical scalar language", languageAvailable, language != "", err)
				if scalar == types.Typ[types.Float32] || scalar == types.Typ[types.Float64] {
					if _, err := goAMD64FrameLanguageType(typ, sizes); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("alias API availability expanded the ordinary frame's floating role", err)
					}
				}
			})
		}
	}
	for _, count := range []int{1, 2, 32} {
		t.Run(fmt.Sprintf("no-callback/depth-%d", count), func(t *testing.T) {
			calls := 0
			typ := amd64ArgumentAlias(&amd64ArgumentCallbackType{calls: &calls}, count)
			calls = 0 // Fixture construction is not an observer or source capability.
			plan, err := planAMD64GoArguments(amd64ArgumentAliasSignature(typ))
			if plan != nil || !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
				t.Fatal("opaque argument alias invoked caller callbacks", plan, err, calls)
			}
			language, err := goAMD64LanguageTypeRole(typ, sizes, true, true)
			if language != "" || !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
				t.Fatal("opaque argument language invoked caller callbacks", language, err, calls)
			}
			language, err = goAMD64NumericalScalarLanguageType(typ, sizes, true)
			if language != "" || !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
				t.Fatal("opaque numerical scalar language invoked caller callbacks", language, err, calls)
			}
		})
	}
}
