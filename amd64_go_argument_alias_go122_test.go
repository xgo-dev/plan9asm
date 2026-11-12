//go:build go1.22

package plan9asm

import (
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"testing"
)

func amd64ArgumentAlias(typ types.Type, count int) types.Type {
	for index := 0; index < count; index++ {
		typ = types.NewAlias(types.NewTypeName(token.NoPos, nil, "Alias", nil), typ)
	}
	return typ
}

func amd64ArgumentAliasSignature(typ types.Type) *types.Signature {
	return types.NewSignatureType(nil, nil, nil,
		types.NewTuple(types.NewVar(token.NoPos, nil, "value", typ)), nil, false)
}

func TestAMD64GoArgumentPlanAliasesPreserveConcreteIdentity(t *testing.T) {
	for _, count := range []int{1, 2, 32} {
		typ := amd64ArgumentAlias(types.Typ[types.Uint32], count)
		plan, err := planAMD64GoArguments(amd64ArgumentAliasSignature(typ))
		if !amd64ArgumentAliasHasActualRHS(typ) {
			if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("opaque alias acquired a concrete argument plan at depth %d: %#v, %v", count, plan, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		argument := plan.Arguments[0]
		if argument.Type != typ || argument.Stack || len(argument.Carriers) != 1 ||
			argument.Carriers[0].Type != I32 || argument.Carriers[0].Width != 4 || argument.Carriers[0].Register != AX {
			t.Fatalf("concrete alias/group identity was lost at depth %d: %#v", count, argument)
		}
	}
	boolean := amd64ArgumentAlias(types.Typ[types.Bool], 2)
	floating := amd64ArgumentAlias(types.Typ[types.Float32], 1)
	aggregate := amd64ArgumentAlias(types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, nil, "B", boolean, false),
		types.NewField(token.NoPos, nil, "F", floating, false),
	}, nil), 2)
	plan, err := planAMD64GoArguments(amd64ArgumentAliasSignature(aggregate))
	if !amd64ArgumentAliasHasActualRHS(aggregate) {
		if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("opaque alias descendants acquired concrete byte kinds: %#v, %v", plan, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	want := []amd64GoArgumentCarrier{
		{Path: []int{0}, Offset: 0, Width: 1, Type: I1, Kind: amd64GoArgumentBoolean, Register: AX},
		{Path: []int{1}, Offset: 4, Width: 4, Type: "float", Kind: amd64GoArgumentFloating, Register: "X0"},
	}
	if plan.Arguments[0].Type != aggregate || !reflect.DeepEqual(plan.Arguments[0].Carriers, want) {
		t.Fatalf("alias descendants changed their concrete byte kinds: %#v", plan)
	}
}

func TestAMD64GoArgumentPlanAliasesRejectUnresolvedAndUnboundedRHS(t *testing.T) {
	parameter := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), types.NewInterfaceType(nil, nil).Complete())
	generic := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Generic", nil), types.Typ[types.Uint64], nil)
	generic.SetTypeParams([]*types.TypeParam{types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "U", nil), types.NewInterfaceType(nil, nil).Complete())})
	for _, test := range []struct {
		name string
		typ  types.Type
	}{
		{"type-parameter", amd64ArgumentAlias(parameter, 1)},
		{"alias-of-alias-type-parameter", amd64ArgumentAlias(parameter, 2)},
		{"generic-named-RHS", amd64ArgumentAlias(generic, 2)},
		{"alias-depth", amd64ArgumentAlias(types.Typ[types.Uint64], 33)},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := planAMD64GoArguments(amd64ArgumentAliasSignature(test.typ))
			if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unsupported alias RHS acquired a partial plan: %#v, %v", plan, err)
			}
		})
	}
}

func TestAMD64GoArgumentIssuerAliasesRetainResultBoundary(t *testing.T) {
	for _, count := range []int{1, 2, 32} {
		for _, scalar := range []types.Type{types.Typ[types.Bool], types.Typ[types.Uint8], types.Typ[types.Uint16],
			types.Typ[types.Uint32], types.Typ[types.Uint64]} {
			t.Run(fmt.Sprintf("%s/depth-%d", scalar, count), func(t *testing.T) {
				input := amd64ArgumentEntryModel(t, "a float64")
				result := amd64ArgumentAlias(scalar, count)
				pkg := types.NewPackage(input.Package.Path(), input.Package.Name())
				signature := types.NewSignatureType(nil, nil, nil,
					input.Declaration.Type().(*types.Signature).Params(),
					types.NewTuple(types.NewVar(token.NoPos, nil, "r", result)), false)
				input.Declaration = types.NewFunc(token.NoPos, pkg, "Entry", signature)
				pkg.Scope().Insert(input.Declaration)
				input.Package = pkg
				var err error
				input.Signature, err = DeriveGoFuncABI0Signature(input.Native, input.Declaration, "amd64", types.SizesFor("gc", "amd64"))
				if err != nil {
					t.Fatal(err)
				}
				language, err := numericalSDKDeclarationLanguage(input.Declaration, types.SizesFor("gc", "amd64"), true)
				if !amd64ArgumentAliasHasActualRHS(result) {
					if language != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("opaque scalar result alias acquired a language identity", language, err)
					}
					if plan, err := amd64GoArgumentEntryPlan(input); plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("opaque scalar result alias acquired an independent transport", plan, err)
					}
					return
				}
				if err != nil {
					t.Fatal("concrete scalar result alias lost its language identity", err)
				}
				if _, err := amd64GoArgumentEntryPlan(input); err != nil {
					t.Fatal("concrete scalar result alias lost its independent transport", err)
				}
			})
		}
	}
	for _, count := range []int{1, 2} {
		calls := 0
		result := amd64ArgumentAlias(&amd64ArgumentCallbackType{calls: &calls}, count)
		signature := types.NewSignatureType(nil, nil, nil, nil,
			types.NewTuple(types.NewVar(token.NoPos, nil, "r", result)), false)
		function := types.NewFunc(token.NoPos, nil, "Entry", signature)
		calls = 0 // Only issuer sampling, not fixture construction, is observed.
		if _, err := numericalSDKDeclarationLanguage(function, types.SizesFor("gc", "amd64"), true); !errors.Is(err, ErrProbeNeedsContext) || calls != 0 {
			t.Fatalf("alias RHS reached caller type callbacks at depth %d: err=%v, calls=%d", count, err, calls)
		}
	}
}
