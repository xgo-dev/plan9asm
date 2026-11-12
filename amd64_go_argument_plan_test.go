package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func amd64ArgumentTestSignature(t *testing.T, parameters string) *types.Signature {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "arguments.go", "package arguments\nfunc Entry("+parameters+") int", 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check("example.invalid/arguments", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg.Scope().Lookup("Entry").Type().(*types.Signature)
}

func TestAMD64GoArgumentPlanIndependentTypedCarriers(t *testing.T) {
	type expected struct {
		parameter int
		path      []int
		offset    int64
		width     int64
		typ       LLVMType
		kind      amd64GoArgumentKind
		register  Reg
	}
	tests := []struct {
		name       string
		parameters string
		gp, fp     int
		want       []expected
	}{
		{"strings", "a, b string", 4, 0, []expected{
			{0, []int{0}, 0, 8, Ptr, amd64GoArgumentPointer, AX},
			{0, []int{1}, 8, 8, I64, amd64GoArgumentInteger, BX},
			{1, []int{0}, 0, 8, Ptr, amd64GoArgumentPointer, CX},
			{1, []int{1}, 8, 8, I64, amd64GoArgumentInteger, DI},
		}},
		{"slices", "a, b []byte", 6, 0, []expected{
			{0, []int{0}, 0, 8, Ptr, amd64GoArgumentPointer, AX},
			{0, []int{1}, 8, 8, I64, amd64GoArgumentInteger, BX},
			{0, []int{2}, 16, 8, I64, amd64GoArgumentInteger, CX},
			{1, []int{0}, 0, 8, Ptr, amd64GoArgumentPointer, DI},
			{1, []int{1}, 8, 8, I64, amd64GoArgumentInteger, SI},
			{1, []int{2}, 16, 8, I64, amd64GoArgumentInteger, "R8"},
		}},
		{"independent-banks", "f float64, n uint32, b bool, s string", 4, 1, []expected{
			{0, nil, 0, 8, "double", amd64GoArgumentFloating, "X0"},
			{1, nil, 0, 4, I32, amd64GoArgumentInteger, AX},
			{2, nil, 0, 1, I1, amd64GoArgumentBoolean, BX},
			{3, []int{0}, 0, 8, Ptr, amd64GoArgumentPointer, CX},
			{3, []int{1}, 8, 8, I64, amd64GoArgumentInteger, DI},
		}},
		{"nested-padding-and-array-one", "a struct { B byte; F struct { X float32; N uint16 }; P [1]*byte }", 3, 1, []expected{
			{0, []int{0}, 0, 1, I8, amd64GoArgumentInteger, AX},
			{0, []int{1, 0}, 4, 4, "float", amd64GoArgumentFloating, "X0"},
			{0, []int{1, 1}, 8, 2, I16, amd64GoArgumentInteger, BX},
			{0, []int{2, 0}, 16, 8, Ptr, amd64GoArgumentPointer, CX},
		}},
		{"complex-and-opaque-handles", "z complex64, p *byte, m map[int]int, c chan byte, f func(), i interface{}", 6, 2, []expected{
			{0, []int{0}, 0, 4, "float", amd64GoArgumentFloating, "X0"},
			{0, []int{1}, 4, 4, "float", amd64GoArgumentFloating, "X1"},
			{1, nil, 0, 8, Ptr, amd64GoArgumentPointer, AX},
			{2, nil, 0, 8, Ptr, amd64GoArgumentPointer, BX},
			{3, nil, 0, 8, Ptr, amd64GoArgumentPointer, CX},
			{4, nil, 0, 8, Ptr, amd64GoArgumentPointer, DI},
			{5, []int{0}, 0, 8, Ptr, amd64GoArgumentPointer, SI},
			{5, []int{1}, 8, 8, Ptr, amd64GoArgumentPointer, "R8"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sig := amd64ArgumentTestSignature(t, test.parameters)
			plan, err := planAMD64GoArguments(sig)
			if err != nil {
				t.Fatal(err)
			}
			if plan.GPUsed != test.gp || plan.FPUsed != test.fp || len(plan.Arguments) != sig.Params().Len() {
				t.Fatalf("incorrect complete grouping/banks: %#v", plan)
			}
			var got []expected
			for _, argument := range plan.Arguments {
				if argument.Type != sig.Params().At(argument.Index).Type() || argument.Stack {
					t.Fatalf("original parameter identity/group lost: %#v", argument)
				}
				for _, carrier := range argument.Carriers {
					got = append(got, expected{argument.Index, carrier.Path, carrier.Offset, carrier.Width, carrier.Type, carrier.Kind, carrier.Register})
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("carrier map\n got %#v\nwant %#v", got, test.want)
			}
			if err := plan.requireRegisters(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAMD64GoArgumentPlanWholeArgumentSpillRollback(t *testing.T) {
	for _, test := range []struct {
		name, parameters string
		spilled, next    int
		register         Reg
		gp, fp           int
	}{
		{"gp-string", "a,b,c,d,e,f,g,h uint64, s string, last uint64", 8, 9, "R11", 9, 0},
		{"fp-complex", "a,b,c,d,e,f,g,h,i,j,k,l,m,n float64, z complex128, last float64", 14, 15, "X14", 0, 15},
		{"both-bank-rollback", "a,b,c,d,e,f,g,h uint64, s struct { F float64; A,B uint64 }, last float64, n uint64", 8, 9, "X0", 9, 1},
		{"fp-failure-does-not-consume-gp", "a,b,c,d,e,f,g,h,i,j,k,l,m,n float64, s struct { P *byte; Z complex128 }, last uint64", 14, 15, AX, 1, 14},
		{"nontrivial-array", "a [2]uint32, n uint64", 0, 1, AX, 1, 0},
		{"nested-array", "a struct { N uint64; V [2]float64 }, n uint64", 0, 1, AX, 1, 0},
		{"zero-size", "a struct{}, n uint64", 0, 1, AX, 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := planAMD64GoArguments(amd64ArgumentTestSignature(t, test.parameters))
			if err != nil {
				t.Fatal(err)
			}
			spill := plan.Arguments[test.spilled]
			if !spill.Stack || len(spill.Carriers) != 0 {
				t.Fatalf("whole argument was partially assigned: %#v", spill)
			}
			next := plan.Arguments[test.next]
			if next.Stack || len(next.Carriers) != 1 || next.Carriers[0].Register != test.register || plan.GPUsed != test.gp || plan.FPUsed != test.fp {
				t.Fatalf("failed parameter consumed registers: %#v", plan)
			}
			if err := plan.requireRegisters(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("stack assignment acquired register/backing permission: %v", err)
			}
		})
	}
}

func TestAMD64GoArgumentPlanPreservesGroupingAndZeroFields(t *testing.T) {
	grouped, err := planAMD64GoArguments(amd64ArgumentTestSignature(t, "a,b,c,d,e,f,g,h uint64, pair struct { X,Y uint64 }"))
	if err != nil {
		t.Fatal(err)
	}
	separate, err := planAMD64GoArguments(amd64ArgumentTestSignature(t, "a,b,c,d,e,f,g,h uint64, x,y uint64"))
	if err != nil {
		t.Fatal(err)
	}
	if len(grouped.Arguments) != 9 || !grouped.Arguments[8].Stack || grouped.GPUsed != 8 ||
		len(separate.Arguments) != 10 || separate.Arguments[8].Stack || !separate.Arguments[9].Stack ||
		separate.Arguments[8].Carriers[0].Register != "R11" {
		t.Fatal("flattening changed the original all-or-nothing parameter boundary")
	}
	for _, test := range []struct {
		parameters string
		stack      bool
		path       []int
	}{
		{"a struct { Z [0]uint64; N uint64 }", false, []int{1}},
		{"a struct { Z struct{}; N uint64 }", false, []int{1}},
		{"a struct { Z [1]struct{}; N uint64 }", false, []int{1}},
		// CalcArraySize makes even a zero-sized nontrivial array unsuitable
		// for recursive register assignment of this nonzero-sized struct.
		{"a struct { Z [2]struct{}; N uint64 }", true, nil},
	} {
		t.Run(test.parameters, func(t *testing.T) {
			plan, err := planAMD64GoArguments(amd64ArgumentTestSignature(t, test.parameters))
			if err != nil {
				t.Fatal(err)
			}
			argument := plan.Arguments[0]
			if argument.Stack != test.stack {
				t.Fatalf("incorrect zero-field classification: %#v", argument)
			}
			if !test.stack && (len(argument.Carriers) != 1 || !reflect.DeepEqual(argument.Carriers[0].Path, test.path) || argument.Carriers[0].Offset != 0) {
				t.Fatalf("zero field acquired storage/carriers or changed the field path: %#v", argument)
			}
		})
	}
}

func TestAMD64GoArgumentPlanCompleteScalarKindsAndRegisterBanks(t *testing.T) {
	for _, test := range []struct {
		typ   types.BasicKind
		width int64
		llvm  LLVMType
		kind  amd64GoArgumentKind
	}{
		{types.Bool, 1, I1, amd64GoArgumentBoolean},
		{types.Int8, 1, I8, amd64GoArgumentInteger}, {types.Uint8, 1, I8, amd64GoArgumentInteger},
		{types.Int16, 2, I16, amd64GoArgumentInteger}, {types.Uint16, 2, I16, amd64GoArgumentInteger},
		{types.Int32, 4, I32, amd64GoArgumentInteger}, {types.Uint32, 4, I32, amd64GoArgumentInteger},
		{types.Int64, 8, I64, amd64GoArgumentInteger}, {types.Uint64, 8, I64, amd64GoArgumentInteger},
		{types.Int, 8, I64, amd64GoArgumentInteger}, {types.Uint, 8, I64, amd64GoArgumentInteger},
		{types.Uintptr, 8, I64, amd64GoArgumentInteger}, {types.UnsafePointer, 8, Ptr, amd64GoArgumentPointer},
		{types.Float32, 4, "float", amd64GoArgumentFloating}, {types.Float64, 8, "double", amd64GoArgumentFloating},
	} {
		t.Run(types.Typ[test.typ].Name(), func(t *testing.T) {
			parameter := types.NewVar(token.NoPos, nil, "value", types.Typ[test.typ])
			sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(parameter), nil, false)
			plan, err := planAMD64GoArguments(sig)
			if err != nil {
				t.Fatal(err)
			}
			carriers := plan.Arguments[0].Carriers
			if len(carriers) != 1 || carriers[0].Width != test.width || carriers[0].Type != test.llvm || carriers[0].Kind != test.kind {
				t.Fatalf("scalar kind/byte extent differs: %#v", carriers)
			}
		})
	}
	for _, test := range []struct {
		name      string
		typ       string
		registers []Reg
	}{
		{"GP", "uint64", []Reg{AX, BX, CX, DI, SI, "R8", "R9", "R10", "R11"}},
		{"FP", "float64", []Reg{"X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parameters := strings.TrimSuffix(strings.Repeat(test.typ+",", len(test.registers)), ",")
			plan, err := planAMD64GoArguments(amd64ArgumentTestSignature(t, parameters))
			if err != nil {
				t.Fatal(err)
			}
			for index, argument := range plan.Arguments {
				if argument.Stack || len(argument.Carriers) != 1 || argument.Carriers[0].Register != test.registers[index] {
					t.Fatalf("incorrect bank order at %d: %#v", index, argument)
				}
			}
		})
	}
}

func TestAMD64GoArgumentPlanRejectsUnsupportedAndUnboundedTypes(t *testing.T) {
	signature := func(typ types.Type) *types.Signature {
		return types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(token.NoPos, nil, "value", typ)), nil, false)
	}
	deep := types.Type(types.Typ[types.Uint64])
	for index := 0; index < 34; index++ {
		deep = types.NewArray(deep, 1)
	}
	parameter := types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "T", nil), types.NewInterfaceType(nil, nil).Complete())
	generic := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Generic", nil), types.Typ[types.Uint64], nil)
	generic.SetTypeParams([]*types.TypeParam{types.NewTypeParam(types.NewTypeName(token.NoPos, nil, "U", nil), types.NewInterfaceType(nil, nil).Complete())})
	constraint := types.NewInterfaceType(nil, []types.Type{types.NewUnion([]*types.Term{types.NewTerm(true, types.Typ[types.Int])})}).Complete()
	tests := map[string]*types.Signature{
		"nil":             nil,
		"variadic":        amd64ArgumentTestSignature(t, "values ...byte"),
		"type-parameter":  signature(parameter),
		"generic-named":   signature(generic),
		"constraint":      signature(constraint),
		"untyped-integer": signature(types.Typ[types.UntypedInt]),
		"invalid":         signature(types.Typ[types.Invalid]),
		"unbounded-depth": signature(deep),
		"array-overflow":  signature(types.NewArray(types.Typ[types.Uint64], 1<<62)),
		"method": types.NewSignatureType(types.NewVar(token.NoPos, nil, "receiver", types.Typ[types.Int]), nil, nil,
			types.NewTuple(), nil, false),
		"generic-function": types.NewSignatureType(nil, nil, []*types.TypeParam{parameter}, types.NewTuple(), nil, false),
	}
	for name, sig := range tests {
		t.Run(name, func(t *testing.T) {
			plan, err := planAMD64GoArguments(sig)
			if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unsupported shape got a partial plan: %#v, %v", plan, err)
			}
		})
	}
	if err := (*amd64GoArgumentPlan)(nil).requireRegisters(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("nil plan acquired a register role: %v", err)
	}
}

func TestAMD64GoArgumentPlanIndependentInventoryBudgets(t *testing.T) {
	makeSignature := func(count int, typ types.Type) *types.Signature {
		parameters := make([]*types.Var, count)
		for index := range parameters {
			parameters[index] = types.NewVar(token.NoPos, nil, "", typ)
		}
		return types.NewSignatureType(nil, nil, nil, types.NewTuple(parameters...), nil, false)
	}
	for _, count := range []int{4096, 4097} {
		t.Run(fmt.Sprintf("parameters-%d", count), func(t *testing.T) {
			plan, err := planAMD64GoArguments(makeSignature(count, types.Typ[types.Uint64]))
			if count == 4096 {
				if err != nil || len(plan.Arguments) != count || plan.GPUsed != 9 {
					t.Fatalf("exact parameter boundary: %#v, %v", plan, err)
				}
			} else if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("oversized parameter inventory: %#v, %v", plan, err)
			}
		})
	}
	for _, count := range []int{2048, 2049} {
		t.Run(fmt.Sprintf("complex-carriers-%d", count), func(t *testing.T) {
			plan, err := planAMD64GoArguments(makeSignature(count, types.Typ[types.Complex128]))
			if count == 2048 {
				if err != nil || len(plan.Arguments) != count || plan.FPUsed != 14 {
					t.Fatalf("exact carrier boundary: %#v, %v", plan, err)
				}
			} else if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("oversized carrier inventory: %#v, %v", plan, err)
			}
		})
	}
	for _, count := range []int{4095, 4096} {
		t.Run(fmt.Sprintf("struct-nodes-%d", count+1), func(t *testing.T) {
			fields := make([]*types.Var, count)
			for index := range fields {
				fields[index] = types.NewField(token.NoPos, nil, fmt.Sprintf("N%d", index), types.Typ[types.Uint64], false)
			}
			plan, err := planAMD64GoArguments(makeSignature(1, types.NewStruct(fields, nil)))
			if count == 4095 {
				if err != nil || len(plan.Arguments) != 1 || !plan.Arguments[0].Stack {
					t.Fatalf("exact node boundary: %#v, %v", plan, err)
				}
			} else if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("oversized node inventory: %#v, %v", plan, err)
			}
		})
	}
	for _, count := range []int{32, 33} {
		t.Run(fmt.Sprintf("depth-%d", count), func(t *testing.T) {
			typ := types.Type(types.Typ[types.Uint64])
			for index := 0; index < count; index++ {
				typ = types.NewArray(typ, 1)
			}
			plan, err := planAMD64GoArguments(makeSignature(1, typ))
			if count == 32 {
				if err != nil || len(plan.Arguments[0].Carriers[0].Path) != count {
					t.Fatalf("exact depth boundary: %#v, %v", plan, err)
				}
			} else if plan != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("oversized depth: %#v, %v", plan, err)
			}
		})
	}
}

func TestAMD64GoArgumentPlanRetainsNamedIdentityAndIndependentPaths(t *testing.T) {
	first := types.NewNamed(types.NewTypeName(token.NoPos, nil, "First", nil), types.Typ[types.Uint32], nil)
	second := types.NewNamed(types.NewTypeName(token.NoPos, nil, "Second", nil), types.Typ[types.Uint32], nil)
	aggregate := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, nil, "A", first, false),
		types.NewField(token.NoPos, nil, "B", second, false),
	}, nil)
	sig := types.NewSignatureType(nil, nil, nil,
		types.NewTuple(types.NewVar(token.NoPos, nil, "value", aggregate)), nil, false)
	plan, err := planAMD64GoArguments(sig)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Arguments[0].Type != aggregate || aggregate.Field(0).Type() != first || aggregate.Field(1).Type() != second {
		t.Fatal("same-width original language identities were replaced")
	}
	plan.Arguments[0].Carriers[0].Path[0] = 99
	again, err := planAMD64GoArguments(sig)
	if err != nil || again.Arguments[0].Carriers[0].Path[0] != 0 || plan.Arguments[0].Carriers[1].Path[0] != 1 {
		t.Fatal("one plan or sibling carrier mutated another owned path")
	}
}

func TestAMD64GoArgumentPlanDoesNotAuthorizeExistingSourceConsumers(t *testing.T) {
	for _, parameters := range []string{"value string", "value []byte", "value float64", "value bool", "value struct { N uint64 }"} {
		t.Run(parameters, func(t *testing.T) {
			declaration := amd64ArgumentTestSignature(t, parameters)
			plan, err := planAMD64GoArguments(declaration)
			if err != nil || plan.requireRegisters() != nil {
				t.Fatalf("valid private model was not calculated: %#v, %v", plan, err)
			}
			fn := types.NewFunc(token.NoPos, nil, "Entry", declaration)
			sig, err := DeriveGoFuncABI0Signature("Entry", fn, "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, "TEXT ·Entry<ABIInternal>(SB),4,$0-64\nMOVQ $1,AX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ctx := &amd64Ctx{fpScalarSource: file.Funcs[0], sig: sig, goarch: "amd64"}
			if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private allocation plan widened the existing register entry: %v", err)
			}
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private allocation plan became ABI0 result storage: %v", err)
			}
		})
	}
}

func TestAMD64GoArgumentPlanEveryScalarWidthAndNoHiddenDX(t *testing.T) {
	sig := amd64ArgumentTestSignature(t, "a int8, b uint16, c int32, d uint64, e bool, p *byte, f float32, g float64")
	plan, err := planAMD64GoArguments(sig)
	if err != nil {
		t.Fatal(err)
	}
	widths := []int64{1, 2, 4, 8, 1, 8, 4, 8}
	kinds := []amd64GoArgumentKind{amd64GoArgumentInteger, amd64GoArgumentInteger, amd64GoArgumentInteger, amd64GoArgumentInteger,
		amd64GoArgumentBoolean, amd64GoArgumentPointer, amd64GoArgumentFloating, amd64GoArgumentFloating}
	for index, argument := range plan.Arguments {
		if len(argument.Carriers) != 1 || argument.Carriers[0].Width != widths[index] || argument.Carriers[0].Kind != kinds[index] {
			t.Fatalf("incorrect declared byte kind/width at %d: %#v", index, argument)
		}
		if argument.Carriers[0].Register == DX {
			t.Fatal("hidden DX context was assigned as an ordinary argument")
		}
	}
	if strings.Contains(types.TypeString(sig, nil), "DX") {
		t.Fatal("planner mutated the original logical declaration")
	}
}
