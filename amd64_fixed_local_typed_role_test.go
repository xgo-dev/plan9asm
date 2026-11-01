package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalTypedRoleNumericActualWitness(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	name := pkg.Path + ".Value"
	observed, declaration := source.functions[name], source.declarations[name]
	if observed.transport != goAMD64FrameNumericTransport || declaration.transport != goAMD64FrameNumericTransport ||
		observed.languageType == "" || observed.languageType != declaration.languageType {
		t.Fatal("actual numeric object has no matching complete language witness")
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
		if err != nil || !strings.Contains(ir, "fixed_local_native") {
			t.Fatalf("actual numeric witness did not reach its existing private consumer: %v", err)
		}
	})
}

func TestGoAMD64FixedLocalTypedRoleCompositeObservationsNeedCompleteBinding(t *testing.T) {
	for _, test := range []struct {
		name, declaration string
		args, n, result   int64
	}{
		{"pointer", "func Value(a *uint64, n uint64) uint64", 24, 8, 16},
		{"slice", "func Value(a []byte, n uint64) uint64", 40, 24, 32},
		{"pointer to array", "func Value(a *[64]byte, n uint64) uint64", 24, 8, 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			// This complete object reads only the numeric parameter. Its
			// pointer/slice ABI slots are observations, not input permissions.
			assembly := fmt.Sprintf("TEXT ·Value(SB),4,$160-%d\nMOVQ n+%d(FP),AX\nMOVQ AX,ret+%d(FP)\nRET\n", test.args, test.n, test.result)
			pkg, request := goAMD64FrameTypedFixture(t, test.declaration, assembly)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			observed := source.functions[pkg.Path+".Value"]
			if observed.transport != goAMD64FrameCompositeTransport || observed.languageType == "" || len(observed.code) == 0 {
				t.Fatal("actual composite object was not captured as observation-only")
			}
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := DeriveGoFuncABI0Signature(pkg.Path+".Value", pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			options := Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{sig.Name: sig},
				ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil || len(bound.Sigs) != 1 {
				t.Fatalf("complete original composite source lacked its independent local proof: %v", err)
			}
			t.Logf("complete binding retained opaque transport: transport=%d args=%d locals=%d code_bytes=%d", observed.transport, observed.args, observed.locals, len(observed.code))
			// A stale private role must not overrule the independent complete
			// original language typecheck, even if both role records agree.
			declaration := source.declarations[sig.Name]
			declaration.transport = goAMD64FrameNumericTransport
			observed.transport = goAMD64FrameNumericTransport
			source.declarations[sig.Name], source.functions[sig.Name] = declaration, observed
			bound, err = source.BindFixedLocal(ctx, pkg, file, options)
			if !errors.Is(err, ErrProbeNeedsContext) || len(bound.Sigs) != 0 {
				t.Fatalf("paired numeric role claims replaced actual composite source: %v", err)
			}
		})
	}
	// By-value arrays have no Step B observation contract at all. Do not
	// confuse a pointer-to-array observation with machine aggregate layout.
	t.Run("by-value array", func(t *testing.T) {
		pkg, request := goAMD64FrameTypedFixture(t, "func Value(a [2]uint64, n uint64) uint64", "TEXT ·Value(SB),4,$160-32\nRET\n")
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
		if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("by-value array acquired an invented observation contract: %v", err)
		}
	})
}

// These mutations simulate an internal stale role/model, not a public way to
// write opaque fields. The independent original typecheck must remain the
// authority even when two private observations are changed consistently.
func fixedLocalTypedRoleMutation(t *testing.T, source *GoAMD64FrameSource, name, mutation string) {
	t.Helper()
	function, declaration := source.functions[name], source.declarations[name]
	t.Cleanup(func() {
		source.functions[name] = function
		source.declarations[name] = declaration
	})
	changedFunction, changedDeclaration := function, declaration
	switch mutation {
	case "object role":
		changedFunction.transport = goAMD64FrameCompositeTransport
	case "object missing language":
		changedFunction.languageType = ""
	case "object changed language":
		changedFunction.languageType += "changed"
	case "declaration role":
		changedDeclaration.transport = goAMD64FrameCompositeTransport
	case "declaration missing language":
		changedDeclaration.languageType = ""
	case "declaration changed language":
		changedDeclaration.languageType += "changed"
	case "paired changed language":
		changedFunction.languageType += "changed"
		changedDeclaration.languageType = changedFunction.languageType
	case "missing declaration":
		delete(source.declarations, name)
		return
	default:
		t.Fatalf("unknown fixture mutation %q", mutation)
	}
	source.functions[name], source.declarations[name] = changedFunction, changedDeclaration
}

var fixedLocalTypedRoleMutations = []string{
	"object role", "object missing language", "object changed language",
	"declaration role", "declaration missing language", "declaration changed language",
	"paired changed language", "missing declaration",
}

func TestGoAMD64FixedLocalTypedRoleBindRejectsStaleLanguage(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	for _, mutation := range fixedLocalTypedRoleMutations {
		t.Run(mutation, func(t *testing.T) {
			fixedLocalTypedRoleMutation(t, source, pkg.Path+".Value", mutation)
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if !errors.Is(err, ErrProbeNeedsContext) || len(bound.Sigs) != 0 {
				t.Fatalf("stale private observation overrode actual numeric source: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedRoleConsumerRejectsStaleLanguage(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range fixedLocalTypedRoleMutations {
		t.Run(mutation, func(t *testing.T) {
			fixedLocalTypedRoleMutation(t, source, pkg.Path+".Value", mutation)
			fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
		})
	}
}

func TestGoAMD64FixedLocalTypedRoleSuppliedTypeIdentityRemainsExact(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	for _, declaration := range []string{
		"func Value(a, b, c, d int64) int64",
		"func Value(a, b, c, d uintptr) uint64",
		"func Value(a, b, c, renamed uint64) uint64",
	} {
		t.Run(declaration, func(t *testing.T) {
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, "changed.go", "package framefixture\n"+declaration+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			typed, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check(pkg.Path, fset, []*ast.File{syntax}, nil)
			if err != nil {
				t.Fatal(err)
			}
			changed := pkg
			changed.Types, changed.Syntax = typed, []*ast.File{syntax}
			bound, err := source.BindFixedLocal(ctx, changed, file, options)
			if !errors.Is(err, ErrProbeNeedsContext) || len(bound.Sigs) != 0 {
				t.Fatalf("same-width supplied type/parameter identity replaced actual original source: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedRoleBindingWitnessCannotDrift(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	name := pkg.Path + ".Value"
	binding := bound.Sigs[name].x86FixedLocal
	original := binding.declarations[name]
	for _, mutation := range []string{"role", "language", "missing witness"} {
		t.Run(mutation, func(t *testing.T) {
			t.Cleanup(func() { binding.declarations[name] = original })
			changed := original
			switch mutation {
			case "role":
				changed.transport = goAMD64FrameCompositeTransport
			case "language":
				changed.languageType += "changed"
			case "missing witness":
				delete(binding.declarations, name)
			}
			if mutation != "missing witness" {
				binding.declarations[name] = changed
			}
			fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
		})
	}
}

func TestGoAMD64FixedLocalTypedRoleJSONCannotSupplyPrivateWitness(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone GoAMD64FrameSource
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	if _, err := clone.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("JSON recovered an authenticated object/language token: %v", err)
	}
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	bound.Sigs, err = cloneFixedLocalSigs(bound.Sigs)
	if err != nil {
		t.Fatal(err)
	}
	fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
}
