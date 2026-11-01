package plan9asm

// The explicit public context entry is separate from the retained legacy
// wrapper/private-context regressions in go_translate_context_test.go.

import (
	"errors"
	"testing"

	"github.com/xgo-dev/llvm"
)

const goModuleOwnedContextSource = "TEXT ·Value(SB),4,$0-4\nMOVL $7,ret+0(FP)\nRET\n"

func goModuleOwnedContextOptions(pkg GoPackage) GoModuleOptions {
	return GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: testResolveSym(pkg.Path)}
}

func goModuleRequireOwnedContext(t *testing.T, ctx llvm.Context, result *GoModuleTranslation, err error) {
	t.Helper()
	if err != nil || result == nil || result.Module.IsNil() {
		t.Fatalf("complete caller-context GoModule translation failed: %v", err)
	}
	if result.Module.Context() != ctx {
		t.Fatal("GoModule ignored the explicit caller-owned LLVM context")
	}
	if err := llvm.VerifyModule(result.Module, llvm.ReturnStatusAction); err != nil {
		t.Fatal("caller-context module does not verify", err)
	}
	if len(result.Functions) != 1 {
		t.Fatal("complete original source function inventory changed")
	}
	function := result.Module.NamedFunction(result.Functions[0].ResolvedSymbol)
	if function.IsNil() || function.FirstBasicBlock().IsNil() || function.Type().Context() != ctx {
		t.Fatal("translated body/type does not belong to the explicit context")
	}
}

func TestTranslateGoModuleInContextIdentity(t *testing.T) {
	pkg := mustGoPackage(t, "example.com/contextowner", "package contextowner\nfunc Value() uint32\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	result, err := TranslateGoModuleInContext(ctx, pkg, []byte(goModuleOwnedContextSource), goModuleOwnedContextOptions(pkg))
	if result != nil && !result.Module.IsNil() {
		defer result.Module.Dispose() // The returned module precedes its owner's context.
	}
	goModuleRequireOwnedContext(t, ctx, result, err)
}

func TestTranslateGoModuleInContextIndependentLifetimes(t *testing.T) {
	pkg := mustGoPackage(t, "example.com/contextowner", "package contextowner\nfunc Value() uint32\n")
	second := llvm.NewContext()
	defer second.Dispose()
	retained, err := TranslateGoModuleInContext(second, pkg, []byte(goModuleOwnedContextSource), goModuleOwnedContextOptions(pkg))
	if retained != nil && !retained.Module.IsNil() {
		defer retained.Module.Dispose()
	}
	goModuleRequireOwnedContext(t, second, retained, err)
	func() {
		first := llvm.NewContext()
		defer first.Dispose()
		temporary, err := TranslateGoModuleInContext(first, pkg, []byte(goModuleOwnedContextSource), goModuleOwnedContextOptions(pkg))
		if temporary != nil && !temporary.Module.IsNil() {
			defer temporary.Module.Dispose()
		}
		goModuleRequireOwnedContext(t, first, temporary, err)
		if first == second || temporary.Module.Context() == retained.Module.Context() ||
			temporary.Module.NamedFunction(temporary.Functions[0].ResolvedSymbol).Type() ==
				retained.Module.NamedFunction(retained.Functions[0].ResolvedSymbol).Type() {
			t.Fatal("independent requests shared LLVM context/type ownership")
		}
	}()
	// The first module and its complete context have actually been destroyed.
	// The second caller's original module must remain valid and usable.
	goModuleRequireOwnedContext(t, second, retained, nil)
	again, err := TranslateGoModuleInContext(second, pkg, []byte(goModuleOwnedContextSource), goModuleOwnedContextOptions(pkg))
	if again != nil && !again.Module.IsNil() {
		defer again.Module.Dispose()
	}
	goModuleRequireOwnedContext(t, second, again, err)
}

func TestTranslateGoModuleInContextErrorOwnership(t *testing.T) {
	pkg := mustGoPackage(t, "example.com/contextowner", "package contextowner\nfunc Value() uint32\n")
	for _, failure := range []string{"missing-architecture", "uninitialized-result", "unknown-instruction"} {
		t.Run(failure, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			// This separate valid module belongs to the caller before the API
			// is invoked. Failure must not dispose the surrounding context.
			sentinel := ctx.NewModule("caller-owned-before-error")
			defer sentinel.Dispose()
			builder := ctx.NewBuilder()
			function := llvm.AddFunction(sentinel, "sentinel", llvm.FunctionType(ctx.Int32Type(), nil, false))
			builder.SetInsertPointAtEnd(ctx.AddBasicBlock(function, "entry"))
			builder.CreateRet(llvm.ConstInt(ctx.Int32Type(), 19, false))
			builder.Dispose()
			options, source := goModuleOwnedContextOptions(pkg), goModuleOwnedContextSource
			switch failure {
			case "missing-architecture":
				options.GOARCH = ""
			case "uninitialized-result":
				source = "TEXT ·Value(SB),4,$0-4\nMOVL AX,ret+0(FP)\nRET\n"
			case "unknown-instruction":
				source = "TEXT ·Value(SB),4,$0-4\nUNKNOWN\nRET\n"
			}
			result, err := TranslateGoModuleInContext(ctx, pkg, []byte(source), options)
			if result != nil && !result.Module.IsNil() {
				defer result.Module.Dispose()
			}
			if err == nil || result != nil {
				t.Fatal("failed GoModule request published a result", err)
			}
			if failure == "uninitialized-result" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("failure lost its original missing-input classification", err)
			}
			if sentinel.Context() != ctx {
				t.Fatal("failed request changed the caller's existing module ownership")
			}
			if err := llvm.VerifyModule(sentinel, llvm.ReturnStatusAction); err != nil {
				t.Fatal("failed request invalidated the caller's existing module", err)
			}
			valid, err := TranslateGoModuleInContext(ctx, pkg, []byte(goModuleOwnedContextSource), goModuleOwnedContextOptions(pkg))
			if valid != nil && !valid.Module.IsNil() {
				defer valid.Module.Dispose()
			}
			goModuleRequireOwnedContext(t, ctx, valid, err)
		})
	}
}
