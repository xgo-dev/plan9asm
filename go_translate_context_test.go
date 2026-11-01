package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoBindingInContextUsesOwnedContextAndPreservesPublicWrapper(t *testing.T) {
	pkg := mustGoPackage(t, "test/ownedcontext", "package ownedcontext\nfunc Pass(uint64) uint64\n")
	for _, target := range []struct {
		goarch, triple, source string
	}{
		{"amd64", "x86_64-unknown-linux-gnu", "TEXT ·Pass(SB),4,$0-16\nMOVQ x+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n"},
		{"arm64", "aarch64-unknown-linux-gnu", "TEXT ·Pass<ABIInternal>(SB),4,$0-16\nRET\n"},
	} {
		for _, annotate := range []bool{false, true} {
			for repeat := 0; repeat < 3; repeat++ {
				func() {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					options := GoModuleOptions{
						GOARCH: target.goarch, TargetTriple: target.triple,
						AnnotateSource: annotate,
						ResolveSym:     func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
					}
					tr, err := translateGoModuleInContext(ctx, pkg, []byte(target.source), options)
					if err != nil {
						t.Fatal(err)
					}
					defer tr.Module.Dispose() // Module must die before its context.
					if tr.Module.Context() != ctx {
						t.Fatal("Go-bound module escaped the supplied context")
					}
					if err := llvm.VerifyModule(tr.Module, llvm.ReturnStatusAction); err != nil {
						t.Fatal(err)
					}
					public, err := TranslateGoModule(pkg, []byte(target.source), options)
					if err != nil {
						t.Fatal(err)
					}
					defer public.Module.Dispose()
					if public.Module.Context() != llvm.GlobalContext() {
						t.Fatal("public Go binding wrapper changed its default context")
					}
					// Textual parsing records its unique owned temporary path as
					// module identity. Compare actual function IR, not that path.
					if public.Module.NamedFunction("Pass").String() != tr.Module.NamedFunction("Pass").String() {
						t.Fatalf("public Go binding wrapper changed the translated body:\n%s\n%s", public.Module.String(), tr.Module.String())
					}
				}()
			}
		}
	}
}

func TestGoBindingInContextErrorDoesNotAcquireContextOwnership(t *testing.T) {
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if _, err := translateGoModuleInContext(ctx, GoPackage{}, nil, GoModuleOptions{}); err == nil {
		t.Fatal("missing package accepted")
	}
	// A rejected translation cannot destroy its caller's still-live context.
	pkg := mustGoPackage(t, "test/ownedcontext", "package ownedcontext\nfunc Pass(uint64) uint64\n")
	tr, err := translateGoModuleInContext(ctx, pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\nRET\n"), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if tr.Module.Context() != ctx {
		t.Fatal("successful retry did not use the still-owned context")
	}
}
