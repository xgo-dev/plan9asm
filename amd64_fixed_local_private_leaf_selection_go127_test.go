//go:build go1.27

package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoAMD64FixedLocalPrivateLeafSelectionBoundary(t *testing.T) {
	for _, sibling := range []struct {
		name, value string
		valid       bool
	}{
		{"defined_sibling", "$17", true},
		{"undefined_sibling", "R8", false},
	} {
		t.Run(sibling.name, func(t *testing.T) {
			assembly := fixedLocalPrivateLeafSource("CALL leaf<>(SB)", "MOVQ (BP),AX") +
				"TEXT ·Other(SB),4,$0-8\n MOVQ " + sibling.value + ",AX\n MOVQ AX,ret+0(FP)\n RET\n"
			x86InsertExtractGoListing(t, "amd64", assembly)
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly,
				"func Value(a uint64) uint64\nfunc Other() uint64")
			other, err := DeriveGoFuncABI0Signature(pkg.Path+".Other",
				pkg.Types.Scope().Lookup("Other").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			options.Sigs[other.Name] = other
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("complete original sibling observation must succeed", err)
			}
			defer owner.Close()
			expanded, err := owner.preprocess(request.AssemblyFile, []byte(assembly))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			if len(file.Funcs) != 3 || len(owner.functions) != 3 {
				t.Fatal("complete original root, leaf and sibling inventory changed")
			}
			bound, err := owner.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("sibling semantics must reach the public translation consumer", err)
			}
			for _, selection := range []string{"complete", "keep_all", "omit_sibling"} {
				t.Run(selection, func(t *testing.T) {
					queries := make(map[string]int)
					opt := GoModuleOptions{
						GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple, ResolveSym: bound.ResolveSym,
						ManualSig: func(name string) (FuncSig, bool) {
							sig, found := bound.Sigs[name]
							return sig, found
						},
					}
					if selection != "complete" {
						opt.KeepFunc = func(symbol, name string) bool {
							queries[symbol]++
							return selection == "keep_all" || name != other.Name
						}
					}
					context := llvm.NewContext()
					defer context.Dispose()
					result, err := translateGoModuleInContext(context, pkg, []byte(expanded), opt)
					if result != nil && !result.Module.IsNil() {
						defer result.Module.Dispose()
					}
					if selection != "complete" {
						if len(queries) != len(file.Funcs) {
							t.Fatal("KeepFunc did not observe the complete original inventory", queries)
						}
						for _, fn := range file.Funcs {
							if queries[fn.Sym] != 1 {
								t.Fatal("KeepFunc omitted or repeated an original TEXT", fn.Sym, queries)
							}
						}
					}
					if selection == "omit_sibling" {
						// This route currently rejects even valid partial selection.
						// It does not claim semantic auditing before filtering.
						if result != nil || !errors.Is(err, ErrProbeNeedsContext) ||
							!strings.Contains(err.Error(), "fixed local consumer original/normalized source changed") {
							t.Fatal("cropping a sibling reused a complete-source frame binding", err)
						}
						return
					}
					if !sibling.valid {
						if result != nil || !errors.Is(err, ErrProbeNeedsContext) ||
							!strings.Contains(err.Error(), "result initialization") ||
							!strings.Contains(err.Error(), "MOVQ R8,AX") {
							t.Fatal("complete source hid an undefined ordinary sibling result", err)
						}
						return
					}
					if err != nil || result == nil || result.Module.IsNil() {
						t.Fatal("complete valid root, leaf and sibling source was rejected", err)
					}
					ir := result.Module.String()
					if strings.Count(ir, "define ") != 2 || !strings.Contains(ir, other.Name) {
						t.Fatal("complete valid source omitted its ordinary sibling", ir)
					}
					fixedLocalPrivateLeafObjects(t, ir)
				})
			}
		})
	}
}
