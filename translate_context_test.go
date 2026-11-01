package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestTranslateModuleInContextKeepsModuleInCallerContext(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·f(SB),NOSPLIT,$0-0\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}

	for _, annotate := range []bool{false, true} {
		for i := 0; i < 3; i++ {
			ctx := llvm.NewContext()
			mod, err := TranslateModuleInContext(ctx, file, Options{
				Goarch:         "amd64",
				TargetTriple:   "x86_64-unknown-linux-gnu",
				AnnotateSource: annotate,
				ResolveSym:     func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs:           map[string]FuncSig{"f": {Name: "f", Ret: Void}},
			})
			if err != nil {
				ctx.Dispose()
				t.Fatal(err)
			}
			if mod.Context() != ctx {
				mod.Dispose()
				ctx.Dispose()
				t.Fatal("module escaped its caller-owned LLVM context")
			}
			if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
				mod.Dispose()
				ctx.Dispose()
				t.Fatal(err)
			}
			mod.Dispose()
			ctx.Dispose()
		}
	}
}
