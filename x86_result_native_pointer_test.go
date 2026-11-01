package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86ABI0ResultInitializationDeclaredPointerReadsRemainUnproved(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		for _, fixture := range []struct {
			name, declaration, load, store string
		}{
			{"integer", "func Value(x *uint32) uint32", "MOVL (AX),BX", "MOVL BX"},
			{"floating", "func Value(x *float32) float32", "MOVSS (AX),X0", "MOVSS X0"},
		} {
			t.Run(target.triple+"/"+fixture.name, func(t *testing.T) {
				word, pointerMove := 8, "MOVQ"
				if target.arch == "386" {
					word, pointerMove = 4, "MOVL"
				}
				body := fmt.Sprintf("MOVL $0,ret0+%d(FP)\n%s x+0(FP),AX\n%s\n%s,ret0+%d(FP)\nRET",
					word, pointerMove, fixture.load, fixture.store, word)
				pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, fixture.declaration, body)
				receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				t.Logf("ORIGINAL_DECLARED_POINTER_OBJECT: %+v", receipt)
				resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
				options := Options{Goarch: target.arch, TargetTriple: target.triple,
					ResolveSym: resolve, Sigs: map[string]FuncSig{"Value": sig}}
				text, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, text, "text")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, module.String(), "module")
				typed, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve,
				})
				if typed != nil && !typed.Module.IsNil() {
					defer typed.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, typed.Module.String(), "typed-go")
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("original and LLVM objects do not prove initialized pointee bytes: %v", err)
				}
			})
		}
	}
}
