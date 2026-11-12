package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These functions return a literal; their opaque addresses are never read or
// written. Object acceptance must not silently replace initialization proofs.
func TestX86ABI0ResultIncomingPointerIdentityFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		word := 8
		if target.arch == "386" {
			word = 4
		}
		for name, body := range x86ResultIncomingPointerIdentityBodies(target.arch) {
			t.Run(target.triple+"/"+name, func(t *testing.T) {
				body += fmt.Sprintf("MOVL $42,ret0+%d(FP)\nRET", word)
				pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch,
					"func Value(x *[8]uint32) uint32", body)
				receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				t.Logf("ORIGINAL_POINTER_IDENTITY_OBJECT: %+v", receipt)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal(err)
				}
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
			})
		}
	}
}
