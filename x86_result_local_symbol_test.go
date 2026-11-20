package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Go's symRefAttrs assigns ABI0 to both plain and file-local (<>) symbols.
// Scope is not a register-entry contract or permission to access other bytes.
func TestX86ABI0LocalSymbolScalarResultsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, kind := range []struct{ name, move string }{
			{"uint8", "MOVB"}, {"uint16", "MOVW"}, {"uint32", "MOVL"}, {"uint64", "MOVQ"},
		} {
			t.Run(target.triple+"/"+kind.name, func(t *testing.T) {
				word, move := 8, kind.move
				if target.arch == "386" {
					word = 4
					if kind.name == "uint64" {
						// The Go mode32 frontend has no 64-bit GP transfer.
						move = "MOVSD"
						word = 8
					}
				}
				register := "AX"
				if move == "MOVSD" {
					register = "X0"
				}
				body := fmt.Sprintf("%s x+0(FP),%s\n%s %s,ret0+%d(FP)\nRET", move, register, move, register, word)
				pkg, _, signature, ordinary := x86ResultInitializationFixture(t, target.arch,
					"func Value(x "+kind.name+") "+kind.name, body)
				source := strings.Replace(ordinary, "·Value(SB)", "·Value<>(SB)", 1)
				file := mustParseX86RawReturn(t, source)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], signature, target.arch); err != nil {
					t.Fatal("file-local scope changed the scalar result contract", err)
				}
				resolve := func(symbol string) string {
					return strings.ReplaceAll(strings.TrimPrefix(symbol, "·"), "<>", "$local")
				}
				signature.Name = "Value$local"
				options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve,
					Sigs: map[string]FuncSig{signature.Name: signature}}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						var ir string
						var err error
						switch api {
						case "text":
							ir, err = Translate(file, options)
						case "module":
							module, failure := TranslateModuleInContext(ctx, file, options)
							err = failure
							if !module.IsNil() {
								defer module.Dispose()
								ir = module.String()
							}
						case "Go":
							module, failure := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
								GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve,
								ManualSig: func(name string) (FuncSig, bool) { return signature, name == signature.Name },
							})
							err = failure
							if module != nil && !module.Module.IsNil() {
								defer module.Module.Dispose()
								ir = module.Module.String()
							}
						}
						if err != nil || ir == "" {
							t.Fatal("typed local scalar source rejected", err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					})
				}
				for _, suffix := range []string{"<ABIInternal>", "<ABI0>", "<><>", "<><ABIInternal>"} {
					changed := file.Funcs[0]
					changed.Sym = "·Value" + suffix
					if err := CheckX86ABI0ResultInitialization(changed, signature, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("local scope supplied a different entry or malformed symbol role", suffix, err)
					}
				}
			})
		}
	}
}
