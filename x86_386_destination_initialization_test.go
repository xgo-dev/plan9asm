package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Go accepts an X0 store regardless of its incoming value. A bodyless Go
// declaration does not supply that value: a translated result must instead
// have all four source bytes initialized by the actual function.
func TestTranslate386VectorResultRequiresCompleteInitialization(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, fixture := range []struct {
		name, init string
		accepted   bool
	}{
		{name: "uninitialized"},
		{name: "partial-gp", init: "MOVB $1,AX\nMOVL AX,X0\n"},
		{name: "complete-gp", init: "MOVL $1,AX\nMOVL AX,X0\n", accepted: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					source := "TEXT ·value(SB),4,$0-4\n" + fixture.init + "MOVL X0,ret+0(FP)\nRET\n"
					x86LEAActualTargetGoObject(t, "386", triple, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					before := fmt.Sprintf("%#v", file.Funcs)
					pkg := x86AddSubLiteralPackage(t, "386", "func value() uint32\n")
					resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: "386", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							context := llvm.NewContext()
							defer context.Dispose()
							var ir string
							var err error
							switch api {
							case "text":
								ir, err = Translate(file, options)
							case "module":
								var module llvm.Module
								module, err = TranslateModuleInContext(context, file, options)
								if !module.IsNil() {
									defer module.Dispose()
									ir = module.String()
								}
							case "GoModule":
								var result *GoModuleTranslation
								result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
									GOARCH: "386", TargetTriple: triple, ResolveSym: resolve,
								})
								if result != nil && !result.Module.IsNil() {
									defer result.Module.Dispose()
									ir = result.Module.String()
								}
							}
							if before != fmt.Sprintf("%#v", file.Funcs) {
								t.Fatal("result initialization check changed the original source")
							}
							if !fixture.accepted {
								if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
									t.Fatalf("undefined result acquired a translation: %v\n%s", err, ir)
								}
								return
							}
							if err != nil || ir == "" {
								t.Fatalf("initialized result failed: %v", err)
							}
							compileLLVMToObject(t, llc, triple, "initialized-result.ll", "initialized-result.o", ir)
						})
					}
				})
			}
		})
	}
}
