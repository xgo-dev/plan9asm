package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Only ArchAMD64's text/module Options have the documented historical amd64
// default. The Go-aware API deliberately requires an explicit actual GOARCH.
func x86IntegerFPDefaultAPI(t *testing.T, source, declaration, triple, api string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "defaultfp", "package defaultfp\n"+declaration)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	if api == "text" {
		return Translate(file, options)
	}
	context := llvm.NewContext()
	defer context.Dispose()
	if api == "Go-blank" {
		module, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{TargetTriple: triple, ResolveSym: resolve})
		if module != nil && !module.Module.IsNil() {
			defer module.Module.Dispose()
			return module.Module.String(), err
		}
		return "", err
	}
	if api != "module" {
		t.Fatal("unknown default FP API", api)
	}
	module, err := TranslateModuleInContext(context, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

func TestX86OrdinaryIntegerFPDefaultArchitectureCannotBypassProof(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Empty Options.Goarch is AMD64, never a mode32 inference.
		}
		for _, width := range []int{1, 2, 4, 8} {
			move := map[int]string{1: "MOVB", 2: "MOVW", 4: "MOVL", 8: "MOVQ"}[width]
			for _, known := range []bool{false, true} {
				body := move + " AX,ret+0(FP)\nRET\n"
				if known {
					body = move + " $9,AX\n" + body
				}
				for _, api := range []string{"text", "module"} {
					t.Run(fmt.Sprintf("%s/%d/known=%t/%s", target.triple, width, known, api), func(t *testing.T) {
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", width, body)
						ir, err := x86IntegerFPDefaultAPI(t, source, fmt.Sprintf("func Value() uint%d", 8*width), target.triple, api)
						if known {
							if err != nil || ir == "" {
								t.Fatal("documented AMD64 default rejected initialized result", err)
							}
							x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{9})
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("default direct path bypassed whole-source initialization: output=%t, error=%v", ir != "", err)
						}
					})
				}
			}
		}
		for _, api := range []string{"text", "module"} {
			t.Run(target.triple+"/readonly-I1/"+api, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-9\nMOVB x+0(FP),AX\nMOVB AX,ret+8(FP)\nRET\n"
				ir, err := x86IntegerFPDefaultAPI(t, source, "func Value(x bool) uint8", target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("default projection changed the independent logical I1 input route", err)
				}
				x86ScalarFPNamedConstantResult(t, ir+"define i8 @Probe() {\n %v = call i8 @Value(i1 true)\n ret i8 %v\n}\n", "Probe", []uint64{1})
			})
		}
	}
	t.Run("Go-blank-keeps-explicit-selection-boundary", func(t *testing.T) {
		ir, err := x86IntegerFPDefaultAPI(t, "TEXT ·Value(SB),4,$0-4\nMOVL $9,ret+0(FP)\nRET\n", "func Value() uint32", "x86_64-unknown-linux-gnu", "Go-blank")
		if err == nil || !strings.Contains(err.Error(), "empty GOARCH") || ir != "" {
			t.Fatalf("blank Go selection acquired an implicit source/ABI role: output=%t, error=%v", ir != "", err)
		}
	})
}
