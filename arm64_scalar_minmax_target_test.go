package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64MinMaxTargetAPI(t *testing.T, api, source, triple string) (bool, error) {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return false, err
	}
	options := Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"comparison": {Name: "comparison", Ret: Void}},
	}
	switch api {
	case "Translate":
		ir, err := Translate(file, options)
		return ir != "", err
	case "TranslateModule":
		module, err := TranslateModule(file, options)
		present := !module.IsNil()
		if present {
			module.Dispose()
		}
		return present, err
	case "TranslateModuleInContext":
		context := llvm.NewContext()
		defer context.Dispose()
		module, err := TranslateModuleInContext(context, file, options)
		present := !module.IsNil()
		if present {
			module.Dispose()
		}
		return present, err
	case "TranslateGoModule":
		pkg := mustGoPackage(t, "comparison", "package comparison\nfunc comparison()\n")
		bound, err := TranslateGoModule(pkg,
			[]byte(strings.ReplaceAll(source, "TEXT comparison", "TEXT ·comparison")),
			GoModuleOptions{GOOS: "linux", GOARCH: "arm64", TargetTriple: triple})
		if bound != nil {
			bound.Module.Dispose()
		}
		return bound != nil, err
	default:
		t.Fatal("unknown min/max API", api)
		return false, nil
	}
}

func TestARM64ScalarMinMaxUnrelatedRawSyntaxPriority(t *testing.T) {
	for _, row := range arm64MinMaxCases() {
		native := row.instruction(0, 1, 2, false)
		for _, invalid := range []string{"WORD $0xffffffff", "WORD $1.5", "WORD R0"} {
			for _, body := range []string{
				invalid + "\n" + native,
				native + "\n" + invalid,
				native + "\nRET\n" + invalid,
				"RET\n" + invalid + "\n" + native,
			} {
				for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown", "aarch64-unknown-linux-gnu"} {
					for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext", "TranslateGoModule"} {
						present, err := arm64MinMaxTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\n"+body+"\nRET\n", triple)
						if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
							t.Errorf("%s %s %s source=%q: output=%t err=%v", row.name, api, triple, body, present, err)
						}
					}
				}
			}
		}
	}
}
