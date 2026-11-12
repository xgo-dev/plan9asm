package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Complete independent source/type inventories exercise cost selection, not a
// cropped module or an exception for a particular library or function name.
func x86ABI0CallSelectionFixture(kind string, fillers int) (string, string) {
	var source, declarations strings.Builder
	switch kind {
	case "integer":
		source.WriteString("TEXT ·caller(SB),4,$16-4\nCALL ·callee(SB)\nMOVL 0(SP),AX\nMOVL AX,ret+0(FP)\nRET\nTEXT ·callee(SB),4,$0-4\nMOVL $7,ret+0(FP)\nRET\n")
		declarations.WriteString("func caller() uint32\nfunc callee() uint32\n")
	case "void":
		source.WriteString("TEXT ·caller(SB),4,$16-0\nCALL ·callee(SB)\nRET\nTEXT ·callee(SB),4,$0-0\nRET\n")
		declarations.WriteString("func caller()\nfunc callee()\n")
	case "opaque-transport":
		source.WriteString("TEXT ·caller(SB),4,$16-4\nCALL ·callee(SB)\nRET\nTEXT ·callee(SB),4,$0-0\nRET\n")
		declarations.WriteString("func caller(p *byte)\nfunc callee()\n")
	case "bool-input-integer-result":
		source.WriteString("TEXT ·caller(SB),4,$16-8\nCALL ·callee(SB)\nMOVL $7,ret+4(FP)\nRET\nTEXT ·callee(SB),4,$0-0\nRET\n")
		declarations.WriteString("func caller(x bool) uint32\nfunc callee()\n")
	case "bool":
		source.WriteString(x86ABI0BoolCallAssembly(x86ABI0BoolCallBody, x86ABI0BoolCallLeaf))
		declarations.WriteString(x86ABI0BoolCallDeclarations)
	default:
		panic("unknown fixture kind")
	}
	// An unrelated genuine bool return is not a bool CALL caller.
	source.WriteString("TEXT ·unrelated(SB),4,$0-1\nMOVB $1,ret+0(FP)\nRET\n")
	declarations.WriteString("func unrelated() bool\n")
	for index := 0; index < fillers; index++ {
		fmt.Fprintf(&source, "TEXT ·unused%d(SB),4,$0-0\nRET\n", index)
		fmt.Fprintf(&declarations, "func unused%d()\n", index)
	}
	return source.String(), declarations.String()
}

func TestX86ABI0Mode32CanonicalBoolCallSelectionKeepsNonboolGoFilter(t *testing.T) {
	source, declarations := x86ABI0CallSelectionFixture("integer", 0)
	declarations = strings.Replace(declarations, "func unrelated() bool\n", "", 1)
	pkg := mustGoPackage(t, "callselect", "package callselect\n"+declarations)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "386", TargetTriple: "i386-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
		KeepFunc:   func(original, _ string) bool { return original != "·unrelated" },
	})
	if module != nil && !module.Module.IsNil() {
		defer module.Module.Dispose()
	}
	if err != nil || module == nil {
		t.Fatal("unselected non-caller acquired a bool source/declaration requirement", err)
	}
}

func TestX86ABI0Mode32CanonicalBoolCallSelectionKeepsNonboolWholeFiles(t *testing.T) {
	for _, kind := range []string{"integer", "void", "opaque-transport", "bool-input-integer-result"} {
		for _, fillers := range []int{0, 254} {
			source, declarations := x86ABI0CallSelectionFixture(kind, fillers)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/texts%d/%s", kind, fillers+3, api), func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", "i386-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("nonbool CALL acquired unrelated bool source/transport limits", len(ir), err)
					}
				})
			}
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolCallSelectionRetainsTrueBoolLimit(t *testing.T) {
	for _, fillers := range []int{0, 254} {
		source, declarations := x86ABI0CallSelectionFixture("bool", fillers)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("texts%d/%s", fillers+3, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", "i386-unknown-linux-gnu", api)
				if fillers == 0 && (err != nil || ir == "") || fillers != 0 && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("actual I1 CALL lost its complete original source bound", fillers+3, len(ir), err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolCallSelectionRejectsChangingQuery(t *testing.T) {
	for _, kind := range []string{"unknown-declaration", "one-shot-resolution", "changed-declaration", "changed-original-call"} {
		t.Run(kind, func(t *testing.T) {
			file, options := x86ABI0BoolCallParsed(t)
			if kind == "unknown-declaration" {
				delete(options.Sigs, "caller")
			}
			calls := 0
			options.ResolveSym = func(symbol string) string {
				calls++
				if calls == 1 {
					switch kind {
					case "one-shot-resolution":
						return "outside"
					case "changed-declaration":
						sig := options.Sigs["caller"]
						sig.Ret = I32
						options.Sigs["caller"] = sig
					case "changed-original-call":
						file.Funcs[0].Instrs[3].Op = "NOP"
					}
				}
				return strings.TrimPrefix(symbol, "·")
			}
			plan, err := prepareX86ABI0BoolCalls(file, options)
			if calls == 0 || plan != nil || kind == "unknown-declaration" && err != nil ||
				kind != "unknown-declaration" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unknown or changed cost query created a bool source permission", calls, plan != nil, err)
			}
		})
	}
}
