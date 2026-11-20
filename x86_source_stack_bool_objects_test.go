package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86PhysicalBoolObjectSource(arch string) (string, string, string) {
	word, suffix := int64(8), "Q"
	if arch == "386" {
		word, suffix = 4, "L"
	}
	var source, declarations strings.Builder
	for index, body := range []string{
		"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
		"MOVB $0,@RESULT(SP)\nBYTE $0xc3",
		"MOVB $1,@RESULT(SP)\nBYTE $0xc3",
		"MOVB @WORD(SP),AH\nMOVB AH,BL\nMOVB BL,@RESULT(SP)\nBYTE $0xc3",
		"MOVB @WORD(SP),AX\nPUSHW AX\nMOVW $0,AX\nPOPW AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
		"MOVB @WORD(SP),AX\nPUSH" + suffix + " AX\nMOV" + suffix + " $0,AX\nPOP" + suffix + " AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
		"MOVB $3,@RESULT(SP)\nMOVB @RESULT(SP),AX\nANDB $1,AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
		"MOVB $2,@RESULT(SP)\nMOVB @RESULT(SP),AX\nSHRB $1,AX\nANDB $1,AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3",
		"MOVB x+0(FP),AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3",
		"MOVB $1,ret+@WORD(FP)\nBYTE $0xc3",
		"MOVB $2,ret+@WORD(FP)\nMOVB ret+@WORD(FP),AX\nSHRB $1,AX\nANDB $1,AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3",
	} {
		name := fmt.Sprintf("PhysicalBool%d", index)
		text, _, _ := x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB", body)
		source.WriteString(strings.ReplaceAll(text, "·Value", "·"+name))
		fmt.Fprintf(&declarations, "func %s(x bool) bool\n", name)
	}
	negative := strings.Replace(source.String(), fmt.Sprintf("MOVB $1,%d(SP)", 2*word), fmt.Sprintf("MOVB $3,%d(SP)", 2*word), 1)
	return source.String(), declarations.String(), negative
}

func x86PhysicalBoolObjectAPI(t *testing.T, source, declarations, arch, triple, api string) (string, error) {
	t.Helper()
	if !strings.HasPrefix(api, "default-") {
		return x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
	}
	// Derive the actual declaration under the known AMD64 source mode, then
	// independently exercise the public Options default without editing it.
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declarations)
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	if api == "default-text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

func TestX86PhysicalSourceStackBoolFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("physical source-stack bool objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, negative := x86PhysicalBoolObjectSource(target.arch)
			negativeNamed := strings.Replace(source, fmt.Sprintf("MOVB $1,ret+%d(FP)", goWordSize(target.arch)), fmt.Sprintf("MOVB $3,ret+%d(FP)", goWordSize(target.arch)), 1)
			if strings.Count(source, "TEXT ·") != 11 || source == negative || source == negativeNamed {
				t.Fatal("complete physical bool source inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, negative)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, negativeNamed)
			completeRuntime, _ := x86SourceStackRuntimeSource(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, completeRuntime)
			apis := []string{"text", "module", "Go"}
			if target.arch == "amd64" {
				apis = append(apis, "default-text", "default-module")
			}
			for _, api := range apis {
				t.Run(api, func(t *testing.T) {
					ir, err := x86PhysicalBoolObjectAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete original physical bool source rejected", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
					for _, badSource := range []string{negative, negativeNamed} {
						if bad, err := x86PhysicalBoolObjectAPI(t, badSource, declarations, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || bad != "" {
							t.Fatal("noncanonical complete original physical/named bool source published LLVM", err)
						}
					}
				})
			}
		})
	}
}
