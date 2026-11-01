package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This complete original fixture is rejected by Go itself, not a successful
// object or an invalid individual opcode. Require its precise ordinary exit
// and diagnostic; infrastructure failures must never stand in for rejection.
func x86OriginalUnbalancedStackGoRejection(t *testing.T, source, triple string) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "stack.s"), filepath.Join(dir, "stack.o")
	original := "#include \"textflag.h\"\n" + source
	if err := os.WriteFile(input, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	goos := "linux"
	if strings.Contains(triple, "windows") {
		goos = "windows"
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-I", filepath.Join(runtime.GOROOT(), "pkg", "include"), "-o", output, input)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=386", "GOTOOLCHAIN=local")
	diagnostic, err := runtimeOracleCombinedOutput(ctx, command)
	exit, ordinary := err.(*exec.ExitError)
	if ctx.Err() != nil || !ordinary || exit.ProcessState == nil || !exit.ProcessState.Exited() ||
		exit.ExitCode() != 1 || string(diagnostic) != "asm: stack: unbalanced PUSH/POP\nasm: assembly failed\n" {
		t.Fatalf("unknown original stack observation: %v; context=%v\n%s", err, ctx.Err(), diagnostic)
	}
	if data, err := os.ReadFile(input); err != nil || string(data) != original {
		t.Fatal("original stack rejection source changed", err)
	}
}

// Retain every instruction, original TEXT and original register return in the
// old stack fixtures. These emitter-only objects establish no public source
// contract for an entry POP or a stack pointer assigned from an unknown AX.
func x86OriginalStackFormatObject(t *testing.T, function Func, result LLVMType, arch, triple string) string {
	t.Helper()
	if function.FrameSize != 0 || function.ArgSize != 0 || len(function.Instrs) < 2 {
		t.Fatal("original stack format inventory changed")
	}
	sig := FuncSig{Name: "StackFormat", Ret: result}
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\ndefine %s @StackFormat() {\n", triple, result)
	consumer := newX86Ctx(&ir, function, sig, func(name string) string { return name }, nil, arch, triple, false)
	if err := consumer.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	if err := consumer.lowerBlocks(); err != nil {
		t.Fatal("complete original stack format not emitted", err)
	}
	ir.WriteString("}\n")
	return ir.String()
}

// Independent, initialized counterparts use real Go arguments/results and a
// balanced private stack. W writes preserve high register bytes; L/Q writes
// restore the complete source word. No original failing source is rewritten.
func x86StackFixtureValueProgram(arch string) (string, string, string) {
	word, suffix, register := 8, "Q", "R12"
	if arch == "386" {
		word, suffix, register = 4, "L", "CX"
	}
	var source, declarations, driver strings.Builder
	fmt.Fprintf(&driver, "#include <stdint.h>\n#include <stdio.h>\ntypedef uint%d_t word;\n", word*8)
	for _, width := range []string{"W", suffix} {
		name := "PrivateValue" + width
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s value+0(FP),%s\n"+
			"PUSH%s %s\nMOVW $0,%s\nPOP%s %s\nMOV%s %s,AX\nMOV%s AX,ret+%d(FP)\nRET\n",
			name, 2*word, suffix, register, width, register, register, width, register, suffix, register, suffix, word)
		fmt.Fprintf(&declarations, "func %s(value uint%d) uint%d\n", name, word*8, word*8)
		fmt.Fprintf(&driver, "extern word %s(word);\n", name)
	}
	driver.WriteString("int main(void) {\n" +
		"    const word values[] = {0, 1, 65535, 65536, (word)UINT64_MAX,\n" +
		"        (word)UINT64_C(0x1122334455667788), (word)UINT64_C(0x8000000080008000)};\n" +
		"    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); i++) {\n")
	for _, width := range []string{"W", suffix} {
		fmt.Fprintf(&driver, "        if (PrivateValue%s(values[i]) != values[i]) {\n"+
			"            fprintf(stderr, \"private-stack %s row=%%u\\n\", i);\n            return 1;\n        }\n", width, width)
	}
	driver.WriteString("    }\n    return 0;\n}\n")
	return source.String(), declarations.String(), driver.String()
}

func TestX86StackFixtureInitializedPrivateValuesFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _ := x86StackFixtureValueProgram(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized private stack lost its declared inputs/result", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86StackFixtureInitializedPrivateValuesPortableRuntime(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, arch := range []string{"386", "amd64"} {
		source, declarations, driver := x86StackFixtureValueProgram(arch)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []int{0, 2} {
						compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "private-stack-fixture", triple, text, driver, nil, level)
					}
				}
			})
		}
	}
}
