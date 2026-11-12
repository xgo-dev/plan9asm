package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// asm7.go case 56: FREG,FREG and FCON,FREG; all FCON values encode zero.
// This table is independent of the lowering and includes both NaN policies.
var arm64ScalarCompareNames = []string{"FCMPS", "FCMPD", "FCMPES", "FCMPED"}

func arm64ScalarCompareDeadFixture() (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, op := range arm64ScalarCompareNames {
		name := fmt.Sprintf("compareDead%d", index)
		sigs[name] = arm64SM3Signature(name)
		move := "FMOVS"
		if strings.HasSuffix(op, "D") {
			move = "FMOVD"
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMSR ZR,FPCR\nMSR ZR,FPSR\n")
		fmt.Fprintf(&source, "%s (R0),F31\n%s F31,F31\n", move, op)
		// NZCV is intentionally dead: the instruction must still update FPSR.
		source.WriteString("MRS FPSR,R2\nMOVD R2,(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return source.String(), sigs
}

func TestARM64ScalarCompareDeadNativeIR(t *testing.T) {
	source, sigs := arm64ScalarCompareDeadFixture()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{`asm sideeffect "fcmp `, `asm sideeffect "fcmpe `} {
		if strings.Count(ir, operation) != 2 {
			t.Errorf("four dead comparisons must retain their actual quiet/signaling operation: missing %s", operation)
		}
	}
}

func arm64ScalarCompareActualGo(t *testing.T, source, main, goos string, runner []string) {
	t.Helper()
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":         "module compareoracle\n\ngo 1.20\n",
		"main.go":        main,
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT compare", "TEXT ·compare"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	arguments := []string{"run", "-p=1"}
	if len(runner) != 0 {
		arguments = append(arguments, "-exec="+strings.Join(runner, " "))
	}
	command := exec.CommandContext(ctx, "go", append(arguments, ".")...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || !strings.Contains(string(output), "ARM64_COMPARE_ORIGINAL_PASS") {
		t.Fatalf("actual original Go compare: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func arm64CompareGoObject(t *testing.T, source, goos string) {
	t.Helper()
	directory := t.TempDir()
	assembly, object := filepath.Join(directory, "compare.s"), filepath.Join(directory, "compare.o")
	if err := os.WriteFile(assembly, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-p", "compare", "-o", object, assembly)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(assembly, object, output, err, ctx.Err(), true, "arm64"); failure != nil {
		t.Fatalf("actual Go %s object: %v\n%s", goos, failure, output)
	}
}

func arm64ScalarCompareDeadRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, sigs := arm64ScalarCompareDeadFixture()
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range arm64ScalarCompareNames {
		fmt.Fprintf(&original, "func compareDead%d(*uint64,*uint64)\n", index)
		fmt.Fprintf(&driver, "extern void compareDead%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("func main() {\n")
	driver.WriteString("int main(void) { uint64_t input,output;\n")
	for index, op := range arm64ScalarCompareNames {
		for _, signaling := range []bool{false, true} {
			value := uint64(0x7ff8000000000001)
			if signaling {
				value = 0x7ff0000000000001
			}
			if strings.HasSuffix(op, "S") {
				value = 0x7fc00001
				if signaling {
					value = 0x7f800001
				}
			}
			want := 0
			if signaling || strings.Contains(op, "E") {
				want = 1
			}
			fmt.Fprintf(&original, "{ input:=uint64(%#x); var output uint64; compareDead%d(&input,&output); if output!=%d { panic(fmt.Sprintf(\"%s signaling=%t got %%x want %d\",output)) } }\n", value, index, want, op, signaling, want)
			fmt.Fprintf(&driver, "input=%#xULL;output=0;compareDead%d(&input,&output);if(output!=%d){fprintf(stderr,\"%s signaling=%t got %%llx want %d\\n\",(unsigned long long)output);return 1;}\n", value, index, want, op, signaling, want)
		}
	}
	original.WriteString("fmt.Println(\"ARM64_COMPARE_ORIGINAL_PASS dead NaN\")\n}\n")
	driver.WriteString("return 0;\n}\n")
	arm64ScalarCompareActualGo(t, source, original.String(), goos, runner)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR_%s/backend_O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "compare_dead", triple, variant.ir, driver.String(), runner, level)
			})
		}
	}
}

func TestARM64ScalarCompareDeadNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU matrix also runs the same original-source oracle")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64ScalarCompareDeadRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
