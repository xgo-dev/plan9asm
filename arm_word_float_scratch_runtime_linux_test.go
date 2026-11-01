package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMWordFloatScratch(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	const source = `TEXT oracle(SB),4,$0-4
MOVD $3.0,F15
MOVF $7.0,F15
MOVD $1.5,F0
MOVDW F0,R1
MOVW F15,R0
MOVW R0,result+0(FP)
RET
`
	directory := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module armmovconvert\n\ngo 1.20\n",
		"main.go": `package main
import "fmt"
func oracle() uint32
func main() {
    result := oracle()
    if result != 1 { panic(fmt.Sprintf("original F15 scratch = %x, want 1", result)) }
    fmt.Println("ORIGINAL_ARM_CONVERSION_SCRATCH 1")
}

`,
		"original_arm.s": strings.ReplaceAll(source, "TEXT oracle(", "TEXT ·oracle("),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(directory, "original")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", executable, ".")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual Go conversion build: %v\n%s", err, output)
	}
	args := runtimeOracleGuestArguments(t, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, executable)
	ctx, cancel = runtimeOracleStageContext(t)
	output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, args[0], args[1:]...))
	cancel()
	if err != nil || string(output) != "ORIGINAL_ARM_CONVERSION_SCRATCH 1\n" {
		t.Fatalf("actual unchanged Go F15 effect: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))

	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"oracle": {
			Name: "oracle", Ret: I32,
			Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const driver = `#include <stdint.h>
#include <stdio.h>
extern uint32_t oracle(void);
int main(void) {
    uint32_t value = oracle();
    if (value != 1) {
        fprintf(stderr,"LLVM F15 scratch = %x, want 1\n",value);
        return 1;
    }
    return 0;
}
`
	for _, level := range []int{0, 2} {
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
			"arm_conversion_scratch", "armv7-unknown-linux-gnueabihf", ir, driver,
			[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
	}
}

func TestCrossLinuxRuntimeMatrixARMFloatRegisterEffects(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	cases := append(armFloatConversionEffectCases(), armFloatHalfWriteEffectCases()...)
	source, sigs := armFloatEffectSource(cases)
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for i := range cases {
		fmt.Fprintf(&original, "func effect%d(input,output *[4]uint64)\n", i)
		fmt.Fprintf(&driver, "extern void effect%d(uint64_t*,uint64_t*);\n", i)
	}
	original.WriteString("func main() {\n")
	driver.WriteString("int main(void) { unsigned failures = 0;\n")
	for i, fixture := range cases {
		fmt.Fprintf(&original, "{ input := [4]uint64{%#x,%#x,%#x,%#x}; ",
			fixture.input[0], fixture.input[1], fixture.input[2], fixture.input[3])
		fmt.Fprintf(&original, "output := [4]uint64{0,0,0,0xabcdef0100000000}; effect%d(&input,&output); ", i)
		fmt.Fprintf(&original, "want := [4]uint64{%#x,%#x,%#x,%#x}; ",
			fixture.want[0], fixture.want[1], fixture.want[2], fixture.want[3])
		fmt.Fprintf(&original, "if output != want { panic(fmt.Sprintf(%q,output,want)) } }\n",
			fmt.Sprintf("case %d %s: got %%x want %%x", i, fixture.instruction))
		fmt.Fprintf(&driver, "{ uint64_t input[4]={%#xULL,%#xULL,%#xULL,%#xULL}; ",
			fixture.input[0], fixture.input[1], fixture.input[2], fixture.input[3])
		fmt.Fprintf(&driver, "uint64_t output[4]={0,0,0,0xabcdef0100000000ULL}; effect%d(input,output); ", i)
		fmt.Fprintf(&driver, "uint64_t want[4]={%#xULL,%#xULL,%#xULL,%#xULL}; ",
			fixture.want[0], fixture.want[1], fixture.want[2], fixture.want[3])
		fmt.Fprintf(&driver, `for (unsigned j=0;j<4;j++) { if (output[j]!=want[j]) {
if (failures<16) fprintf(stderr,"case %d %s word %%u: got %%llx want %%llx\n",j,(unsigned long long)output[j],(unsigned long long)want[j]); failures++; } } }
`, i, fixture.instruction)
	}
	fmt.Fprintf(&original, "fmt.Println(%q)\n}\n", fmt.Sprintf("ORIGINAL_ARM_FLOAT_EFFECTS %d", len(cases)))
	fmt.Fprintf(&driver, "printf(\"LLVM_ARM_FLOAT_EFFECTS %d failures=%%u\\n\",failures); return failures != 0; }\n", len(cases))

	directory := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":         "module armfloateffects\n\ngo 1.20\n",
		"main.go":        original.String(),
		"original_arm.s": strings.ReplaceAll(source, "TEXT effect", "TEXT ·effect"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(directory, "original")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", executable, ".")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual Go full-register effect build: %v\n%s", err, output)
	}
	args := runtimeOracleGuestArguments(t, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, executable)
	ctx, cancel = runtimeOracleStageContext(t)
	output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, args[0], args[1:]...))
	cancel()
	want := fmt.Sprintf("ORIGINAL_ARM_FLOAT_EFFECTS %d\n", len(cases))
	if err != nil || string(output) != want {
		t.Fatalf("actual Go full-register effects: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))

	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"unoptimized", ir}, {"optimized", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
					"arm_float_effects", "armv7-unknown-linux-gnueabihf", variant.ir, driver.String(),
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
				t.Logf("LLVM22 %s O%d: %d full-register fixtures", variant.name, level, len(cases))
			})
		}
	}
}
