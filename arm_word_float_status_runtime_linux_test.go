package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runARMConversionGoOracle(t *testing.T, source, main, marker string) {
	t.Helper()
	output := armConversionGoObservations(t, source, main)
	if string(output) != marker+"\n" {
		t.Fatalf("original Go conversion observations:\n%s", output)
	}
	t.Log(marker)
}

func armConversionGoObservations(t *testing.T, source, main string) []byte {
	t.Helper()
	directory := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module armconversionoracle\n\ngo 1.20\n", "main.go": main,
		"oracle_arm.s": strings.ReplaceAll(source, "TEXT ", "TEXT ·"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
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
		t.Fatalf("original Go conversion build: %v\n%s", err, output)
	}
	args := runtimeOracleGuestArguments(t, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, executable)
	ctx, cancel = runtimeOracleStageContext(t)
	output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, args[0], args[1:]...))
	cancel()
	if err != nil {
		t.Fatalf("original Go conversion observations: %v\n%s", err, output)
	}
	return output
}

func TestCrossLinuxRuntimeMatrixARMWordFloatNativeStatusConstants(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	source, sigs := armConversionStatusSource()
	cases := armConversionStatusCases()
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for _, fixture := range cases {
		fmt.Fprintf(&original, "func %s(out *[4]uint32)\n", fixture.name)
		fmt.Fprintf(&driver, "extern void %s(uint32_t*);\n", fixture.name)
	}
	original.WriteString("func main() {\n")
	driver.WriteString("int main(void) { unsigned failures = 0;\n")
	for _, fixture := range cases {
		fmt.Fprintf(&original, "{ out := [4]uint32{0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0x12345678}\n%s(&out)\n", fixture.name)
		fmt.Fprintf(&original, "want := [4]uint32{%#x,%#x,%#x,0x12345678}\n", uint32(fixture.value), uint32(fixture.value>>32), fixture.status)
		fmt.Fprintf(&original, "if out != want { panic(fmt.Sprintf(%q,out,want)) } }\n", fixture.name+": got %x want %x")
		fmt.Fprintf(&driver, "{ uint32_t out[4]={0xa5a5a5a5,0xa5a5a5a5,0xa5a5a5a5,0x12345678};\n%s(out);\n", fixture.name)
		fmt.Fprintf(&driver, "uint32_t want[4]={%#x,%#x,%#x,0x12345678};\n", uint32(fixture.value), uint32(fixture.value>>32), fixture.status)
		fmt.Fprintf(&driver, `for(unsigned i=0;i<4;i++) { if(out[i]!=want[i]) {
fprintf(stderr,"%s word %%u: got %%08x want %%08x\n",i,out[i],want[i]); failures++; } } }
`, fixture.name)
	}
	marker := fmt.Sprintf("ORIGINAL_ARM_CONVERSION_STATUS %d", len(cases))
	fmt.Fprintf(&original, "fmt.Println(%q)\n}\n", marker)
	driver.WriteString("return failures != 0; }\n")
	runARMConversionGoOracle(t, source, original.String(), marker)
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
					"arm_conversion_status", "armv7-unknown-linux-gnueabihf", variant.ir, driver.String(),
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
				t.Logf("%d native result/FPSCR/canary observations", len(cases))
			})
		}
	}
}
