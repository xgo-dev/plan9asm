package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This is an observation of the unchanged original Go caller and callee, not
// an LLVM projection oracle. Native padding writes are separately observable.
func TestCrossLinuxRuntimeMatrixARM64NativeResultTailObserver(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	var declarations, assembly, driver strings.Builder
	declarations.WriteString("package main\n\n")
	driver.WriteString("package main\n\nimport \"fmt\"\n\n")
	cases := arm64NativeResultTailCases()
	for _, test := range cases {
		declarations.WriteString(test.declaration())
		fmt.Fprintf(&declarations, "func observe_%s(input uint64) (value, native, guard uint64)\n", test.name())
		assembly.WriteString(test.source())
		assembly.WriteString(arm64NativeResultTailObserver(test))
	}
	driver.WriteString("func main() {\n    inputs := []uint64{\n")
	for _, value := range arm64PaddingRuntimeInputs() {
		fmt.Fprintf(&driver, "        0x%x,\n", value)
	}
	driver.WriteString("    }\n    observations := 0\n")
	for _, test := range cases {
		resultMask := ^uint64(0) >> uint(64-test.resultBits)
		storeMask := ^uint64(0) >> uint(64-test.storeBits)
		fmt.Fprintf(&driver, `    for _, input := range inputs {
        value, native, guard := observe_%s(input)
        wantValue := input & 0x%x
        wantNative := (uint64(0xfeedfacecafebeef) &^ uint64(0x%x)) | (input & 0x%x)
        if value != wantValue || native != wantNative || guard != 0x7ac35ef012345678 {
            panic(fmt.Sprintf("%s input=%%x value=%%x native=%%x guard=%%x", input, value, native, guard))
        }
        observations++
    }
`, test.name(), resultMask, storeMask, storeMask, test.name())
	}
	driver.WriteString("    fmt.Printf(\"native tail observations %d\\n\", observations)\n}\n")

	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":  "module tailobserve\n\ngo 1.20\n",
		"decl.go": declarations.String(), "main.go": driver.String(),
		"tailobserve_arm64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := []string{"run", "-p=1"}
	if len(runner) != 0 {
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "-exec="+quoted)
	}
	command := exec.CommandContext(ctx, "go", append(args, ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=arm64", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		command.Env = append(command.Env, "GOOS=linux")
	}
	out, err := runtimeOracleCombinedOutput(ctx, command)
	want := fmt.Sprintf("native tail observations %d\n", len(cases)*len(arm64PaddingRuntimeInputs()))
	if err != nil || string(out) != want {
		t.Fatalf("original Go result, observable native tail, and adjacent canary: %v\n%s", err, out)
	}
	t.Logf("%d original Go observations establish native-tail visibility, not LLVM equivalence",
		len(cases)*len(arm64PaddingRuntimeInputs()))
}
