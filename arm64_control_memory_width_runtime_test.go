package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCrossLinuxRuntimeMatrixARM64ControlMemoryAdjacent(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	file, sigs, source, cases := arm64ControlMemoryAdjacentFixture(t)
	var goDeclarations, goChecks, cDeclarations, cChecks strings.Builder
	for _, tc := range cases {
		floating := 0
		if tc.floating {
			floating = 1
		}
		fmt.Fprintf(&goDeclarations, "func %s(*byte,*byte)\n", tc.name)
		fmt.Fprintf(&cDeclarations, "extern void %s(const unsigned char *,unsigned char *);\n", tc.name)
		fmt.Fprintf(&goChecks, "check(%s,%d,%d,%d,%d)\n", tc.name, tc.width, tc.count, tc.signBits, floating)
		fmt.Fprintf(&cChecks, "if(check(%s,%d,%d,%d,%d)) return 1;\n", tc.name, tc.width, tc.count, tc.signBits, floating)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module adjacentcalleroracle\n\ngo 1.20\n",
		"main.go": arm64RawPrivateFrameOracleGo + goDeclarations.String() +
			"func main(){\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT adjacent_", "TEXT ·adjacent_"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{"run", "-p=1", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=1", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go adjacent caller-cell width oracle: %v\n%s", err, output)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	cMain := arm64RawPrivateFrameOracleC + cDeclarations.String() +
		"int main(void){\n" + cChecks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "adjacent_caller_memory", triple, ir, cMain, runner)
	t.Logf("actual Go + LLVM22/independent numeric C: %d width/sign/pair/writeback/local-call variants x 256 patterns x 5 unaligned offsets; adjacent saved LR/BP, full canaries and real return", len(cases))
}
