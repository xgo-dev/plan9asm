package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// Shared by portable object tests and the Unix native runtime oracles.
var fixedLocalNativeOperations = []string{
	"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDQ 16(SP),X0",
	"PMADDWL 16(SP),X0", "CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
}

func fixedLocalPackedRunOriginal(t *testing.T, execution x86FloatCompareExecution, assembly, declarations, oracle string, execute bool) {
	t.Helper()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":        "module example.invalid/framefixture\ngo 1.20\n",
		"value.go":      "package framefixture\n" + declarations,
		"value_amd64.s": assembly, "value_test.go": oracle,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, gotoolchain.HostExecutable("original.test"))
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-c", "-p=2", "-vet=off", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go packed-frame oracle: %v\n%s", err, output)
	}
	if execute {
		t.Logf("original Go: %s", execution.run(t, binary, "-test.run=^TestOriginal$"))
	}
}
