//go:build go1.27

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Go's assembler gained the SIMD namespace in Go 1.27. Its independent
// original-object/runtime checks must not hide minimum-Go LLVM coverage.
func TestWASMV128CoreActualGoNamespaceAndObjects(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, match := range regexp.MustCompile(`"(V128(?:Const|Not|And|Andnot|Or|Xor|Bitselect|AnyTrue))"`).FindAllSubmatch(data, -1) {
		names = append(names, string(match[1]))
	}
	if !reflect.DeepEqual(names, wasmV128CoreNames()) {
		t.Fatalf("complete official V128 core namespace changed: %v", names)
	}
	source, _ := wasmV128CoreObjectFixture()
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source, goos)
	}
}

func TestWASMV128CoreOriginalGoRuntime(t *testing.T) {
	_, source, program, _, _ := wasmV128CoreRuntimeFixture(t)
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module v128_core_oracle\ngo 1.20\n", "main.go": program, "oracle_wasm.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-o", "oracle.wasm", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOWORK=off", "GOOS=js", "GOARCH=wasm", "GOTOOLCHAIN=local")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go V128 core build: %v\n%s", err, output)
	}
	command, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), wasmPackedNode(t), filepath.Join(dir, "oracle.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || strings.TrimSpace(string(output)) != "V128 core PASS 48" {
		t.Fatalf("original Go V128 core execution: %v\n%s", err, output)
	}
}
