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
)

// This oracle uses the selected Go compiler and that same toolchain's runtime
// helper. Missing helper files are hard failures, not version-based skips.
func TestWASMPackedFunctionAddressActualGoRuntime(t *testing.T) {
	// Hosted runners carry large unrelated environments. The actual Go wasm
	// runtime has a bounded argv/environment area, unlike the native host.
	t.Setenv("PLAN9ASM_UNRELATED_HOST_CONTEXT", strings.Repeat("x", 16384))
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, _, goSource := wasmPackedRuntimeFixture(t)
	dir := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module packed_pc_oracle\ngo 1.20\n", "main.go": goSource, "oracle_wasm.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(ctx, "go", "build", "-o", "oracle.wasm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=js", "GOARCH=wasm", "GOTOOLCHAIN=local")
	if out, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go wasm oracle build: %v\n%s", err, out)
	}
	cmd, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), wasmPackedNode(t), filepath.Join(dir, "oracle.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil {
		t.Fatalf("actual Go wasm runtime: %v\n%s", err, result)
	}
	if strings.TrimSpace(string(result)) != "actual Go packed address + complete MOV widths + dynamic calls + native division PASS" {
		t.Fatalf("runtime helper exited without executing the complete Go oracle:\n%s", result)
	}
	t.Log(strings.TrimSpace(string(result)))
}

// Old Go's unmodified Node helper assigns its own crypto provider. Current
// Node exposes that global through a configurable getter without a setter.
// Preserve the actual provider and property visibility, making only that
// configurable binding writable before loading the selected SDK's helper.
// Node -e keeps argv[1] as the helper and argv[2] as the wasm program, exactly
// as the original wrapper expects. Paths remain separate arguments.
const wasmPackedNodeBootstrap = `"use strict";
const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
if (descriptor && descriptor.set === undefined &&
    (typeof descriptor.get === "function" || descriptor.writable === false)) {
  if (!descriptor.configurable) {
    throw new Error("Go wasm helper cannot initialize a nonconfigurable read-only crypto binding");
  }
  const provider = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", {
    value: provider, writable: true, enumerable: descriptor.enumerable,
    configurable: descriptor.configurable
  });
}
require(process.argv[1]);
`

func wasmPackedGoRuntimeCommand(ctx context.Context, root, node, wasm string) (*exec.Cmd, error) {
	if ctx == nil {
		return nil, fmt.Errorf("Go wasm runtime requires its bounded command context")
	}
	for _, directory := range []string{"lib", "misc"} {
		dir := filepath.Join(root, directory, "wasm")
		complete := true
		for _, name := range []string{"wasm_exec_node.js", "wasm_exec.js"} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil || !info.Mode().IsRegular() {
				complete = false
				break
			}
		}
		if complete {
			// These are the arguments of Go's go_js_wasm_exec wrapper,
			// without invoking its POSIX shell or requiring execute bits.
			command := exec.CommandContext(ctx, node, "--stack-size=8192", "-e", wasmPackedNodeBootstrap, filepath.Join(dir, "wasm_exec_node.js"), wasm)
			// These self-contained Go oracles need only a single runtime P
			// and the host's temporary/system directories. Forwarding CI's
			// build flags, PATH and unrelated variables overflows Go wasm's
			// small startup environment area; none are program inputs here.
			command.Env = []string{"GOMAXPROCS=1"}
			for _, key := range []string{"SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"} {
				if value, ok := os.LookupEnv(key); ok {
					command.Env = append(command.Env, key+"="+value)
				}
			}
			return command, nil
		}
	}
	return nil, fmt.Errorf("selected Go toolchain lacks its required lib/misc wasm runtime JavaScript files")
}
