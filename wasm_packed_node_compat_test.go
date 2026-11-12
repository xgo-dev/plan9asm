package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWASMPackedGoRuntimeHelperPreservesNodeGlobalCompatibility(t *testing.T) {
	node := wasmPackedNode(t)
	for _, tc := range []struct {
		name, setup, initial, beforeBootstrap string
		refused                               bool
	}{
		{
			name: "configurable_getter", initial: "original",
			setup: `Object.defineProperty(globalThis, "crypto", {
  get() { return source; }, enumerable: true, configurable: true
});`,
		},
		{
			name: "configurable_readonly_data", initial: "original",
			setup: `Object.defineProperty(globalThis, "crypto", {
  value: source, writable: false, enumerable: true, configurable: true
});`,
		},
		{
			name: "writable_provider", initial: "original",
			setup: `Object.defineProperty(globalThis, "crypto", {
  value: source, writable: true, enumerable: true, configurable: true
});`,
		},
		{
			name: "absent_provider",
			setup: `delete globalThis.crypto;
globalThis.__plan9asmOriginalCrypto = undefined;`,
			// Node installs eval-context builtin getters after --require runs.
			// Establish this fixture's genuinely absent binding immediately
			// before the unchanged bootstrap, not merely before eval startup.
			beforeBootstrap: "delete globalThis.crypto;\n",
		},
		{
			name: "nonconfigurable_getter", refused: true,
			setup: `Object.defineProperty(globalThis, "crypto", {
  get() { return source; }, enumerable: true, configurable: false
});`,
		},
		{
			name: "nonconfigurable_readonly_data", refused: true,
			setup: `Object.defineProperty(globalThis, "crypto", {
  value: source, writable: false, enumerable: true, configurable: false
});`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "misc", "wasm")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			setup := filepath.Join(root, "node setup.cjs")
			files := map[string]string{
				setup: `const source = { provider: "original" };
globalThis.__plan9asmOriginalCrypto = source;
` + tc.setup,
				filepath.Join(dir, "wasm_exec.js"): `module.exports = { fixture: "same-sdk" };`,
				filepath.Join(dir, "wasm_exec_node.js"): `"use strict";
const original = globalThis.crypto;
globalThis.crypto = { provider: "go-runtime" };
console.log(JSON.stringify({
  args: process.argv.slice(2), initial: original ? original.provider : "",
  preserved: original === globalThis.__plan9asmOriginalCrypto,
  provider: globalThis.crypto.provider,
  companion: require("./wasm_exec").fixture
}));`,
			}
			for name, data := range files {
				if err := os.WriteFile(name, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			wasm := filepath.Join(root, "Go Program Files", "oracle.wasm")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command, err := wasmPackedGoRuntimeCommand(ctx, root, node, wasm)
			if err != nil {
				t.Fatal(err)
			}
			args := append([]string{"--require", setup}, command.Args[1:]...)
			if tc.beforeBootstrap != "" {
				found := false
				for i := 0; i+1 < len(args); i++ {
					if args[i] == "-e" && args[i+1] == wasmPackedNodeBootstrap {
						args[i+1] = tc.beforeBootstrap + args[i+1]
						found = true
						break
					}
				}
				if !found {
					t.Fatal("fixture cannot bind the actual bootstrap environment")
				}
			}
			output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, node, args...))
			if tc.refused {
				if !wasmPackedNodeBindingRefused(ctx, output, err) {
					t.Fatalf("immutable binding must fail before a fake runtime pass: %v\n%s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("actual Node cannot load its selected Go runtime helper: %v\n%s", err, output)
			}
			var result struct {
				Args                         []string
				Initial, Provider, Companion string
				Preserved                    bool
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("runtime fixture did not execute: %v\n%s", err, output)
			}
			if !reflect.DeepEqual(result.Args, []string{wasm}) || result.Initial != tc.initial ||
				!result.Preserved || result.Provider != "go-runtime" || result.Companion != "same-sdk" {
				t.Fatalf("original provider, Go argv or same-SDK module resolution changed: %+v", result)
			}
		})
	}
}

const wasmPackedImmutableBindingDiagnostic = "Error: Go wasm helper cannot initialize a nonconfigurable read-only crypto binding"

func wasmPackedNodeBindingRefused(ctx context.Context, output []byte, err error) bool {
	// A wrapped/joined exit may contain cancellation or owned cleanup errors.
	// Only the actual plain Node exit and its exact bootstrap error line can
	// establish this refusal, before the selected helper starts executing.
	exit, ok := err.(*exec.ExitError)
	text := strings.ReplaceAll(string(output), "\r\n", "\n")
	return ctx != nil && ctx.Err() == nil && ok && exit.ExitCode() == 1 &&
		!strings.Contains(text, "\r") &&
		strings.Count(text, "\n"+wasmPackedImmutableBindingDiagnostic+"\n") == 1 &&
		!strings.Contains(text, `"companion":"same-sdk"`)
}

func TestWASMPackedGoRuntimeHelperRejectsUnknownNodeFailures(t *testing.T) {
	node := wasmPackedNode(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	_, exitOne := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, node, "-e", "process.exit(1)"))
	_, exitTwo := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, node, "-e", "process.exit(2)"))
	for code, observed := range map[int]error{1: exitOne, 2: exitTwo} {
		exit, ok := observed.(*exec.ExitError)
		if !ok || exit.ExitCode() != code {
			t.Fatalf("Node fixture did not provide its actual plain exit %d: %v", code, observed)
		}
	}

	expired, expire := context.WithCancel(context.Background())
	expire()
	diagnostic := []byte("\n" + wasmPackedImmutableBindingDiagnostic + "\n")
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		output   []byte
		err      error
		accepted bool
	}{
		{"known_plain_exit", ctx, diagnostic, exitOne, true},
		{"native_CRLF", ctx, []byte("\r\n" + wasmPackedImmutableBindingDiagnostic + "\r\n"), exitOne, true},
		{"bare_CR", ctx, []byte("\r" + wasmPackedImmutableBindingDiagnostic + "\r"), exitOne, false},
		{"embedded_CR", ctx, []byte("\n" + wasmPackedImmutableBindingDiagnostic + "\rforeign\n"), exitOne, false},
		{"no_context", nil, diagnostic, exitOne, false},
		{"canceled_context", expired, diagnostic, exitOne, false},
		{"joined_cleanup", ctx, diagnostic, errors.Join(exitOne, errors.New("owned cleanup failure")), false},
		{"wrapped_exit", ctx, diagnostic, &os.PathError{Op: "start", Path: "node", Err: exitOne}, false},
		{"deadline", ctx, diagnostic, context.DeadlineExceeded, false},
		{"missing_program", ctx, diagnostic, exec.ErrNotFound, false},
		{"wrong_status", ctx, diagnostic, exitTwo, false},
		{"successful_status", ctx, diagnostic, nil, false},
		{"missing_diagnostic", ctx, nil, exitOne, false},
		{"unrelated_diagnostic", ctx, []byte("Error: Cannot find module\n"), exitOne, false},
		{"quoted_diagnostic", ctx, []byte("throw new Error(\"" + wasmPackedImmutableBindingDiagnostic + "\");\n"), exitOne, false},
		{"duplicate_diagnostic", ctx, append(append([]byte{}, diagnostic...), diagnostic...), exitOne, false},
		{"runtime_already_executed", ctx, append(append([]byte{}, diagnostic...), []byte(`{"companion":"same-sdk"}`)...), exitOne, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasmPackedNodeBindingRefused(tc.ctx, tc.output, tc.err); got != tc.accepted {
				t.Fatalf("Node binding refusal=%v, want=%v: %v\n%s", got, tc.accepted, tc.err, tc.output)
			}
		})
	}
}
