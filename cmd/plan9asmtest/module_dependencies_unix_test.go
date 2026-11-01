//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestModuleScopeBindsActualWASMAndLLVMConsumers(t *testing.T) {
	moduleFixtureEnvironment(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	dir := moduleFixture(t, false)
	stem := filepath.Join(t.TempDir(), "scope")
	cfg := config{Go: goBinary, Dir: dir, Module: true, Timeout: 2 * time.Minute}
	scope, err := captureCIScope(context.Background(), cfg, stem)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "wasm-ld", "llvm-shared/0", "sdk-wasm/wasm_exec.js", "sdk-wasm/wasm_exec_node.js"} {
		if scope.Tools[name] == "" {
			t.Errorf("complete module scope omitted actual required consumer %s", name)
		}
	}
	var origins map[string]string
	if err := ciReadJSON(stem+"-origins.json", &origins); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wasm_exec.js", "wasm_exec_node.js"} {
		origin := origins["sdk-wasm/"+name]
		if !strings.HasPrefix(origin, runtime.GOROOT()+string(filepath.Separator)) {
			t.Errorf("wasm runtime came from another SDK: %s", origin)
		}
	}
}

func TestModuleActualGoLLVMBindingMatchesConfiguredLibrary(t *testing.T) {
	moduleFixtureEnvironment(t)
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":      moduleLLVMFixtureGoMod(t, "example.org/llvmconsumer"),
		"consumer.go": "package consumer\nimport \"github.com/xgo-dev/llvm\"\nfunc Context() llvm.Context { return llvm.NewContext() }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := os.ReadFile(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0600); err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	stem := filepath.Join(t.TempDir(), "scope")
	cfg := config{Go: goBinary, Dir: dir, Module: true, Timeout: 2 * time.Minute}
	scope, err := captureCIScope(context.Background(), cfg, stem)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Tools["llvm-binding/ir.go"] == "" {
		t.Fatal("actual selected native binding source was not captured")
	}
	var loaded moduleLoadedLibrary
	if err := ciReadJSON(stem+"-llvm-loaded-library.json", &loaded); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(stem + "-llvm-loader-run.stdout")
	if err != nil || string(data) != loaded.Path+"\n" {
		t.Fatal("actual Go LLVM loader query did not execute", err)
	}
	t.Logf("actual selected binding loaded configured shared library index %d", loaded.Index)
	before := filepath.Join(filepath.Dir(stem), "before")
	after := filepath.Join(filepath.Dir(stem), "after")
	first, err := captureCIScope(context.Background(), cfg, before)
	if err != nil {
		t.Fatal(err)
	}
	last, err := captureCIScope(context.Background(), cfg, after)
	if err != nil || !reflect.DeepEqual(first, last) {
		t.Fatal("unchanged actual Go LLVM binding", err)
	}
	report := moduleReport{Scope: first}
	if err := verifyModuleDependencyArtifacts(filepath.Dir(stem), report); err != nil {
		t.Fatal(err)
	}
	var origins map[string]string
	if err := ciReadJSON(before+"-origins.json", &origins); err != nil {
		t.Fatal(err)
	}
	delete(origins, "llvm-binding/ir.go")
	if err := ciWriteJSON(before+"-origins.json", origins); err != nil {
		t.Fatal(err)
	}
	delete(report.Scope.Tools, "llvm-binding/ir.go")
	if err := verifyModuleDependencyArtifacts(filepath.Dir(stem), report); err == nil {
		t.Fatal("paired binding-source deletion accepted")
	}
}

func TestModuleDependencyArtifactDeletionAndChangesFail(t *testing.T) {
	moduleFixtureEnvironment(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	dir, out := moduleFixture(t, false), t.TempDir()
	cfg := config{Go: goBinary, Dir: dir, Module: true, Timeout: 2 * time.Minute}
	before, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "before"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "after"))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("actual unchanged dependency scope control", err)
	}
	report := moduleReport{Scope: before}
	if err := verifyModuleDependencyArtifacts(out, report); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before-node-version.stdout", "before-wasm-linker-selection.json", "before-llvm-shared-files.stdout", "before-llvm-go-packages.stdout"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(out, name)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, changed := range [][]byte{nil, []byte("foreign\n")} {
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if err := verifyModuleDependencyArtifacts(out, report); err == nil {
					t.Fatal("missing/mutated dependency observation was accepted")
				}
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestModuleWASMRuntimeSelectionAndSharedLibraryBounds(t *testing.T) {
	root := t.TempDir()
	if _, err := moduleWASMRuntimeFiles(root); err == nil {
		t.Fatal("absent actual SDK wasm runtime accepted")
	}
	write := func(directory, name string) {
		path := filepath.Join(root, directory, "wasm")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, name), []byte("runtime identity model"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("lib", "wasm_exec.js")
	write("misc", "wasm_exec_node.js")
	if _, err := moduleWASMRuntimeFiles(root); err == nil {
		t.Fatal("mixed partial directories accepted")
	}
	write("misc", "wasm_exec.js")
	files, err := moduleWASMRuntimeFiles(root)
	if err != nil || files["sdk-wasm/wasm_exec.js"] != filepath.Join(root, "misc", "wasm", "wasm_exec.js") {
		t.Fatal("complete historical runtime selection", err)
	}
	write("lib", "wasm_exec_node.js")
	files, err = moduleWASMRuntimeFiles(root)
	if err != nil || files["sdk-wasm/wasm_exec.js"] != filepath.Join(root, "lib", "wasm", "wasm_exec.js") {
		t.Fatal("current runtime must win only with its complete pair", err)
	}
	for _, data := range []string{"", "relative", "/library /library", "/library\x00", strings.Repeat("/library ", 33)} {
		if _, err := moduleSharedLibraries([]byte(data)); err == nil {
			t.Fatal("invalid/unbounded actual shared-library list accepted", data)
		}
	}
}

func TestModuleActualCLIRejectsMissingNodeConsumer(t *testing.T) {
	moduleFixtureEnvironment(t)
	binary := parallelFixtureCLI(t)
	dir := moduleFixture(t, false)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	llvmConfig := moduleFixtureLLVMConfig(t)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gitDirectory := t.TempDir()
	if err := os.Symlink(git, filepath.Join(gitDirectory, "git")); err != nil {
		t.Fatal(err)
	}
	// Keep the real SDK and LLVM tools, but no Node interpreter. This is an
	// actual Go module execution, not a script impersonating a compiler.
	t.Setenv("PATH", strings.Join([]string{filepath.Dir(goBinary), filepath.Dir(llvmConfig), gitDirectory}, string(os.PathListSeparator)))
	if _, err := exec.LookPath("node"); err == nil {
		t.Fatal("missing-Node fixture still has an interpreter")
	}
	stem := filepath.Join(t.TempDir(), "cli")
	out := filepath.Join(t.TempDir(), "module")
	_, err = captureCommand(context.Background(), 5*time.Minute, dir, binary,
		[]string{"-module", "-dir", dir, "-out", out, "-shards=2", "-workers=2", "-timeout=2m", "--", "-p=2"}, stem)
	if err == nil {
		t.Fatal("module completed without its required Node runtime")
	}
	data, readErr := os.ReadFile(stem + ".stderr")
	if readErr != nil || !strings.Contains(string(data), "node") {
		t.Fatalf("missing runtime did not retain its concrete cause: %v\n%s", readErr, data)
	}
}

func TestModuleActualScopeRejectsUnmodeledNodeEnvironment(t *testing.T) {
	moduleFixtureEnvironment(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	dir := moduleFixture(t, false)
	cfg := config{Go: goBinary, Dir: dir, Module: true, Timeout: 2 * time.Minute}
	controls := []string{"NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA"}
	for _, key := range controls {
		t.Setenv(key, "")
	}
	for _, absent := range []bool{false, true} {
		if absent {
			for _, key := range controls {
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
		}
		stem := filepath.Join(t.TempDir(), "scope")
		scope, err := captureCIScope(context.Background(), cfg, stem)
		if err != nil {
			t.Fatal("absent/empty actual Node environment control", err)
		}
		for _, key := range controls {
			if value, present := scope.Environment["process/"+key]; !present || value != "" {
				t.Fatalf("Node consumer control %s was not bound: %q %v", key, value, present)
			}
		}
	}
	for _, test := range []struct{ key, value string }{
		{"NODE_OPTIONS", "--enable-source-maps"},
		{"NODE_PATH", t.TempDir()},
		{"NODE_ICU_DATA", t.TempDir()},
	} {
		t.Run(test.key, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			stem := filepath.Join(t.TempDir(), "scope")
			if _, err := captureCIScope(context.Background(), cfg, stem); err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("actual unmodeled %s must fail with its concrete key: %v", test.key, err)
			}
		})
	}
	process := map[string]string{"NODE_OPTIONS": "", "NODE_PATH": "", "NODE_ICU_DATA": ""}
	for _, key := range controls {
		delete(process, key)
		if err := validateModuleNodeEnvironment(process); err == nil {
			t.Fatal("missing captured Node control accepted", key)
		}
		process[key] = ""
	}
}
