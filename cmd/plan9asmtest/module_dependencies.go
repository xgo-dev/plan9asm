package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

var ciLLVM22Version = regexp.MustCompile(`(?im)(?:\bLLVM|\bclang) version 22(?:\.|$)|\bLLD 22(?:\.|$)`)
var ciNodeVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\r?\n$`)

func validateModuleNodeEnvironment(process map[string]string) error {
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA"} {
		value, present := process[key]
		if !present {
			return fmt.Errorf("required Node environment observation %s missing", key)
		}
		if value != "" {
			return fmt.Errorf("unmodeled nonempty Node consumer environment %s", key)
		}
	}
	return nil
}

func moduleDependencyCommand(ctx context.Context, cfg config, stem, executable string, args ...string) ([]byte, error) {
	if _, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, executable, args, stem); err != nil {
		return nil, err
	}
	info, err := os.Stat(stem + ".stdout")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, fmt.Errorf("bounded dependency observation required: %v", err)
	}
	return os.ReadFile(stem + ".stdout")
}

// Match the root oracle's real separate-LLD search order. A configured compiler
// never falls back; LLD is separately packaged and independently version checked.
func moduleWASMLinkerCandidates(bindir string) []string {
	return []string{filepath.Join(bindir, "wasm-ld"), "wasm-ld-22", "wasm-ld",
		filepath.Join("/opt/homebrew/opt/lld@22/bin", "wasm-ld"),
		filepath.Join("/usr/local/opt/lld@22/bin", "wasm-ld")}
}

func moduleWASMRuntimeFiles(root string) (map[string]string, error) {
	for _, directory := range []string{"lib", "misc"} {
		files := map[string]string{}
		for _, name := range []string{"wasm_exec.js", "wasm_exec_node.js"} {
			path := filepath.Join(root, directory, "wasm", name)
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				break
			}
			files["sdk-wasm/"+name] = path
		}
		if len(files) == 2 {
			return files, nil
		}
	}
	return nil, fmt.Errorf("selected Go SDK lacks required lib/misc wasm runtime JavaScript files")
}

func moduleSharedLibraries(data []byte) ([]string, error) {
	files := strings.Fields(string(data))
	if len(files) == 0 || len(files) > 32 || len(data) > 64<<10 {
		return nil, fmt.Errorf("bounded actual LLVM shared-library list required")
	}
	seen := map[string]bool{}
	for _, file := range files {
		if !ciAbsolutePath(file) || seen[filepath.FromSlash(file)] || strings.ContainsAny(file, "\"'") {
			return nil, fmt.Errorf("invalid/duplicate actual LLVM shared-library origin")
		}
		seen[filepath.FromSlash(file)] = true
	}
	return files, nil
}

func captureCINodeDependency(ctx context.Context, cfg config, stem string, origins map[string]string) error {
	process := map[string]string{}
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA"} {
		process[key] = os.Getenv(key)
	}
	if err := validateModuleNodeEnvironment(process); err != nil {
		return err
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("required module node runtime: %w", err)
	}
	origins["node"], err = filepath.Abs(node)
	if err != nil {
		return err
	}
	version, err := moduleDependencyCommand(ctx, cfg, stem+"-node-version", origins["node"], "--version")
	if err != nil {
		return fmt.Errorf("actual Node runtime: %w", err)
	}
	if !ciNodeVersion.Match(version) {
		return fmt.Errorf("actual Node runtime returned an unregistered version observation")
	}
	return nil
}

func captureModuleDependencies(ctx context.Context, cfg config, stem string, environment, origins map[string]string) error {
	if err := captureCINodeDependency(ctx, cfg, stem, origins); err != nil {
		return err
	}
	bindirData, err := os.ReadFile(stem + "-llvm-configbindir.stdout")
	if err != nil {
		return err
	}
	for index, candidate := range moduleWASMLinkerCandidates(strings.TrimSpace(string(bindirData))) {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		versionConfig := cfg
		if versionConfig.Timeout > 5*time.Second {
			versionConfig.Timeout = 5 * time.Second
		}
		data, err := moduleDependencyCommand(ctx, versionConfig, fmt.Sprintf("%s-wasm-linker-%d", stem, index), path, "--version")
		if err == nil && ciLLVM22Version.Match(data) {
			origins["wasm-ld"], err = filepath.Abs(path)
			if err != nil {
				return err
			}
			if err := ciWriteJSON(stem+"-wasm-linker-selection.json", moduleLoadedLibrary{Index: index, Path: origins["wasm-ld"]}); err != nil {
				return err
			}
			break
		}
	}
	if origins["wasm-ld"] == "" {
		return fmt.Errorf("required module LLVM 22 wasm-ld is unavailable")
	}
	runtimeFiles, err := moduleWASMRuntimeFiles(environment["GOROOT"])
	if err != nil {
		return err
	}
	for name, path := range runtimeFiles {
		origins[name] = path
	}
	data, err := moduleDependencyCommand(ctx, cfg, stem+"-llvm-shared-files", origins["llvm-config"], "--libfiles", "--link-shared")
	if err != nil {
		return err
	}
	libraries, err := moduleSharedLibraries(data)
	if err != nil {
		return err
	}
	for index, path := range libraries {
		origins[fmt.Sprintf("llvm-shared/%d", index)] = path
	}
	return captureModuleLLVMBinding(ctx, cfg, stem, libraries, origins)
}

type moduleLLVMPackage struct {
	ImportPath, Dir                             string
	GoFiles, CgoFiles, CFiles, CXXFiles, HFiles []string
	Error                                       json.RawMessage
	DepsErrors                                  []json.RawMessage
}

type moduleLoadedLibrary struct {
	Index int    `json:"configured_library_index"`
	Path  string `json:"actual_loaded_path"`
	SHA   string `json:"actual_loaded_sha256,omitempty"`
}

func moduleLLVMBinding(data []byte) (*moduleLLVMPackage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var binding *moduleLLVMPackage
	seen := map[string]bool{}
	for {
		var pkg moduleLLVMPackage
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			if len(seen) == 0 {
				return nil, fmt.Errorf("complete actual dependency inventory is empty")
			}
			return binding, nil
		}
		if err != nil || pkg.Error != nil || len(pkg.DepsErrors) != 0 {
			return nil, fmt.Errorf("actual complete Go dependency selection failed: %v", err)
		}
		if pkg.ImportPath == "" || seen[pkg.ImportPath] || len(seen) >= 20000 {
			return nil, fmt.Errorf("missing/duplicate/unbounded actual Go dependency identity")
		}
		seen[pkg.ImportPath] = true
		if pkg.ImportPath == "github.com/xgo-dev/llvm" {
			if binding != nil || !filepath.IsAbs(pkg.Dir) || len(pkg.CgoFiles) == 0 {
				return nil, fmt.Errorf("unique actual native Go LLVM binding required")
			}
			binding = &pkg
		}
	}
}

// This is an owned tool-dependency query, not a translated program. The selected
// Go binding calls LLVMContextCreate; observe that same loader symbol using
// dladdr or the Windows imported address, never a guessed library basename.
const moduleLLVMLoaderProbe = `package main
/*
#ifdef _WIN32
#include <stdint.h>
#include <windows.h>
// Explicit dllimport obtains the IAT target rather than MinGW's local thunk.
__declspec(dllimport) void *LLVMContextCreate(void);
static const char *loadedLLVM(void) {
    HMODULE module;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCWSTR)(uintptr_t)LLVMContextCreate, &module)) {
        return 0;
    }
    WCHAR wide[32768];
    DWORD length = GetModuleFileNameW(module, wide, 32768);
    BOOL released = FreeLibrary(module);
    if (!released || length == 0 || length >= 32768) {
        return 0;
    }
    static char path[4 * 32768];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
            path, sizeof(path), 0, 0)) {
        return 0;
    }
    return path;
}
#else
#define _GNU_SOURCE
#include <dlfcn.h>
#cgo linux LDFLAGS: -ldl
static const char *loadedLLVM(void) {
    void *symbol = dlsym(RTLD_DEFAULT, "LLVMContextCreate");
    Dl_info info;
    if (symbol == 0 || dladdr(symbol, &info) == 0) {
        return 0;
    }
    return info.dli_fname;
}
#endif
*/
import "C"
import (
    "fmt"
    "os"
    "github.com/xgo-dev/llvm"
)
func main() {
    context := llvm.NewContext()
    defer context.Dispose()
    path := C.loadedLLVM()
    if path == nil {
        os.Exit(2)
    }
    fmt.Println(C.GoString(path))
}
`

func captureModuleLLVMBinding(ctx context.Context, cfg config, stem string, libraries []string, origins map[string]string) error {
	flags, _, err := validateFlags(cfg.Flags)
	if err != nil {
		return err
	}
	args := append([]string{"list"}, moduleListFlags(flags)...)
	args = append(args, "-deps", "-test", "-json", "./...")
	data, err := moduleDependencyCommand(ctx, cfg, stem+"-llvm-go-packages", cfg.Go, args...)
	if err != nil {
		return err
	}
	binding, err := moduleLLVMBinding(data)
	if err != nil || binding == nil {
		return err // A first-party module without this consumer has no link probe.
	}
	files, err := moduleLLVMBindingFiles(binding)
	if err != nil {
		return err
	}
	for name, path := range files {
		origins[name] = path
	}
	input, err := prepareModuleLLVMProbeSource(ctx, stem)
	if err != nil {
		return err
	}
	source, binary := input.source.Path, gotoolchain.HostExecutable(stem+"-llvm-loader")
	if err := os.WriteFile(input.source.Artifact, []byte(moduleLLVMLoaderProbe), 0600); err != nil {
		return err
	}
	origins["llvm-loader-source"] = source
	args = append([]string{"build"}, moduleListFlags(flags)...)
	args = append(args, "-o", binary, source)
	if _, err := moduleDependencyCommand(ctx, cfg, stem+"-llvm-loader-build", cfg.Go, args...); err != nil {
		return fmt.Errorf("actual Go LLVM loader query build: %w", err)
	}
	loaded, err := moduleDependencyCommand(ctx, cfg, stem+"-llvm-loader-run", binary)
	if err != nil {
		return fmt.Errorf("actual Go LLVM loader query: %w", err)
	}
	if err := input.verify(ctx); err != nil {
		return err
	}
	if err := ciWriteJSON(stem+"-llvm-loader-source.json", input.source); err != nil {
		return err
	}
	path := strings.TrimSuffix(string(loaded), "\n")
	info, err := os.Stat(path)
	if err != nil || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("actual LLVM loaded-library path invalid: %v", err)
	}
	for index, library := range libraries {
		candidate, err := os.Stat(library)
		if err == nil && os.SameFile(info, candidate) {
			hash, err := ciFileSHA(path)
			if err != nil {
				return err
			}
			origins["llvm-loaded"] = path
			return ciWriteJSON(stem+"-llvm-loaded-library.json", moduleLoadedLibrary{Index: index, Path: path, SHA: hash})
		}
	}
	return fmt.Errorf("actual Go LLVM binding loaded a different configured library")
}

func moduleLLVMBindingFiles(binding *moduleLLVMPackage) (map[string]string, error) {
	origins := map[string]string{}
	if binding == nil {
		return origins, nil
	}
	files := append(append(append(append(append([]string{}, binding.GoFiles...), binding.CgoFiles...), binding.CFiles...), binding.CXXFiles...), binding.HFiles...)
	for _, file := range files {
		if file == "" || filepath.Base(file) != file || origins["llvm-binding/"+file] != "" || len(origins) >= 10000 {
			return nil, fmt.Errorf("invalid/duplicate/unbounded selected LLVM binding source")
		}
		origins["llvm-binding/"+file] = filepath.Join(binding.Dir, file)
	}
	return origins, nil
}

func verifyModuleDependencyArtifacts(directory string, report moduleReport) error {
	for _, phase := range []string{"before", "after"} {
		stem := filepath.Join(directory, phase)
		var origins, environment map[string]string
		if err := ciReadJSON(stem+"-origins.json", &origins); err != nil {
			return err
		}
		if err := ciReadJSON(stem+"-env.stdout", &environment); err != nil {
			return err
		}
		var observation ciEnvironmentContext
		if err := ciReadJSON(stem+"-environment-context.json", &observation); err != nil {
			return err
		}
		if err := validateModuleNodeEnvironment(observation.Process); err != nil {
			return err
		}
		for _, name := range []string{"node", "wasm-ld", "sdk-wasm/wasm_exec.js", "sdk-wasm/wasm_exec_node.js"} {
			if origins[name] == "" || report.Scope.Tools[name] == "" {
				return fmt.Errorf("required module dependency %s missing", name)
			}
		}
		version, err := os.ReadFile(stem + "-node-version.stdout")
		if err != nil || !ciNodeVersion.Match(version) {
			return fmt.Errorf("actual Node version observation differs: %v", err)
		}
		var linker moduleLoadedLibrary
		if err := ciReadJSON(stem+"-wasm-linker-selection.json", &linker); err != nil {
			return err
		}
		version, err = os.ReadFile(fmt.Sprintf("%s-wasm-linker-%d.stdout", stem, linker.Index))
		if err != nil || linker.Index < 0 || linker.Index >= len(moduleWASMLinkerCandidates("")) || linker.Path != origins["wasm-ld"] || !ciLLVM22Version.Match(version) {
			return fmt.Errorf("actual LLVM 22 wasm linker observation differs: %v", err)
		}
		for _, name := range []string{"wasm_exec.js", "wasm_exec_node.js"} {
			path := origins["sdk-wasm/"+name]
			if path != filepath.Join(environment["GOROOT"], "lib", "wasm", name) && path != filepath.Join(environment["GOROOT"], "misc", "wasm", name) {
				return fmt.Errorf("wasm runtime belongs to another selected SDK")
			}
		}
		if filepath.Dir(origins["sdk-wasm/wasm_exec.js"]) != filepath.Dir(origins["sdk-wasm/wasm_exec_node.js"]) {
			return fmt.Errorf("mixed Go wasm runtime directories")
		}
		data, err := os.ReadFile(stem + "-llvm-shared-files.stdout")
		if err != nil {
			return err
		}
		libraries, err := moduleSharedLibraries(data)
		if err != nil {
			return err
		}
		count := 0
		for name := range origins {
			if strings.HasPrefix(name, "llvm-shared/") {
				count++
			}
		}
		if count != len(libraries) {
			return fmt.Errorf("LLVM shared-library denominator differs")
		}
		for index, library := range libraries {
			key := fmt.Sprintf("llvm-shared/%d", index)
			if origins[key] != library || report.Scope.Tools[key] == "" {
				return fmt.Errorf("actual LLVM shared-library route differs")
			}
		}
		data, err = os.ReadFile(stem + "-llvm-go-packages.stdout")
		if err != nil {
			return err
		}
		binding, err := moduleLLVMBinding(data)
		if err != nil {
			return err
		}
		files, err := moduleLLVMBindingFiles(binding)
		if err != nil {
			return err
		}
		count = 0
		for name, path := range origins {
			if strings.HasPrefix(name, "llvm-binding/") {
				count++
				if files[name] != path || report.Scope.Tools[name] == "" {
					return fmt.Errorf("actual LLVM binding source route differs")
				}
			}
		}
		if count != len(files) {
			return fmt.Errorf("actual LLVM binding source denominator differs")
		}
		if binding == nil {
			if origins["llvm-loaded"] != "" || origins["llvm-loader-source"] != "" {
				return fmt.Errorf("unconsumed Go LLVM loader origin")
			}
			continue
		}
		source, err := os.ReadFile(stem + "-llvm-loader.go")
		if err != nil || string(source) != moduleLLVMLoaderProbe {
			return fmt.Errorf("actual LLVM loader query source differs: %v", err)
		}
		var compiled moduleLLVMProbeSource
		if err := ciReadJSON(stem+"-llvm-loader-source.json", &compiled); err != nil {
			return err
		}
		if !filepath.IsAbs(compiled.Parent) || filepath.Clean(compiled.Parent) != compiled.Parent ||
			compiled.Path != filepath.Join(compiled.Parent, ".llvm-loader-source", "main.go") ||
			compiled.Artifact != filepath.Join(compiled.Parent, phase+"-llvm-loader.go") ||
			origins["llvm-loader-source"] != compiled.Path || compiled.SHA != moduleLLVMProbeSHA(source) ||
			report.Scope.Tools["llvm-loader-source"] != compiled.SHA {
			return fmt.Errorf("actual LLVM compiled source role/byte identity differs")
		}
		var loaded moduleLoadedLibrary
		if err := ciReadJSON(stem+"-llvm-loaded-library.json", &loaded); err != nil {
			return err
		}
		data, err = os.ReadFile(stem + "-llvm-loader-run.stdout")
		if err != nil || loaded.Index < 0 || loaded.Index >= len(libraries) || !filepath.IsAbs(loaded.Path) || string(data) != loaded.Path+"\n" {
			return fmt.Errorf("actual Go LLVM loader observation differs: %v", err)
		}
		// Producer capture already proves SameFile on the actual loaded and
		// configured files. These paths need not exist on an aggregate runner;
		// retain its byte-bound observation and independently scoped tool hash.
		configuredHash := report.Scope.Tools[fmt.Sprintf("llvm-shared/%d", loaded.Index)]
		if len(loaded.SHA) != 64 || loaded.SHA != configuredHash || loaded.Path != origins["llvm-loaded"] || report.Scope.Tools["llvm-loaded"] != loaded.SHA {
			return fmt.Errorf("actual Go LLVM loader byte identity differs")
		}
	}
	return nil
}
