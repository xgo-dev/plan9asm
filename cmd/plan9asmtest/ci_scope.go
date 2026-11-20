package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// Scope equality excludes disposable cache/workspace spelling, not compiler,
// runtime, source or tool identity. Raw go env and actual tool origins remain
// artifacts. No stored scope can replace a fresh before/after observation.
func captureCIScope(ctx context.Context, cfg config, stem string) (ciScope, error) {
	scope := ciScope{Tools: map[string]string{}, Environment: map[string]string{}}
	query := func(name string, args ...string) ([]byte, error) {
		if _, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, args, stem+"-"+name); err != nil {
			return nil, err
		}
		return os.ReadFile(stem + "-" + name + ".stdout")
	}
	version, err := query("version", "version")
	if err != nil {
		return scope, err
	}
	scope.GoVersion = strings.TrimSpace(string(version))
	data, err := query("env", "env", "-json")
	if err != nil {
		return scope, err
	}
	var environment map[string]string
	if err := json.Unmarshal(data, &environment); err != nil {
		return scope, err
	}
	observation, err := captureCIEnvironmentContext(cfg.Dir, environment)
	if err != nil {
		return scope, err
	}
	scope.Environment, err = normalizeCIEnvironment(environment, observation)
	if err != nil {
		return scope, err
	}
	if err := ciWriteJSON(stem+"-environment-context.json", observation); err != nil {
		return scope, err
	}
	actualDriver, err := os.Stat(cfg.Go)
	if err != nil {
		return scope, err
	}
	sdkDriver, err := os.Stat(filepath.Join(environment["GOROOT"], "bin", gotoolchain.HostExecutable("go")))
	if err != nil || !os.SameFile(actualDriver, sdkDriver) {
		return scope, fmt.Errorf("selected executable is not actual SDK driver: %v", err)
	}
	pathDriver, err := exec.LookPath("go")
	if err != nil {
		return scope, err
	}
	pathInfo, err := os.Stat(pathDriver)
	if err != nil || !os.SameFile(actualDriver, pathInfo) {
		return scope, fmt.Errorf("nested Go test helpers must resolve the same actual SDK driver: %v", err)
	}
	if os.Getenv("GOENV") != "off" || os.Getenv("GOWORK") != "off" || os.Getenv("GOTOOLCHAIN") != "local" {
		return scope, fmt.Errorf("CI scope requires explicit GOENV=off, GOWORK=off and GOTOOLCHAIN=local")
	}
	if err := validateRunnerGoFlags(runtime.GOOS, environment["GOFLAGS"], cfg.Flags); err != nil {
		return scope, err
	}
	toolDir := environment["GOTOOLDIR"]
	root := environment["GOROOT"]
	if !filepath.IsAbs(root) || !filepath.IsAbs(toolDir) {
		return scope, fmt.Errorf("actual SDK roots must be absolute")
	}
	origins := map[string]string{"go": cfg.Go}
	for _, name := range []string{"asm", "compile", "link", "vet", "cgo", "cover", "test2json", "nm", "objdump"} {
		// Go 1.27 builds some official tools on demand; they are not all
		// physical GOTOOLDIR members. Observe the same driver's real route.
		path, err := query("tool-"+name, "tool", "-n", name)
		if err != nil {
			return scope, err
		}
		origins["go/"+name] = strings.TrimSpace(string(path))
		if !filepath.IsAbs(origins["go/"+name]) {
			return scope, fmt.Errorf("actual SDK tool %s route is not absolute", name)
		}
	}
	// Whole-module gates bind the same LLVM 22 core used by their tests.
	// Only the required Linux cross-runtime role demands cross linkers/QEMU.
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" || cfg.Module {
		cross := os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
		if cross {
			if environment["GOHOSTOS"] != "linux" || environment["GOHOSTARCH"] != "amd64" {
				return scope, fmt.Errorf("required native cross-runtime driver is Linux/amd64")
			}
			for _, name := range []string{"CC", "CXX", "AR", "PKG_CONFIG"} {
				requested := environment[name]
				// A wrapper/compound command would need its own delegated-tool
				// closure. The existing CI uses single official compiler commands.
				if requested == "" || strings.ContainsAny(requested, " \t'\"") {
					return scope, fmt.Errorf("unregistered actual %s compiler/tool command", name)
				}
				path, err := exec.LookPath(requested)
				if err != nil {
					return scope, fmt.Errorf("actual %s tool: %w", name, err)
				}
				origins["environment/"+name], err = filepath.Abs(path)
				if err != nil {
					return scope, err
				}
			}
		}
		bindir := ""
		if os.Getenv("LLVM_CONFIG") != "" || cfg.Module {
			configPath, err := resolveCIConfigExecutable()
			if err != nil {
				return scope, err
			}
			origins["llvm-config"] = configPath
			for _, argument := range []string{"--version", "--bindir"} {
				path := stem + "-llvm-config" + strings.TrimPrefix(argument, "--")
				if _, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, configPath, []string{argument}, path); err != nil {
					return scope, err
				}
				output, err := os.ReadFile(path + ".stdout")
				if err != nil {
					return scope, err
				}
				text := strings.TrimSpace(string(output))
				if argument == "--version" && !strings.HasPrefix(text, "22.") {
					return scope, fmt.Errorf("actual LLVM_CONFIG must select LLVM 22")
				}
				if argument == "--bindir" {
					if !filepath.IsAbs(text) {
						return scope, fmt.Errorf("actual LLVM bindir must be absolute")
					}
					bindir = text
				}
			}
		}
		names := []string{"llvm-config", "llc", "clang", "llvm-as", "opt", "llvm-dis", "llvm-objdump", "llvm-nm"}
		if cross {
			names = append(names, "ld.lld", "i686-linux-gnu-gcc", "arm-linux-gnueabihf-gcc", "aarch64-linux-gnu-gcc", "qemu-i386", "qemu-arm", "qemu-aarch64")
		}
		for _, name := range names {
			if name == "llvm-config" && origins[name] != "" {
				continue
			}
			requested := name
			llvmTool := name == "clang" || name == "llc" || name == "opt" || name == "ld.lld" || strings.HasPrefix(name, "llvm-")
			if llvmTool {
				if bindir != "" {
					requested = filepath.Join(bindir, name)
				} else if versioned, err := exec.LookPath(name + "-22"); err == nil {
					requested = versioned
				}
			}
			if name == "llvm-config" && os.Getenv("LLVM_CONFIG") != "" {
				requested = os.Getenv("LLVM_CONFIG")
			}
			path, err := exec.LookPath(requested)
			if err != nil {
				return scope, fmt.Errorf("required runtime tool %s: %w", name, err)
			}
			origins[name], err = filepath.Abs(path)
			if err != nil {
				return scope, err
			}
		}
	}
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" && !cfg.Module {
		if err := captureCINodeDependency(ctx, cfg, stem, origins); err != nil {
			return scope, err
		}
	}
	if cfg.Module {
		if err := captureModuleDependencies(ctx, cfg, stem, environment, origins); err != nil {
			return scope, err
		}
	}
	for name, path := range origins {
		hash, err := ciFileSHA(path)
		if err != nil {
			return scope, fmt.Errorf("tool %s: %w", name, err)
		}
		scope.Tools[name] = hash
	}
	if err := ciWriteJSON(stem+"-origins.json", origins); err != nil {
		return scope, err
	}
	var sdkFiles []string
	for _, directory := range []string{"src", "pkg/include"} {
		files, err := ciDirectoryFiles(filepath.Join(root, directory))
		if err != nil {
			return scope, err
		}
		for _, file := range files {
			sdkFiles = append(sdkFiles, filepath.Join(directory, file))
		}
	}
	if cfg.Module {
		// Include the complete actual selected wasm runtime directory, not only
		// SDK/src (current SDKs keep these consumers under lib/wasm).
		directory := filepath.Dir(origins["sdk-wasm/wasm_exec.js"])
		files, err := ciDirectoryFiles(directory)
		if err != nil {
			return scope, err
		}
		relative, err := filepath.Rel(root, directory)
		if err != nil {
			return scope, err
		}
		for _, file := range files {
			sdkFiles = append(sdkFiles, filepath.Join(relative, file))
		}
	}
	for _, name := range []string{"VERSION", "go.env"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			sdkFiles = append(sdkFiles, name)
		} else if !os.IsNotExist(err) {
			return scope, err
		}
	}
	scope.SDKSource, err = ciFilesSHA(root, sdkFiles)
	if err != nil {
		return scope, err
	}
	scope.SourceSHA, scope.Head, err = ciSourceSHA(ctx, cfg, stem)
	return scope, err
}

func verifyCIScopeArtifacts(directory string, report ciReport) error {
	for name, wanted := range map[string][]string{"inventory": report.Plan.Inventory, "selected": report.Plan.Selected} {
		data, err := os.ReadFile(filepath.Join(directory, name+".stdout"))
		if err != nil {
			return err
		}
		pkg, names, benchmarks, err := parseList(string(data))
		if err != nil || pkg != report.Plan.Package || !reflect.DeepEqual(names, wanted) || (name == "inventory" && !reflect.DeepEqual(benchmarks, report.Plan.Benchmarks)) {
			return fmt.Errorf("actual %s inventory observation differs: %v", name, err)
		}
	}
	return verifyScopeArtifacts(directory, report.Go, report.Plan.Scope)
}

func verifyScopeArtifacts(directory, goBinary string, scope ciScope) error {
	var beforeOrigins map[string]string
	for _, phase := range []string{"before", "after"} {
		stem := filepath.Join(directory, phase)
		version, err := os.ReadFile(stem + "-version.stdout")
		if err != nil || strings.TrimSpace(string(version)) != scope.GoVersion {
			return fmt.Errorf("actual SDK version observation differs: %v", err)
		}
		var environment map[string]string
		if err := ciReadJSON(stem+"-env.stdout", &environment); err != nil {
			return err
		}
		var observation ciEnvironmentContext
		if err := ciReadJSON(stem+"-environment-context.json", &observation); err != nil {
			return err
		}
		normalized, err := normalizeCIEnvironment(environment, observation)
		if err != nil || !reflect.DeepEqual(normalized, scope.Environment) {
			return fmt.Errorf("complete actual environment differs: %v", err)
		}
		var origins map[string]string
		if err := ciReadJSON(stem+"-origins.json", &origins); err != nil {
			return err
		}
		if origins["go"] != goBinary || len(origins) != len(scope.Tools) {
			return fmt.Errorf("actual SDK/tool origins differ")
		}
		if scope.Tools["node"] != "" {
			if err := validateModuleNodeEnvironment(observation.Process); err != nil {
				return err
			}
			version, err := os.ReadFile(stem + "-node-version.stdout")
			if err != nil || !ciNodeVersion.Match(version) {
				return fmt.Errorf("actual Node version observation differs: %v", err)
			}
		}
		for name := range scope.Tools {
			if !filepath.IsAbs(origins[name]) {
				return fmt.Errorf("actual tool %s origin missing", name)
			}
			if strings.HasPrefix(name, "go/") {
				observed, err := os.ReadFile(stem + "-tool-" + strings.TrimPrefix(name, "go/") + ".stdout")
				if err != nil || strings.TrimSpace(string(observed)) != origins[name] {
					return fmt.Errorf("actual SDK tool %s route differs: %v", name, err)
				}
			}
		}
		if phase == "before" {
			beforeOrigins = origins
		} else if !reflect.DeepEqual(beforeOrigins, origins) {
			return fmt.Errorf("tool origin changed during worker")
		}
	}
	return nil
}

func ciFileSHA(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ciDirectoryFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("source file must be regular: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err == nil {
			files = append(files, relative)
		}
		return err
	})
	return files, err
}

func ciFilesSHA(root string, files []string) (string, error) {
	sort.Strings(files)
	hash := sha256.New()
	for _, name := range files {
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", fmt.Errorf("source identity %s: %v", name, err)
		}
		contents, err := ciFileSHA(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(hash, "%s\x00%s\x00", filepath.ToSlash(name), contents)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ciSourceSHA(ctx context.Context, cfg config, stem string) (string, string, error) {
	// Real CI checks a clean complete Git checkout. A local, nongit first-party
	// fixture binds all files in its source directory; artifacts must be outside.
	gitRoot := cfg.Dir
	for {
		if _, err := os.Lstat(filepath.Join(gitRoot, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(gitRoot)
		if parent == gitRoot {
			files, err := ciDirectoryFiles(cfg.Dir)
			if err != nil {
				return "", "", err
			}
			hash, err := ciFilesSHA(cfg.Dir, files)
			return hash, "", err
		}
		gitRoot = parent
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return "", "", err
	}
	query := func(name string, args ...string) ([]byte, error) {
		if _, err := captureCommand(ctx, cfg.Timeout, gitRoot, git, args, stem+"-git-"+name); err != nil {
			return nil, err
		}
		return os.ReadFile(stem + "-git-" + name + ".stdout")
	}
	relative, err := filepath.Rel(gitRoot, cfg.Dir)
	if err != nil {
		return "", "", err
	}
	selected, err := query("selected", "ls-files", "-z", "--", relative)
	if err != nil {
		return "", "", err
	}
	if len(selected) == 0 {
		files, err := ciDirectoryFiles(cfg.Dir)
		if err != nil {
			return "", "", err
		}
		hash, err := ciFilesSHA(cfg.Dir, files)
		return hash, "", err
	}
	status, err := query("status", "status", "--porcelain", "--untracked-files=normal")
	if err != nil || len(status) != 0 {
		return "", "", fmt.Errorf("CI source must be clean: %s (%v)", status, err)
	}
	head, err := query("head", "rev-parse", "HEAD")
	if err != nil {
		return "", "", err
	}
	listing, err := query("files", "ls-files", "-z")
	if err != nil {
		return "", "", err
	}
	files := strings.Split(strings.TrimSuffix(string(listing), "\x00"), "\x00")
	hash, err := ciFilesSHA(gitRoot, files)
	return hash, strings.TrimSpace(string(head)), err
}
