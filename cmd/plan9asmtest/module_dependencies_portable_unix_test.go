//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestModuleActualDependencyArtifactsSurviveProducerOriginRemoval(t *testing.T) {
	moduleFixtureEnvironment(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	configBinary := moduleFixtureLLVMConfig(t)
	// llvm-config reports its physical relocatable prefix. Keep the fixture's
	// own installation in that same namespace, including Darwin's /var alias.
	producerRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	producer := filepath.Join(producerRoot, "producer")
	for _, directory := range []string{"bin", "lib"} {
		if err := os.MkdirAll(filepath.Join(producer, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Copy only the real llvm-config bytes. Its actual relocatable-prefix
	// query determines the library origins; no script impersonates a tool.
	localConfig := filepath.Join(producer, "bin", "llvm-config")
	if err := copyModuleFixtureTool(configBinary, localConfig); err != nil {
		t.Fatal(err)
	}
	cfg := config{Go: goBinary, Module: true, Timeout: 2 * time.Minute}
	cfg.Dir = moduleLLVMConsumerFixture(t)
	out := t.TempDir()
	data, err := moduleDependencyCommand(context.Background(), cfg, filepath.Join(out, "original-libraries"), configBinary, "--libfiles", "--link-shared")
	if err != nil {
		t.Fatal(err)
	}
	libraries, err := moduleSharedLibraries(data)
	if err != nil {
		t.Fatal(err)
	}
	var hostLibraryDirectories []string
	for _, library := range libraries {
		if err := copyModuleFixtureTool(library, filepath.Join(producer, "lib", filepath.Base(library))); err != nil {
			t.Fatal(err)
		}
		physical, err := filepath.EvalSymlinks(library)
		if err != nil {
			t.Fatal(err)
		}
		hostLibraryDirectories = append(hostLibraryDirectories, filepath.Dir(physical))
		// The selected spelling and the library's actual loader filename may
		// differ. Keep that alias entirely within the fixture's copied tree.
		if filepath.Base(physical) != filepath.Base(library) {
			if err := os.Symlink(filepath.Base(library), filepath.Join(producer, "lib", filepath.Base(physical))); err != nil {
				t.Fatal(err)
			}
		}
	}
	bindir, err := moduleDependencyCommand(context.Background(), cfg, filepath.Join(out, "original-bindir"), configBinary, "--bindir")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range moduleFixtureRelocatedLLVMTools(os.Getenv("PLAN9ASM_CROSS_EXEC") == "1") {
		if err := os.Symlink(filepath.Join(strings.TrimSpace(string(bindir)), name), filepath.Join(producer, "bin", name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LLVM_CONFIG", localConfig)
	// Actual ELF SONAME/Mach-O install-name resolution must consume the copied
	// library, not a same-byte host inode. These controls are already recorded
	// completely by the ordinary module dependency producer and reader.
	t.Setenv("LD_LIBRARY_PATH", filepath.Join(producer, "lib"))
	t.Setenv("DYLD_LIBRARY_PATH", filepath.Join(producer, "lib"))
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" {
		t.Run("reject-missing-required-llvm-tool", func(t *testing.T) {
			tool := filepath.Join(producer, "bin", "ld.lld")
			retired := tool + "-retired"
			if err := os.Rename(tool, retired); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Rename(retired, tool); err != nil {
					t.Error("restore exact fixture tool", err)
				}
			}()
			_, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "missing-required-tool"))
			if err == nil || !strings.Contains(err.Error(), "required runtime tool ld.lld:") {
				t.Fatal("actual missing relocated LLVM tool did not retain its role rejection", err)
			}
			t.Logf("ACTUAL_MISSING_RELOCATED_LLVM_TOOL rejected=%q cause=%q", tool, err)
		})
	}
	t.Run("reject-original-host-loader", func(t *testing.T) {
		hostPath := strings.Join(hostLibraryDirectories, string(os.PathListSeparator))
		t.Setenv("LD_LIBRARY_PATH", hostPath)
		t.Setenv("DYLD_LIBRARY_PATH", hostPath)
		_, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "host-loader"))
		if err == nil || !strings.Contains(err.Error(), "actual Go LLVM binding loaded a different configured library") {
			t.Fatal("real host loader did not retain its selected-inode rejection", err)
		}
	})
	before, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "before"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "after"))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("unchanged actual relocated producer scope", err)
	}
	report := moduleReport{Scope: before}
	if err := verifyModuleDependencyArtifacts(out, report); err != nil {
		t.Fatal("actual producer control", err)
	}
	var origins map[string]string
	if err := ciReadJSON(filepath.Join(out, "before-origins.json"), &origins); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual relocated llvm-config library origin=%q requested producer=%q",
		origins["llvm-shared/0"], producer)
	if !strings.HasPrefix(origins["llvm-shared/0"], producer+string(filepath.Separator)) {
		t.Fatal("real llvm-config did not select the owned producer installation")
	}
	var loaded moduleLoadedLibrary
	if err := ciReadJSON(filepath.Join(out, "before-llvm-loaded-library.json"), &loaded); err != nil {
		t.Fatal(err)
	}
	loadedInfo, err := os.Stat(loaded.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range libraries {
		originalInfo, err := os.Stat(original)
		if err != nil || os.SameFile(loadedInfo, originalInfo) {
			t.Fatal("actual Go LLVM native handle still refers to a host library inode", err)
		}
		t.Logf("ACTUAL_RELOCATED_LLVM_NATIVE_HANDLE copied=%q original=%q independent_inode=true", loaded.Path, original)
	}
	if err := os.Rename(producer, producer+"-closed"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(origins["llvm-shared/0"]); !os.IsNotExist(err) {
		t.Fatal("producer origin is unexpectedly still available", err)
	}
	relocated := filepath.Join(t.TempDir(), "downloaded-owner")
	if err := os.Rename(out, relocated); err != nil {
		t.Fatal(err)
	}
	if err := verifyModuleDependencyArtifacts(relocated, report); err != nil {
		t.Fatal("portable reader required a retired producer physical path", err)
	}
	path := filepath.Join(relocated, "before-llvm-loaded-library.json")
	if err := ciReadJSON(path, &loaded); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"missing-byte-identity", "changed-byte-identity", "changed-configured-index", "changed-loaded-path"} {
		t.Run(mutation, func(t *testing.T) {
			changed := loaded
			switch mutation {
			case "missing-byte-identity":
				changed.SHA = ""
			case "changed-byte-identity":
				changed.SHA = strings.Repeat("0", 64)
			case "changed-configured-index":
				changed.Index = len(libraries)
			case "changed-loaded-path":
				changed.Path = goBinary
			}
			if err := ciWriteJSON(path, changed); err != nil {
				t.Fatal(err)
			}
			if err := verifyModuleDependencyArtifacts(relocated, report); err == nil {
				t.Fatal("changed/missing loaded library identity accepted")
			}
			if err := ciWriteJSON(path, loaded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func moduleLLVMConsumerFixture(t *testing.T) string {
	t.Helper()
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
	return dir
}
