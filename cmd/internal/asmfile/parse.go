// Package asmfile binds generated Go headers and target-specific includes for the assembly CLIs.
package asmfile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/goversion"
	"github.com/xgo-dev/plan9asm/internal/preprocess"
)

// Both commands load packages with the Go command selected for their process.
// Its SDK may differ from the SDK used to build the CLI.
type goSDKIncludes struct {
	sync.Once
	path    string
	version string
	err     error
}

var commandIncludes goSDKIncludes

func (dir *goSDKIncludes) load() {
	dir.Do(func() {
		out, err := exec.Command("go", "env", "GOROOT").Output()
		if err != nil {
			dir.err = fmt.Errorf("resolve assembler SDK with go env GOROOT: %w", err)
			return
		}
		root := strings.TrimSpace(string(out))
		if !filepath.IsAbs(root) {
			dir.err = fmt.Errorf("go env GOROOT returned invalid root %q", root)
			return
		}
		dir.version, dir.err = selectedSDKVersion(root)
		dir.path = filepath.Join(root, "pkg", "include")
	})
}

// Distribution SDKs can omit VERSION. In that case query the selected
// root's own tool with toolchain switching disabled.
func selectedSDKVersion(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if os.IsNotExist(err) {
		name := "go"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		cmd := exec.Command(filepath.Join(root, "bin", name), "env", "GOVERSION")
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOROOT="+root)
		b, err = cmd.Output()
	}
	if err != nil {
		return "", fmt.Errorf("read selected SDK version at %s: %w", root, err)
	}
	first, _, _ := strings.Cut(string(b), "\n")
	v := strings.TrimSpace(first)
	if _, ok := goversion.ParseMinor(v); !ok {
		return "", fmt.Errorf("invalid selected SDK version %q in %s", v, root)
	}
	return v, nil
}

func (dir *goSDKIncludes) read(name string) (string, []byte, error) {
	dir.load()
	if dir.err != nil {
		return "", nil, dir.err
	}
	path := filepath.Join(dir.path, name)
	data, err := os.ReadFile(path)
	return path, data, err
}

// ParseInput returns nil input only for a genuinely empty assembler unit. The
// legacy parser omits include directives; a header can contain the entire unit.
func ParseInput(pkg plan9asm.GoPackage, src []byte, filename, goos, goarch string, arch asm.Arch) (*plan9asm.File, []byte, error) {
	var file *asm.File
	var expanded []byte
	var err error
	if preprocess.HasDirective(src) {
		file, expanded, err = parseHeaders(pkg, src, filename, goos, goarch, arch)
	} else {
		file, err = pkg.ParseAssembly(src, goarch)
	}
	if errors.Is(err, asm.ErrEmptyFile) {
		return nil, nil, nil
	}
	if err == nil && goos == "windows" && goarch == "386" {
		commandIncludes.load()
		if commandIncludes.err != nil {
			return nil, nil, commandIncludes.err
		}
		file.SourceGoVersion = commandIncludes.version
	}
	return file, expanded, err
}

func EmptyModule(triple string) llvm.Module {
	mod := llvm.GlobalContext().NewModule("plan9asm")
	mod.SetTarget(triple)
	return mod
}

func parseHeaders(pkg plan9asm.GoPackage, src []byte, filename, goos, goarch string, arch asm.Arch) (*plan9asm.File, []byte, error) {
	expanded, err := plan9asm.PreprocessAssemblySource(string(src), plan9asm.AssemblyPreprocessOptions{
		FileName: filename, Defines: plan9asm.GoAssemblerDefines(goos, goarch),
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if name == "go_asm.h" {
				data, err := plan9asm.GoAssemblyHeader(pkg, goarch)
				return name, data, err
			}
			local := filepath.Join(filepath.Dir(parent), name)
			data, err := os.ReadFile(local)
			if !os.IsNotExist(err) {
				return local, data, err
			}
			return commandIncludes.read(name)
		},
	})
	if err != nil {
		return nil, nil, err
	}
	file, err := asm.ParsePreprocessed(arch, expanded)
	return file, []byte(expanded), err
}
