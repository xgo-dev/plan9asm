package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func x86CPUQueryBuildOriginal386(t *testing.T, raw bool) x87IA32Executable {
	t.Helper()
	declarations, assembly := x86CPUQueryRuntimeFixtures(raw, "386")
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module cpuquery386\n\ngo 1.20\n", "main.go": x86CPUQuery386OriginalDriver(),
		"decl.go": "package main\n" + declarations, "query_386.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-go")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=386", "GOTOOLCHAIN=local",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	sealed, err := x87IA32StaticExecutable(executable)
	if err != nil || sealed.verify() != nil {
		t.Fatalf("unchanged IA32 query reference did not compile as stable ELF32: %v", err)
	}
	return sealed
}

// This portable axis compiles unchanged original Go objects, not a native
// execution pass. The required Linux counterpart runs these same programs.
func TestX86CPUQuery386OriginalNativeReferenceCompiles(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			_ = x86CPUQueryBuildOriginal386(t, raw)
		})
	}
}

func TestX86CPUQuery386RuntimeSourceObjects(t *testing.T) {
	x86CPUQueryRuntimeSourceObjects(t, "386", []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"})
}

func TestX86CPUQueryAMD64RuntimeSourceObjects(t *testing.T) {
	x86CPUQueryRuntimeSourceObjects(t, "amd64", []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	})
}

func x86CPUQueryRuntimeSourceObjects(t *testing.T, arch string, triples []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, raw := range []bool{false, true} {
		declarations, source := x86CPUQueryRuntimeFixtures(raw, arch)
		for _, triple := range triples {
			x86LEAActualTargetGoObject(t, arch, triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/raw=%t/%s", triple, raw, api), func(t *testing.T) {
					ir := x86CPUQueryIRFromDeclaration(t, source, declarations, arch, triple, api)
					for _, op := range []string{"cpuid", "xgetbv"} {
						if strings.Count(ir, "asm sideeffect \""+op+"\"") != 2 {
							t.Fatal("original native query reference lost a complete opcode", op)
						}
					}
					compileLLVMToObject(t, llc, triple, "query.ll", "query.o", ir)
					compileLLVMToObject(t, llc, triple, "query-opt.ll", "query-opt.o", x86UndefinedTrapOptimizedIR(t, ir))
				})
			}
		}
	}
}
