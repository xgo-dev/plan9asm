package plan9asm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadGoAssemblySourceExpandsToolchainHeadersInTrimpathBinary(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "funcdata_amd64.s")
	source := `#include "funcdata.h"
TEXT ·metadata(SB),$0-0
 GO_ARGS
 GO_RESULTS_INITIALIZED
 NO_LOCAL_POINTERS
 RET
`
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	program := `package main
import (
    "fmt"
    "os"
    plan9asm "github.com/xgo-dev/plan9asm"
)
func main() {
    source, err := plan9asm.ReadGoAssemblySource(os.Args[1], os.Args[2])
    if err != nil {
        panic(err)
    }
    file, err := plan9asm.Parse(plan9asm.ArchAMD64, string(source))
    if err != nil {
        panic(err)
    }
    for _, ins := range file.Funcs[0].Instrs {
        fmt.Println(ins.Op)
    }
}
`
	mainFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(mainFile, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "read-asm")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath", "-o", bin, mainFile)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build trimpath reader: %v\n%s", err, out)
	}
	run := exec.Command(bin, asm, dir)
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "GOROOT=") {
			run.Env = append(run.Env, item)
		}
	}
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run trimpath reader: %v\n%s", err, out)
	}
	want := "TEXT\nFUNCDATA\nPCDATA\nFUNCDATA\nRET\n"
	if string(out) != want {
		t.Fatalf("trimpath reader ops = %q, want %q", out, want)
	}
}

func TestEvalGoAssemblyPathWindowsGOROOTLinkFallback(t *testing.T) {
	goRoot := t.TempDir()
	file := filepath.Join(goRoot, "src", "runtime", "asm.s")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("RET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evalErr := errors.New("cross-volume link cannot be evaluated")
	failingEval := func(string) (string, error) { return "", evalErr }
	got, err := evalGoAssemblyPathForOS(file, "windows", goRoot, failingEval)
	if err != nil {
		t.Fatalf("trusted existing GOROOT path fallback error = %v", err)
	}
	want, err := filepath.Abs(file)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(want) {
		t.Fatalf("trusted existing GOROOT path fallback = %q, want %q", got, want)
	}

	outside := filepath.Join(t.TempDir(), "outside.s")
	if err := os.WriteFile(outside, []byte("RET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evalGoAssemblyPathForOS(outside, "windows", goRoot, failingEval); !errors.Is(err, evalErr) {
		t.Fatalf("outside-GOROOT fallback error = %v, want %v", err, evalErr)
	}
}

func TestReadGoAssemblySourceExpandsNestedLocalHeaders(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ops.h", "#define SAVE(offset) MOVD R19, offset(RSP)\n")
	write("abi.h", "#include \"ops.h\"\n")
	write("entry_arm64.s", "#include \"abi.h\"\nTEXT entry(SB),$0-0\nSAVE(8)\nRET\n")

	src, err := ReadGoAssemblySource(filepath.Join(dir, "entry_arm64.s"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `#include "abi.h"`) || !strings.Contains(string(src), "#define SAVE") {
		t.Fatalf("nested header was not expanded:\n%s", src)
	}
	if _, err := ParseWithDefines(ArchARM64, string(src), GoAssemblerDefines("linux", "arm64")); err != nil {
		t.Fatalf("expanded assembly did not parse: %v\n%s", err, src)
	}
}
