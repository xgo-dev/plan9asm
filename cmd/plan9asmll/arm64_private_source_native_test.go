//go:build arm64 && (darwin || linux)

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

func TestCompileOneARM64PrivateSourceNativeNumericalOracle(t *testing.T) {
	const declaration = "package p\nfunc Run(uint64) uint64\n"
	pkg, input := arm64PrivateCLIPackage(t, declaration, arm64PrivateCLISource)
	dir := t.TempDir()
	const goMain = `package main
func Run(uint64) uint64
func main() {
    for _, x := range []uint64{0, 1, 123, 0x8000000000000000, ^uint64(0)} {
        y := x + 1
        if x == ^uint64(0) { y++ }
        if Run(x) != (x*y)^7 { panic("original source continuation result differs") }
    }
}
`
	for name, contents := range map[string]string{
		"go.mod":  "module originalcontinuation\n\ngo 1.20\n",
		"main.go": goMain, "original_arm64.s": arm64PrivateCLISource,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	original := filepath.Join(dir, "original")
	stdout, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, env,
		"go", "build", "-p=2", "-o", original, ".")
	if err != nil {
		t.Fatalf("build actual original Go source: %v\n%s%s", err, stdout, stderr)
	}
	stdout, stderr, err = gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, env, original)
	if err != nil {
		t.Fatalf("execute actual original Go source: %v\n%s%s", err, stdout, stderr)
	}

	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	output := filepath.Join(dir, "private.ll")
	if err := compileOne(pkg, plan9asm.ArchARM64, runtime.GOOS, "arm64", targetTriple(runtime.GOOS, "arm64"),
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal("LLVM22 clang required:", err)
	}
	stdout, stderr, err = gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(), clang, "--version")
	if err != nil || !regexp.MustCompile(`\bclang version 22\.`).Match(stdout) {
		t.Fatalf("LLVM22 clang required: %v\n%s%s", err, stdout, stderr)
	}
	label := pkg.PkgPath + ".Run"
	if runtime.GOOS == "darwin" {
		label = "_" + label
	}
	main := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern uint64_t Source(uint64_t) __asm__(%q);
int main(void) {
    uint64_t rows[] = {0, 1, 123, UINT64_C(0x8000000000000000), UINT64_MAX};
    for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        uint64_t x = rows[i];
        uint64_t y = x + 1 + (x == UINT64_MAX);
        uint64_t want = (x * y) ^ 7;
        uint64_t got = Source(x);
        if (got != want) {
            fprintf(stderr, "source continuation differs at row %%u\n", i);
            return 1;
        }
    }
    return 0;
}
`, label)
	mainPath, binary := filepath.Join(dir, "oracle.c"), filepath.Join(dir, "translated")
	if err := os.WriteFile(mainPath, []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	object := strings.TrimSuffix(output, ".ll") + ".o"
	arguments := []string{"-O2", mainPath, object, "-o", binary}
	if runtime.GOOS == "darwin" {
		flags, err := nativeoracle.DarwinClangFlags(arm64PrivateCLIContext(t), os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		arguments = append(flags, arguments...)
	}
	stdout, stderr, err = gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(),
		clang, arguments...)
	if err != nil {
		t.Fatalf("link actual translated source: %v\n%s%s", err, stdout, stderr)
	}
	stdout, stderr, err = gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(), binary)
	if err != nil {
		t.Fatalf("execute actual translated source: %v\n%s%s", err, stdout, stderr)
	}
}
