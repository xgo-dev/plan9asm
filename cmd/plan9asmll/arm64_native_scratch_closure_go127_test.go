//go:build go1.27

package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// These are original, first-party ABI0 source bodies, not replacements for a
// downloaded library. Every positive needs an actual selected-package/native
// closure producer; a declaration alone is deliberately insufficient.
func arm64NativeScratchClosureSource(callee string) string {
	return `#include "textflag.h"
TEXT ·Scratch(SB),0,$32904-16
    MOVD n+0(FP),R1
    MOVD R1,8(RSP)
    CALL ·Value(SB)
    MOVD 16(RSP),R2
    MOVD R2,ret+8(FP)
    RET
` + callee
}

func arm64NativeScratchClosureFixture(t *testing.T, source, declarations string) (*packages.Package, string, compileConfig) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"go.mod":        "module example.invalid/scratchclosure\n\ngo 1.20\n",
		"value.go":      "package scratchclosure\n" + declarations + "\nfunc Scratch(n uint64) uint64\n",
		"value_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	context := arm64PrivateCLIContext(t)
	environment, err := ordinaryPackageEnvironment("linux", "arm64", append(os.Environ(), "CGO_ENABLED=0",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOPACKAGESDRIVER=off"))
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := gotoolprofile.RunBounded(context, directory, environment, "go",
		"list", "-export", "-compiled", "-mod=readonly", "-json", ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual original package export: %v\n%s%s", err, stdout, stderr)
	}
	t.Logf("original source SHA256=%x; actual original Go package selection:\n%s", sha256.Sum256([]byte(source)), stdout)
	selected, err := packages.Load(&packages.Config{
		Context: context, Dir: directory, Env: environment,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedModule | packages.NeedDeps | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax,
	}, ".")
	if err != nil || len(selected) != 1 || len(selected[0].Errors) != 0 || selected[0].IllTyped {
		t.Fatalf("actual complete source load: %v; %+v", err, selected)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = context
	config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(selected, "linux/arm64", environment)
	input := filepath.Join(directory, "value_arm64.s")
	object := filepath.Join(directory, "original.o")
	listing, stderr, err := gotoolprofile.RunBounded(context, directory, environment, "go",
		"tool", "asm", "-S", "-p", selected[0].PkgPath, "-I", directory,
		"-I", filepath.Join(runtime.GOROOT(), "pkg", "include"), "-o", object, input)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual original native source/object: %v\n%s%s", err, listing, stderr)
	}
	t.Logf("actual original Go assembly listing:\n%s", listing)
	return selected[0], input, config
}

func TestCompileOneARM64NativeScratchClosedCalleeFamily(t *testing.T) {
	for _, test := range []struct {
		name, body, declarations string
	}{
		{
			name: "scalar_gp",
			body: `TEXT ·Value(SB),NOSPLIT,$0-16
    MOVD n+0(FP),R1
    ADD $1,R1
    MOVD R1,ret+8(FP)
    RET
`,
			declarations: "func Value(n uint64) uint64\n",
		},
		{
			name: "bounded_local_pair",
			body: `TEXT ·Value(SB),NOSPLIT,$32-16
    MOVD n+0(FP),R1
    MOVD $7,R2
    STP (R1,R2),16(RSP)
    LDP 16(RSP),(R3,R4)
    ADD R4,R3
    MOVD R3,ret+8(FP)
    RET
`,
			declarations: "func Value(n uint64) uint64\n",
		},
		{
			name: "full_cfg",
			body: `TEXT ·Value(SB),NOSPLIT,$0-16
    MOVD n+0(FP),R1
    CBZ R1,zero
    SUB $1,R1
    B done
zero:
    MOVD $9,R1
done:
    MOVD R1,ret+8(FP)
    RET
`,
			declarations: "func Value(n uint64) uint64\n",
		},
		{
			name: "transitive_same_package",
			body: `TEXT ·Value(SB),NOSPLIT,$24-16
    MOVD n+0(FP),R1
    MOVD R1,8(RSP)
    CALL ·Leaf(SB)
    MOVD 16(RSP),R2
    MOVD R2,ret+8(FP)
    RET
TEXT ·Leaf(SB),NOSPLIT,$0-16
    MOVD n+0(FP),R1
    ADD $3,R1
    MOVD R1,ret+8(FP)
    RET
`,
			declarations: "func Value(n uint64) uint64\nfunc Leaf(n uint64) uint64\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := arm64NativeScratchClosureSource(test.body)
			pkg, input, config := arm64NativeScratchClosureFixture(t, source, test.declarations)
			output := filepath.Join(t.TempDir(), "closed.ll")
			if err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatalf("complete original source/native closure lacks its producer/consumer: %v", err)
			}
			if info, err := os.Lstat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("closed callee did not produce its eligible LLVM22 object: %v", err)
			}
		})
	}
}

func TestCompileOneARM64NativeScratchUnknownExternalRemainsContext(t *testing.T) {
	source := arm64NativeScratchClosureSource("")
	pkg, input, config := arm64NativeScratchClosureFixture(t, source, "func Value(n uint64) uint64\n")
	output := filepath.Join(t.TempDir(), "unbound.ll")
	err := compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
	if err == nil || !strings.Contains(err.Error(), "unbound original Go memory scratch") {
		t.Fatalf("unbound external source borrowed a declaration as a scratch certificate: %v", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); !os.IsNotExist(err) {
		t.Fatalf("unbound source acquired an eligible LLVM object: %v", err)
	}
	t.Logf("retained precise Context: %v", err)
}
