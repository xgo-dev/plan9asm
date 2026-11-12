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

// The complete original function combines initialized scalar shifts, a live
// Go-defined CPU-choice byte and independently initialized assembly literals.
// Child package directories do not make its own direct compiler inputs flat.
func TestCompileOneOriginalSDKMathExpScalarShiftAndNumericalSource(t *testing.T) {
	compileOriginalSDKX86FamilySource(t, "math", "math", "exp_amd64.s",
		"CMPB ·useFMA(SB), $1", "exprodata<>")
}

// Keep the whole original field multiplication source, rather than extracting
// its first MULQ or substituting a synthetic register-source program.
func TestCompileOneOriginalSDKFieldImplicitMultiplySource(t *testing.T) {
	const packagePath = "crypto/internal/fips140/edwards25519/field"
	compileOriginalSDKX86FamilySource(t, packagePath, packagePath, "fe_amd64.s",
		"TEXT ·feMul(SB)", "MULQ (BX)", "IMUL3Q")
}

// Retain all three original bigmod functions and both CPU-choice paths. The
// FIPS text-kind listing is an observation, not a substituted SB/entry role.
func TestCompileOneOriginalSDKBigmodNativeListingSource(t *testing.T) {
	const packagePath = "crypto/internal/fips140/bigmod"
	compileOriginalSDKX86FamilySource(t, packagePath, packagePath, "nat_amd64.s",
		"CMPB ·supportADX+0(SB), $0x01", "MULXQ", "ADCXQ", "ADOXQ")
}

func compileOriginalSDKX86FamilySource(t *testing.T, relativeDirectory, packagePath, assemblyFile string, witnesses ...string) {
	t.Helper()
	setX86SDKNumericalCLIProfile(t, "explicit")
	ctx := arm64PrivateCLIContext(t)

	directory := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(relativeDirectory))
	input := filepath.Join(directory, assemblyFile)
	original, err := os.ReadFile(input)
	if err != nil {
		t.Fatal("complete original SDK source is absent", err)
	}
	for _, witness := range witnesses {
		if !strings.Contains(string(original), witness) {
			t.Fatalf("complete original SDK source %s lacks witness %q", assemblyFile, witness)
		}
	}
	environment := os.Environ()
	pkgs, err := packages.Load(&packages.Config{
		Context: ctx, Dir: directory, Env: environment,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedModule | packages.NeedDeps | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes,
	}, ".")
	if err != nil || len(pkgs) != 1 || pkgs[0].PkgPath != packagePath || len(pkgs[0].Errors) != 0 {
		t.Fatalf("actual original SDK selection failed: %v %+v", err, pkgs)
	}
	selection, stderr, err := gotoolprofile.RunBounded(ctx, directory, environment, "go",
		"list", "-export", "-compiled", "-mod=readonly", "-json", ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("stock Go failed the original package: %v\n%s%s", err, selection, stderr)
	}
	t.Logf("complete original ASM SHA256=%x; actual stock-Go archive selection SHA256=%x",
		sha256.Sum256(original), sha256.Sum256(selection))
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = ctx
	config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/amd64", nil)
	output := filepath.Join(t.TempDir(), strings.TrimSuffix(assemblyFile, ".s")+".ll")
	if err := compileOne(pkgs[0], plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal("original SDK source did not retain its complete LLVM object", err)
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
		t.Fatal("original SDK source changed during translation", err)
	}
	object, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o")
	if err != nil || !object.Mode().IsRegular() || object.Size() == 0 {
		t.Fatal("complete original SDK LLVM22 object is absent", err)
	}
}
