//go:build go1.27

package main

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinux(t *testing.T) {
	compileOneX86SDKOriginalMapsLiteralMinimumSource(t, "linux")
}

func TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceDarwin(t *testing.T) {
	compileOneX86SDKOriginalMapsLiteralMinimumSource(t, "darwin")
}

func TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceWindows(t *testing.T) {
	compileOneX86SDKOriginalMapsLiteralMinimumSource(t, "windows")
}

func TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinuxPublicCLI(t *testing.T) {
	runPublicCLIX86SDKOriginalMapsLiteralMinimumSource(t, "linux")
}

func compileOneX86SDKOriginalMapsLiteralMinimumSource(t *testing.T, goos string) {
	t.Helper()
	setX86SDKNumericalCLIProfile(t, "effective-defaults")
	t.Setenv("GOOS", goos)
	ctx := arm64PrivateCLIContext(t)
	directory, originals := mapsLiteralMinimumOriginalSourceInputs(t)
	input := filepath.Join(directory, "memhash_amd64.s")
	original := originals["memhash_amd64.s"]
	actual, err := packages.Load(&packages.Config{Context: ctx, Dir: directory, Env: os.Environ(), Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedModule | packages.NeedDeps | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes}, ".")
	if err != nil || len(actual) != 1 || len(actual[0].Errors) != 0 {
		t.Fatalf("actual complete SDK load: %v %+v", err, actual)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = ctx
	config.x86CallerSelections = captureX86CallerSelections(actual, goos+"/amd64", nil)
	output := filepath.Join(t.TempDir(), "maps.ll")
	if err := compileOne(actual[0], plan9asm.ArchAMD64, goos, "amd64", targetTriple(goos, "amd64"), asmTask{PkgPath: actual[0].PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal("whole original SDK source/minimum/LLVM object", err)
	}
	ir, err := os.ReadFile(output)
	if err != nil || strings.Count(string(ir), "define ") != 2 || !strings.Contains(string(ir), "external global [128 x i8]") || strings.Count(string(ir), "internal constant [256 x i8]") != 2 {
		t.Fatal("whole original TEXT/DATA/runtime mutable source publication differs", err)
	}
	if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || info.Size() == 0 {
		t.Fatal("LLVM22 complete object absent", err)
	}
	verifyMapsLiteralMinimumOriginalSourceInputs(t, directory, originals)
	t.Logf("complete SDK source SHA256=%x; all original TEXT/DATA plus compiler-owned helper, logical LLVM object only, not native SDK entry or execution", sha256.Sum256(original))
}

func runPublicCLIX86SDKOriginalMapsLiteralMinimumSource(t *testing.T, goos string) {
	t.Helper()
	setX86SDKNumericalCLIProfile(t, "effective-defaults")
	t.Setenv("GOOS", goos)
	ctx := arm64PrivateCLIContext(t)
	directory, originals := mapsLiteralMinimumOriginalSourceInputs(t)
	folder, report := t.TempDir(), filepath.Join(t.TempDir(), "report.json")
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal([]string{"-targets=" + goos + "/amd64", "-patterns=.", "-compile", "-keep-obj", "-strict-load", "-out=" + folder, "-report=" + report, "-repo-root=" + repository})
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, directory, append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(args)), os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
	if err != nil {
		t.Fatalf("genuine original package public CLI: %v\n%s%s", err, stdout, stderr)
	}
	raw, err := os.ReadFile(report)
	var decoded matrixReport
	if err != nil || json.Unmarshal(raw, &decoded) != nil || decoded.Success != 2 || decoded.Failed != 0 || decoded.NotApplicable != 0 || decoded.TotalAsm != 2 || decoded.TotalTargets != 1 || len(decoded.Targets) != 1 {
		t.Fatalf("genuine complete package denominator/result differs: %v\n%s", err, raw)
	}
	target := decoded.Targets[0]
	if target.Goos != goos || target.Goarch != "amd64" || target.Success != 2 || target.TotalAsm != 2 ||
		target.Failed != 0 || target.NotApplicable != 0 || len(target.AsmFiles) != 2 ||
		len(target.AsmPackages) != 1 || target.AsmPackages[0] != "internal/runtime/maps" {
		t.Fatal("public CLI changed its actual complete package/target selection", target)
	}
	seen := map[string]bool{}
	for _, input := range target.AsmFiles {
		name := filepath.Base(input)
		if originals[name] == nil || seen[name] {
			t.Fatal("public CLI omitted, duplicated or replaced a complete original member", input)
		}
		seen[name] = true
		output := filepath.Join(folder, "internal", "runtime", "maps", name+".ll")
		ir, err := os.ReadFile(output)
		if err != nil || strings.Count(string(ir), "define ") != 2 {
			t.Fatal("public CLI complete original definitions/compiler-owned helper differ", name, err)
		}
		if name == "memhash_amd64.s" && (!strings.Contains(string(ir), "external global [128 x i8]") || strings.Count(string(ir), "internal constant [256 x i8]") != 2) {
			t.Fatal("public CLI changed complete original readonly DATA/mutable runtime storage", name)
		}
		if info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o"); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatal("public CLI complete LLVM22 object absent", name, err)
		}
	}
	verifyMapsLiteralMinimumOriginalSourceInputs(t, directory, originals)
	t.Log("genuine public CLI: both original SDK ASM members/all three TEXTs plus compiler-owned helper, all DATA, strict full package denominator, nonempty LLVM22 objects; no native SDK execution claim")
}

func mapsLiteralMinimumOriginalSourceInputs(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	directory := filepath.Join(runtime.GOROOT(), "src", "internal", "runtime", "maps")
	originals := map[string][]byte{}
	for _, name := range []string{"memhash_amd64.s", "memhash_nosimd_amd64.s"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal("complete original SDK member absent", name, err)
		}
		originals[name] = data
	}
	return directory, originals
}

func verifyMapsLiteralMinimumOriginalSourceInputs(t *testing.T, directory string, originals map[string][]byte) {
	t.Helper()
	for name, original := range originals {
		after, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
			t.Fatal("original complete SDK member changed", name, err)
		}
		t.Logf("complete original SDK member=%s SHA256=%x", name, sha256.Sum256(original))
	}
}
