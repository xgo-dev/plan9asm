//go:build go1.27

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ByteCarrierExactWidthControl(t *testing.T, directory string, widths []arm64NativeResultTailCase) []arm64NativeResultTailCase {
	t.Helper()
	control := arm64NativeResultTailCase{op: "MOVW", resultBits: 32, storeBits: 32}
	controlName := strings.ToLower(control.name())
	for name, extra := range map[string]string{
		"decl.go": strings.ReplaceAll(control.declaration(), control.name(), controlName) +
			"func observe_" + controlName + "(input uint64) (value,native,guard uint64)\n",
		"original_arm64.s": strings.ReplaceAll(control.source()+arm64NativeResultTailObserver(control), control.name(), controlName),
	} {
		filename := filepath.Join(directory, name)
		original, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, append(original, []byte(extra)...), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return append(widths, control)
}

func arm64ByteCarrierRuntimeFamily(t *testing.T, goos, triple, llc string, compiler, runner []string) {
	t.Helper()
	directory, packagePath, widths := arm64ByteCarrierFixture(t)
	widths = arm64ByteCarrierExactWidthControl(t, directory, widths)
	goSource, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := arm64PaddingRuntimeInputs()
	var original strings.Builder
	original.WriteString("package carrierfixture\nimport \"testing\"\nfunc TestOriginalCarrierFamily(t *testing.T) {\n")
	for _, width := range widths {
		name := strings.ToLower(width.name())
		for _, input := range inputs {
			resultMask := ^uint64(0) >> uint(64-width.resultBits)
			storeMask := ^uint64(0) >> uint(64-width.storeBits)
			fmt.Fprintf(&original, `{ value,native,guard := observe_%s(0x%x)
if value != 0x%x || native != 0x%x || guard != 0x7ac35ef012345678 { t.Fatal("%s native/canary mismatch") } }
`, name, input, input&resultMask, uint64(0xfeedfacecafebeef)&^storeMask|input&storeMask, name)
		}
	}
	marker := fmt.Sprintf("ACTUAL_BYTE_CARRIER_FAMILY %d", len(widths)*len(inputs))
	fmt.Fprintf(&original, "t.Log(%q)\n}\n", marker)
	if err := os.WriteFile(filepath.Join(directory, "original_test.go"), []byte(original.String()), 0600); err != nil {
		t.Fatal(err)
	}
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	request.Target = goos + "/arm64"
	for index, pair := range request.Environment {
		if strings.HasPrefix(pair, "GOOS=") {
			request.Environment[index] = "GOOS=" + goos
		}
	}
	lease, release := runtimeOracleStageContext(t)
	defer release()
	arguments := []string{"test", "-p=1", "-mod=readonly", "-run=^TestOriginalCarrierFamily$", "-count=1", "-v"}
	if len(runner) != 0 {
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "-exec="+quoted)
	}
	command := exec.CommandContext(lease, request.GoBinary, append(arguments, ".")...)
	command.Dir, command.Env = directory, request.Environment
	output, err := runtimeOracleCombinedOutput(lease, command)
	if err != nil || strings.Count(string(output), marker) != 1 || !strings.Contains(string(output), "--- PASS: TestOriginalCarrierFamily") {
		t.Fatalf("unchanged original whole-family native bytes/canary: %v\n%s", err, output)
	}
	t.Logf("actual original Go %s observations: %d", request.Target, len(widths)*len(inputs))
	source, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	pkg := mustGoPackage(t, packagePath, string(goSource))
	for _, api := range []string{"text", "module", "Go"} {
		for _, optimization := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", api, optimization), func(t *testing.T) {
				ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), triple, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ir, "store volatile i64") || !strings.Contains(ir, "store volatile i16") ||
					!strings.Contains(ir, "store volatile i32") || !strings.Contains(ir, "align 1") {
					t.Fatal("native memory widths and exact alignment were not retained")
				}
				checks, driver := arm64ByteCarrierRuntimeChecks(packagePath, widths, inputs)
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "byte_carrier_family", triple, ir+checks, driver, runner, optimization)
				t.Logf("actual LLVM22 %s O%d observations: %d", api, optimization, len(widths)*len(inputs))
			})
		}
	}
}

func arm64ByteCarrierTranslateAPI(t *testing.T, api string, source *GoARM64ByteCarrierSource, pkg GoPackage, assembly, triple string, mutate func(*File, *Options, *GoModuleOptions)) (string, error) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	file, err := Parse(ArchARM64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := testResolveSym(pkg.Path)
	signatures, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: signatures, ARM64ByteCarrierSource: source}
	goOptions := GoModuleOptions{GOOS: strings.Split(source.request.Target, "/")[0], GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: resolve, ARM64ByteCarrierSource: source}
	if mutate != nil {
		mutate(file, &options, &goOptions)
	}
	if api == "text" {
		return Translate(file, options)
	}
	if api == "module" {
		module, err := TranslateModuleInContext(context, file, options)
		if !module.IsNil() {
			defer module.Dispose()
			return module.String(), err
		}
		return "", err
	}
	translated, err := translateGoModuleInContext(context, pkg, []byte(assembly), goOptions)
	if translated != nil && !translated.Module.IsNil() {
		defer translated.Module.Dispose()
		return translated.Module.String(), err
	}
	return "", err
}

func arm64ByteCarrierRuntimeChecks(packagePath string, widths []arm64NativeResultTailCase, inputs []uint64) (string, string) {
	var checks, driver strings.Builder
	driver.WriteString("#include <stdint.h>\n")
	for _, width := range widths {
		name := strings.ToLower(width.name())
		resultMask := ^uint64(0) >> uint(64-width.resultBits)
		storeMask := ^uint64(0) >> uint(64-width.storeBits)
		fmt.Fprintf(&driver, "extern int32_t check_%s(uint64_t);\n", name)
		fmt.Fprintf(&checks, `
define i32 @check_%s(i64 %%input) {
    %%scalar = call i%d %s(i64 %%input)
    %%scalar_wide = zext i%d %%scalar to i64
    %%result = call { i64, i64, i64 } %s(i64 %%input)
    %%value = extractvalue { i64, i64, i64 } %%result, 0
    %%native = extractvalue { i64, i64, i64 } %%result, 1
    %%guard = extractvalue { i64, i64, i64 } %%result, 2
    %%low = and i64 %%input, %d
    %%store = and i64 %%input, %d
    %%expected = or i64 %%store, %d
    %%scalar_ok = icmp eq i64 %%scalar_wide, %%low
    %%typed_ok = icmp eq i64 %%value, %%low
    %%native_ok = icmp eq i64 %%native, %%expected
    %%guard_ok = icmp eq i64 %%guard, %d
    %%values = and i1 %%scalar_ok, %%typed_ok
    %%bytes = and i1 %%native_ok, %%guard_ok
    %%all = and i1 %%values, %%bytes
    %%status = select i1 %%all, i32 0, i32 1
    ret i32 %%status
}
`, name, width.resultBits, llvmGlobal(packagePath+"."+name), width.resultBits,
			llvmGlobal(packagePath+".observe_"+name), resultMask, storeMask,
			uint64(0xfeedfacecafebeef)&^storeMask, uint64(0x7ac35ef012345678))
	}
	driver.WriteString("int main(void) {\nstatic const uint64_t inputs[] = {\n")
	for _, input := range inputs {
		fmt.Fprintf(&driver, "UINT64_C(0x%x),\n", input)
	}
	driver.WriteString("};\nfor (unsigned i=0; i<sizeof(inputs)/sizeof(inputs[0]); i++) {\n")
	for _, width := range widths {
		fmt.Fprintf(&driver, "if (check_%s(inputs[i])) return 1;\n", strings.ToLower(width.name()))
	}
	driver.WriteString("}\nreturn 0;\n}\n")
	return checks.String(), driver.String()
}
