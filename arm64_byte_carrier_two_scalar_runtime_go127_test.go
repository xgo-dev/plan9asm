//go:build go1.27

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func arm64ByteCarrierTwoScalarRuntimeFamily(t *testing.T, goos, triple, llc string, compiler, runner []string) {
	t.Helper()
	widths := append(arm64NativeResultTailCases(), arm64NativeResultTailCase{op: "MOVW", resultBits: 32, storeBits: 32})
	directory, packagePath := arm64ByteCarrierTwoScalarFixture(t, widths)
	// This independent exact-width control actually consumes the second
	// parameter. An unused argument or IR spelling alone cannot prove transport.
	for name, extra := range map[string]string{
		"decl.go":          "func read_spare(input uint64, spare uint32) (result uint32)\n",
		"original_arm64.s": "TEXT ·read_spare(SB),4,$0-20\nMOVWU spare+8(FP),R0\nMOVW R0,result+16(FP)\nRET\n",
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
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	inputs := arm64PaddingRuntimeInputs()
	var original strings.Builder
	original.WriteString("package twoscalarcarrier\nimport \"testing\"\nfunc TestOriginalTwoScalarFamily(t *testing.T) {\n")
	original.WriteString("for _, spare := range []uint32{0,1,0x123456,0x89abcdef,0xffffffff} {\n" +
		"if read_spare(0x123456789abcdef0, spare) != spare { t.Fatal(\"second parameter transport mismatch\") }\n}\n")
	for _, width := range widths {
		name := strings.ToLower(width.name())
		resultMask := ^uint64(0) >> uint(64-width.resultBits)
		storeMask := ^uint64(0) >> uint(64-width.storeBits)
		for _, input := range inputs {
			fmt.Fprintf(&original, `{ value,native,guard,paramgap := observe_%s(0x%x)
if value != 0x%x || native != 0x%x || guard != 0x7ac35ef012345678 || paramgap != 0xabad1dea00123456 {
    t.Fatal("%s native result, adjacent guard or parameter/gap canary mismatch")
} }
`, name, input, input&resultMask, uint64(0xfeedfacecafebeef)&^storeMask|input&storeMask, name)
		}
	}
	marker := fmt.Sprintf("ACTUAL_TWO_SCALAR_CARRIER_FAMILY %d", len(widths)*len(inputs))
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
	arguments := []string{"test", "-p=1", "-mod=readonly", "-run=^TestOriginalTwoScalarFamily$", "-count=1", "-v"}
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
	if err != nil || strings.Count(string(output), marker) != 1 || !strings.Contains(string(output), "--- PASS: TestOriginalTwoScalarFamily") {
		t.Fatalf("original Go two-scalar whole-cell/canary precondition: %v\n%s", err, output)
	}
	t.Logf("actual original Go %s two-scalar observations: %d", request.Target, len(widths)*len(inputs))
	source, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatalf("producer precondition: %v", err)
	}
	defer source.Close()
	pkg := mustGoPackage(t, packagePath, string(declarations))
	checks, driver := arm64ByteCarrierTwoScalarRuntimeChecks(packagePath, widths, inputs)
	for _, api := range []string{"text", "module", "Go"} {
		for _, optimization := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", api, optimization), func(t *testing.T) {
				ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), triple, nil)
				if err != nil {
					t.Fatal(err)
				}
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "two_scalar_carrier_family", triple, ir+checks, driver, runner, optimization)
				t.Logf("actual LLVM22 %s O%d two-scalar observations: %d", api, optimization, len(widths)*len(inputs))
			})
		}
	}
}

func arm64ByteCarrierTwoScalarRuntimeChecks(packagePath string, widths []arm64NativeResultTailCase, inputs []uint64) (string, string) {
	var checks, driver strings.Builder
	driver.WriteString("#include <stdint.h>\nextern uint32_t observe_second_parameter(uint32_t);\n")
	fmt.Fprintf(&checks, `
define i32 @observe_second_parameter(i32 %%spare) {
    %%result = call i32 %s(i64 1311768467463790320, i32 %%spare)
    ret i32 %%result
}
`, llvmGlobal(packagePath+".read_spare"))
	for _, width := range widths {
		name := strings.ToLower(width.name())
		resultMask := ^uint64(0) >> uint(64-width.resultBits)
		storeMask := ^uint64(0) >> uint(64-width.storeBits)
		fmt.Fprintf(&driver, "extern int32_t check_%s(uint64_t);\n", name)
		// C only calls an explicit scalar status shim. LLVM aggregate return
		// conventions are not assumed to match a C struct ABI.
		fmt.Fprintf(&checks, `
define i32 @check_%s(i64 %%input) {
    %%scalar = call i%d %s(i64 %%input, i32 1193046)
    %%scalar_wide = zext i%d %%scalar to i64
    %%result = call { i64, i64, i64, i64 } %s(i64 %%input)
    %%value = extractvalue { i64, i64, i64, i64 } %%result, 0
    %%native = extractvalue { i64, i64, i64, i64 } %%result, 1
    %%guard = extractvalue { i64, i64, i64, i64 } %%result, 2
    %%paramgap = extractvalue { i64, i64, i64, i64 } %%result, 3
    %%low = and i64 %%input, %d
    %%store = and i64 %%input, %d
    %%expected = or i64 %%store, %d
    %%scalar_ok = icmp eq i64 %%scalar_wide, %%low
    %%typed_ok = icmp eq i64 %%value, %%low
    %%native_ok = icmp eq i64 %%native, %%expected
    %%guard_ok = icmp eq i64 %%guard, %d
    %%paramgap_ok = icmp eq i64 %%paramgap, %d
    %%values = and i1 %%scalar_ok, %%typed_ok
    %%bytes = and i1 %%native_ok, %%guard_ok
    %%both = and i1 %%values, %%bytes
    %%all = and i1 %%both, %%paramgap_ok
    %%status = select i1 %%all, i32 0, i32 1
    ret i32 %%status
}
`, name, width.resultBits, llvmGlobal(packagePath+"."+name), width.resultBits,
			llvmGlobal(packagePath+".observe_"+name), resultMask, storeMask,
			uint64(0xfeedfacecafebeef)&^storeMask, uint64(0x7ac35ef012345678), uint64(0xabad1dea00123456))
	}
	driver.WriteString("int main(void) {\n" +
		"static const uint32_t spares[] = {0,1,0x123456,0x89abcdef,0xffffffff};\n" +
		"for (unsigned i=0; i<sizeof(spares)/sizeof(spares[0]); i++) {\n" +
		"if (observe_second_parameter(spares[i]) != spares[i]) return 1;\n}\n" +
		"static const uint64_t inputs[] = {\n")
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
