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

func arm64SignedCarrierRuntime(t *testing.T, goos, triple, llc string, compiler, runner []string) {
	t.Helper()
	directory, packagePath, cases := arm64SignedCarrierMatrixFixture(t)
	inputs := arm64PaddingRuntimeInputs()
	var original strings.Builder
	original.WriteString("package signedcarriermatrix\nimport \"testing\"\nfunc TestOriginalSignedCarrier(t *testing.T) {\ninputs := []uint64{\n")
	for _, input := range inputs {
		fmt.Fprintf(&original, "0x%x,\n", input)
	}
	original.WriteString("}\n")
	for _, row := range cases {
		args, gap := "input", uint64(0)
		if row.twoParameters {
			args, gap = args+",0x123456", 0xabad1dea00123456
		}
		resultMask := ^uint64(0) >> uint(64-row.resultBits)
		storeMask := ^uint64(0) >> uint(64-row.storeBits)
		fmt.Fprintf(&original, "for _,input := range inputs {\nactual := uint64(int64(%s(%s)))\n"+
			"expected := input & 0x%x\n", row.name, args, resultMask)
		if row.signed && row.resultBits < 64 {
			fmt.Fprintf(&original, "if expected & (uint64(1)<<%d) != 0 { expected |= 0x%x }\n", row.resultBits-1, ^resultMask)
		}
		fmt.Fprintf(&original, "value,native,guard,paramgap := observe_%s(input)\n"+
			"if actual != expected || value != expected || native != (input & 0x%x | 0x%x) || "+
			"guard != 0x7ac35ef012345678 || paramgap != 0x%x { t.Fatalf(%q, input, actual, value, native, guard, paramgap) }\n}\n",
			row.name, storeMask, uint64(0xfeedfacecafebeef)&^storeMask, gap,
			row.name+": input=%x typed=%x value=%x native=%x guard=%x paramgap=%x")
	}
	marker := fmt.Sprintf("ORIGINAL_SIGNED_CARRIER %d", len(cases)*len(inputs))
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
	args := []string{"test", "-p=1", "-count=1", "-v", "-run", "^TestOriginalSignedCarrier$"}
	if len(runner) != 0 {
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "-exec", quoted)
	}
	lease, release := runtimeOracleStageContext(t)
	defer release()
	command := exec.CommandContext(lease, request.GoBinary, args...)
	command.Dir, command.Env = directory, request.Environment
	output, err := runtimeOracleCombinedOutput(lease, command)
	if err != nil || strings.Count(string(output), marker) != 1 || !strings.Contains(string(output), "--- PASS: TestOriginalSignedCarrier") {
		t.Fatalf("unchanged original signed/native/canary runtime: %v\n%s", err, output)
	}
	t.Logf("actual original Go %s signed/canary observations: %d", request.Target, len(cases)*len(inputs))
	source, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	checks, driver := arm64SignedCarrierRuntimeChecks(packagePath, cases, inputs)
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), triple, nil)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, optimization := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", api, optimization), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "signed_carrier", triple, ir+checks, driver, runner, optimization)
				t.Logf("actual LLVM22 %s O%d signed/canary observations: %d", api, optimization, len(cases)*len(inputs))
			})
		}
	}
}

func arm64SignedCarrierRuntimeChecks(packagePath string, cases []arm64SignedCarrierCase, inputs []uint64) (string, string) {
	var checks, driver strings.Builder
	driver.WriteString("#include <stdint.h>\n")
	for _, row := range cases {
		args, gap := "i64 %input", uint64(0)
		if row.twoParameters {
			args, gap = args+", i32 1193046", 0xabad1dea00123456
		}
		fmt.Fprintf(&checks, "define i32 @check_%s(i64 %%input) {\n%%scalar = call i%d %s(%s)\n",
			row.name, row.resultBits, llvmGlobal(packagePath+"."+row.name), args)
		if row.resultBits == 64 {
			checks.WriteString("%scalar_wide = add i64 %scalar, 0\n%expected = add i64 %input, 0\n")
		} else {
			extension, shift := "zext", "lshr"
			if row.signed {
				extension, shift = "sext", "ashr"
			}
			fmt.Fprintf(&checks, "%%scalar_wide = %s i%d %%scalar to i64\n"+
				"%%shifted = shl i64 %%input, %d\n%%expected = %s i64 %%shifted, %d\n",
				extension, row.resultBits, 64-row.resultBits, shift, 64-row.resultBits)
		}
		storeMask := ^uint64(0) >> uint(64-row.storeBits)
		fmt.Fprintf(&checks, `%%result = call { i64,i64,i64,i64 } %s(i64 %%input)
%%value = extractvalue { i64,i64,i64,i64 } %%result, 0
%%native = extractvalue { i64,i64,i64,i64 } %%result, 1
%%guard = extractvalue { i64,i64,i64,i64 } %%result, 2
%%gap = extractvalue { i64,i64,i64,i64 } %%result, 3
%%store = and i64 %%input, %d
%%native_expected = or i64 %%store, %d
%%typed_ok = icmp eq i64 %%scalar_wide, %%expected
%%value_ok = icmp eq i64 %%value, %%expected
%%native_ok = icmp eq i64 %%native, %%native_expected
%%guard_ok = icmp eq i64 %%guard, %d
%%gap_ok = icmp eq i64 %%gap, %d
%%typed = and i1 %%typed_ok, %%value_ok
%%bytes = and i1 %%native_ok, %%guard_ok
%%both = and i1 %%typed, %%bytes
%%all = and i1 %%both, %%gap_ok
%%status = select i1 %%all, i32 0, i32 1
ret i32 %%status
}
`, llvmGlobal(packagePath+".observe_"+row.name), storeMask,
			uint64(0xfeedfacecafebeef)&^storeMask, uint64(0x7ac35ef012345678), gap)
		fmt.Fprintf(&driver, "extern int32_t check_%s(uint64_t);\n", row.name)
	}
	driver.WriteString("int main(void) {\nconst uint64_t inputs[] = {\n")
	for _, input := range inputs {
		fmt.Fprintf(&driver, "UINT64_C(0x%x),\n", input)
	}
	driver.WriteString("};\nfor (unsigned i=0; i<sizeof(inputs)/sizeof(inputs[0]); i++) {\n")
	for _, row := range cases {
		fmt.Fprintf(&driver, "if (check_%s(inputs[i])) return 1;\n", row.name)
	}
	driver.WriteString("}\nreturn 0;\n}\n")
	return checks.String(), driver.String()
}
