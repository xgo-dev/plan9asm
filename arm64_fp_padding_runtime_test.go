package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func arm64PaddingRuntimeInputs() []uint64 {
	values := []uint64{0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, ^uint64(0)}
	x := uint64(0x6492b630f84d)
	for i := 0; i < 64; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		values = append(values, x)
	}
	return values
}

// Only the native Go caller shim writes padding: the translated function and
// its original native-width load are identical. This makes unspecified bytes
// vary independently of the real narrow argument instead of assuming zero.
func arm64PaddingNativeCaller(test arm64PaddingCase) string {
	move := map[int]string{8: "MOVB", 16: "MOVH", 32: "MOVW"}[test.parameter]
	return fmt.Sprintf(`
TEXT ·pad_%s(SB),4,$80-24
    MOVD noise+8(FP),R0
    MOVD R0,8(RSP)
    %s rhs+0(FP),R0
    %s R0,8(RSP)
    MOVD $0xcafef00d01234567,R12
    MOVD R12,24(RSP)
    MOVD R12,32(RSP)
    MOVD g,R12
    MOVD R12,40(RSP)
    WORD $0xaa1203ec // mov x12,x18: Go's OS-reserved register is not named.
    MOVD R12,48(RSP)
    MOVD 0(RSP),R12
    MOVD R12,56(RSP)
    MOVD RSP,R12
    MOVD R12,64(RSP)
    CALL ·%s(SB)
    MOVD $0xcafef00d01234567,R12
    MOVD 24(RSP),R13
    CMP R12,R13
    BNE bad_%s
    MOVD 32(RSP),R13
    CMP R12,R13
    BNE bad_%s
    MOVD 40(RSP),R12
    CMP g,R12
    BNE bad_%s
    MOVD 48(RSP),R13
    WORD $0xaa1203ec
    CMP R12,R13
    BNE bad_%s
    MOVD 0(RSP),R12
    MOVD 56(RSP),R13
    CMP R12,R13
    BNE bad_%s
    MOVD RSP,R12
    MOVD 64(RSP),R13
    CMP R12,R13
    BNE bad_%s
    MOVD 16(RSP),R0
    MOVD R0,res+16(FP)
    RET
bad_%s:
    MOVD $0xdeadbeeff00dbabe,R0
    MOVD R0,res+16(FP)
    RET
`, test.name, move, move, test.name, test.name, test.name, test.name, test.name, test.name, test.name, test.name)
}

func TestARM64FPPaddingOriginalGoRandomizedBytes(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("original Go runtime requires an ARM64 host; objects are tested independently")
	}
	arm64FPPaddingOriginalGoRandomizedBytes(t, nil)
}

func arm64FPPaddingOriginalGoRandomizedBytes(t *testing.T, runner []string) {
	t.Helper()
	cases := arm64PaddingCases()
	source, declarations := arm64PaddingSource(cases)
	declarations = strings.Replace(declarations, "package padbits", "package main", 1)
	var driver strings.Builder
	driver.WriteString("package main\n\nimport \"fmt\"\n\n")
	for _, test := range cases {
		fmt.Fprintf(&driver, "func pad_%s(rhs int%d, noise uint64) (res uint64)\n", test.name, test.parameter)
		source += arm64PaddingNativeCaller(test)
	}
	driver.WriteString("\nfunc main() {\n")
	driver.WriteString("    inputs := []uint64{")
	for _, input := range arm64PaddingRuntimeInputs() {
		fmt.Fprintf(&driver, "%d,", input)
	}
	driver.WriteString("}\n    count := 0\n")
	count := 0
	for _, test := range cases {
		driver.WriteString("    {\n        want := []uint64{")
		for _, input := range arm64PaddingRuntimeInputs() {
			fmt.Fprintf(&driver, "%d,", arm64PaddingExpected(test, input))
			count += 4
		}
		fmt.Fprintf(&driver, `}
        for i, input := range inputs {
            // Padding varies independently from the real parameter bits.
            noises := []uint64{0, ^uint64(0), input * 0x9e3779b97f4a7c15, input ^ 0xd1096542b630f84d}
            for _, noise := range noises {
                got := pad_%s(int%d(input), noise)
                if got != want[i] {
                    panic(fmt.Sprintf("%s input=%%x noise=%%x got=%%x want=%%x", input, noise, got, want[i]))
                }
                count++
            }
        }
    }
`, test.name, test.parameter, test.name)
	}
	driver.WriteString("    fmt.Printf(\"padding %d\\n\", count)\n}\n")
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod": "module padbits\n\ngo 1.20\n", "main.go": driver.String(),
		"decl.go": declarations, "padding_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := []string{"run", "-p=1"}
	if len(runner) != 0 {
		// Go's -exec parses a quoted argument list, not a shell command.
		// Retain the exact required runner's executable and sysroot arguments.
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "-exec="+quoted)
	}
	command := exec.CommandContext(ctx, "go", append(args, ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=arm64", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		command.Env = append(command.Env, "GOOS=linux")
	}
	out, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil || string(out) != fmt.Sprintf("padding %d\n", count) {
		t.Fatalf("original Go random padding, adjacent stack/g/OS18/LR/SP canaries: %v\n%s", err, out)
	}
	t.Logf("%d original Go calls with randomized ABI0 padding and control/stack canaries", count)
}

func TestARM64FPPaddingLLVMIndependentNumericalAndCanaries(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("LLVM numerical execution requires an ARM64 host; cross objects remain mandatory")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	arm64FPPaddingLLVMIndependentNumericalAndCanaries(t, llc,
		testTargetTriple(runtime.GOOS, runtime.GOARCH), []string{clang}, nil)
}

func arm64FPPaddingLLVMIndependentNumericalAndCanaries(t *testing.T, llc, triple string, compiler, runner []string) {
	t.Helper()
	cases := arm64PaddingCases()
	source, declarations := arm64PaddingSource(cases)
	pkg := mustGoPackage(t, "padbits", declarations)
	translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOOS: runtime.GOOS, GOARCH: "arm64", TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path)})
	if err != nil {
		t.Fatal(err)
	}
	defer translated.Module.Dispose()
	var driver strings.Builder
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n\n")
	for _, test := range cases {
		symbol := "padbits." + test.name
		if runtime.GOOS == "darwin" {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&driver, "extern uint64_t %s(int%d_t) __asm__(%q);\n", test.name, test.parameter, symbol)
	}
	driver.WriteString("\nint main(void) {\n")
	for _, test := range cases {
		for _, input := range arm64PaddingRuntimeInputs() {
			fmt.Fprintf(&driver, `    {
        volatile uint64_t guards[2] = { UINT64_C(0xcafef00d01234567), UINT64_C(0x76543210d00fefac) };
        uint64_t result = %s((int%d_t) UINT64_C(%d));
        if (result != UINT64_C(%d) || guards[0] != UINT64_C(0xcafef00d01234567) ||
                guards[1] != UINT64_C(0x76543210d00fefac)) {
            fprintf(stderr, "%s input=%%llx result=%%llx\n", (unsigned long long) UINT64_C(%d), (unsigned long long) result);
            return 1;
        }
    }
`, test.name, test.parameter, input, arm64PaddingExpected(test, input), test.name, input)
		}
	}
	driver.WriteString("    return 0;\n}\n")
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_fp_padding", triple, translated.Module.String(), driver.String(), runner)
	t.Logf("%d LLVM/C independent numerical cases; no assertion that native padding was initialized", len(cases)*len(arm64PaddingRuntimeInputs()))
}

func TestCrossLinuxRuntimeMatrixARM64FPPadding(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	// The required matrix consumes exactly the existing 46 forms, 76 inputs
	// and four independent native padding values, including all old canaries.
	arm64FPPaddingOriginalGoRandomizedBytes(t, runner)
	arm64FPPaddingLLVMIndependentNumericalAndCanaries(t, llc, triple, compiler, runner)
}

func arm64PaddingGoExecArguments(args []string) (string, error) {
	// cmd/internal/quoted.Split in both Go 1.20 and 1.27 treats quoted
	// contents literally: backslashes are not escapes. Follow quoted.Join's
	// choice of quote, but explicitly quote empty arguments so they survive.
	quoted := make([]string, len(args))
	for i, arg := range args {
		single := strings.ContainsRune(arg, '\'')
		double := strings.ContainsRune(arg, '"')
		switch {
		case single && double:
			return "", fmt.Errorf("Go -exec argument %q contains both quote kinds", arg)
		case arg != "" && !single && !double && !strings.ContainsAny(arg, " \t\n\r"):
			quoted[i] = arg
		case !single:
			quoted[i] = "'" + arg + "'"
		default:
			quoted[i] = "\"" + arg + "\""
		}
	}
	return strings.Join(quoted, " "), nil
}

func TestARM64FPPaddingGoExecArgumentsActualGo(t *testing.T) {
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":  "module paddingexecargv\n\ngo 1.20\n",
		"main.go": "package main\n\nfunc main() {}\n",
		"runner/main.go": `package main

import (
    "encoding/json"
    "fmt"
    "os"
)

func main() {
    if len(os.Args) < 2 {
        panic("go -exec did not append the compiled executable")
    }
    if _, err := os.Stat(os.Args[len(os.Args)-1]); err != nil {
        panic(err)
    }
    encoded, err := json.Marshal(os.Args[1:len(os.Args)-1])
    if err != nil {
        panic(err)
    }
    fmt.Println(string(encoded))
}
`,
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}

	runner := filepath.Join(dir, gotoolchain.HostExecutable("exec runner"))
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=1", "-o", runner, "./runner")
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("compile actual Go argv observer: %v\n%s", err, output)
	}

	want := []string{"plain", "with space", `back\slash`, "with\ttab", "with\nnewline", "with\rcarriage", "", "single'quote", `double"quote`}
	encoded, err := arm64PaddingGoExecArguments(append([]string{runner}, want...))
	if err != nil {
		t.Fatal(err)
	}
	command = exec.CommandContext(ctx, "go", "run", "-p=1", "-exec="+encoded, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual Go -exec argv observer: %v\n%s", err, output)
	}
	var got []string
	if err := json.Unmarshal(output, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("actual Go -exec changed argv: got %q, want %q, decode %v", got, want, err)
	}
}

func TestARM64FPPaddingGoExecArgumentsRejectBothQuotes(t *testing.T) {
	for _, arg := range []string{`both'"quotes`, "'double with space\"", "'\t\""} {
		if encoded, err := arm64PaddingGoExecArguments([]string{"runner", arg}); err == nil || encoded != "" {
			t.Fatalf("unrepresentable argument %q accepted as %q: %v", arg, encoded, err)
		}
	}
}
