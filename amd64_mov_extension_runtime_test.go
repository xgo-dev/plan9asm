package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86ExtensionNumericalCase struct {
	op             string
	source, result int
	signed         bool
	mode, name     string
}

func x86ExtensionNumericalCases() []x86ExtensionNumericalCase {
	var cases []x86ExtensionNumericalCase
	for _, operation := range []x86ExtensionNumericalCase{
		{op: "MOVBWSX", source: 8, result: 16, signed: true},
		{op: "MOVBWZX", source: 8, result: 16},
		{op: "MOVBLSX", source: 8, result: 32, signed: true},
		{op: "MOVBLZX", source: 8, result: 32},
		{op: "MOVBQSX", source: 8, result: 64, signed: true},
		{op: "MOVBQZX", source: 8, result: 64},
		{op: "MOVWLSX", source: 16, result: 32, signed: true},
		{op: "MOVWLZX", source: 16, result: 32},
		{op: "MOVWQSX", source: 16, result: 64, signed: true},
		{op: "MOVWQZX", source: 16, result: 64},
		{op: "MOVLQSX", source: 32, result: 64, signed: true},
		{op: "MOVLQZX", source: 32, result: 64},
		{op: "MOVSWW", source: 16, result: 16, signed: true},
		{op: "MOVZWW", source: 16, result: 16},
	} {
		for _, mode := range []string{"Register", "Memory", "LowAlias", "InPlace", "PhysicalBytes"} {
			if mode == "LowAlias" && operation.source == 32 ||
				mode == "LowAlias" && operation.source == 16 && operation.result != 16 {
				continue
			}
			operation.mode = mode
			operation.name = "extension" + operation.op + mode
			cases = append(cases, operation)
		}
	}
	// REX.W changes BH to DI's low byte. The source DI is explicitly numeric
	// here, not the imported input pointer or an unknown entry register.
	for _, operation := range []x86ExtensionNumericalCase{
		{op: "MOVBQZX", source: 8, result: 64},
		{op: "MOVBQSX", source: 8, result: 64, signed: true},
		{op: "MOVSWW", source: 16, result: 16, signed: true},
		{op: "MOVZWW", source: 16, result: 16},
	} {
		operation.mode, operation.name = "PhysicalAlias", "extension"+operation.op+"PhysicalAlias"
		cases = append(cases, operation)
	}
	return cases
}

// Independent fixed encodings for the BX-to-AX forms. In particular LQSX
// requires REX.W; the ambiguous no-REX 63 form is a separate Context test.
func x86ExtensionNumericalRawBytes(operation string) string {
	encodings := map[string][]byte{
		"MOVBWSX": {0x66, 0x0f, 0xbe, 0xc3},
		"MOVBWZX": {0x66, 0x0f, 0xb6, 0xc3},
		"MOVBLSX": {0x0f, 0xbe, 0xc3},
		"MOVBLZX": {0x0f, 0xb6, 0xc3},
		"MOVBQSX": {0x48, 0x0f, 0xbe, 0xc3},
		"MOVBQZX": {0x48, 0x0f, 0xb6, 0xc3},
		"MOVWLSX": {0x0f, 0xbf, 0xc3},
		"MOVWLZX": {0x0f, 0xb7, 0xc3},
		"MOVWQSX": {0x48, 0x0f, 0xbf, 0xc3},
		"MOVWQZX": {0x48, 0x0f, 0xb7, 0xc3},
		"MOVLQSX": {0x48, 0x63, 0xc3},
		"MOVLQZX": {0x8b, 0xc3},
		"MOVSWW":  {0x66, 0x0f, 0xbf, 0xc3},
		"MOVZWW":  {0x66, 0x0f, 0xb7, 0xc3},
	}
	var source strings.Builder
	for _, value := range encodings[operation] {
		fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
	}
	return source.String()
}

func x86ExtensionNumericalSource() (string, string) {
	var declarations, assembly strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	for _, test := range x86ExtensionNumericalCases() {
		declaration := strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint64")
		declaration = declaration[strings.Index(declaration, "//go:noescape"):]
		declaration = strings.ReplaceAll(declaration, "kernel", test.name)
		declaration = strings.Replace(declaration, "func Call(", "func Call"+test.name+"(", 1)
		declarations.WriteString(declaration)
		operand := "BX"
		body := "MOVQ (DI),BX\nMOVQ $0x5a6b7c8d9eaf1021,AX\n"
		switch test.mode {
		case "Memory":
			operand = "(DI)"
		case "LowAlias":
			operand = "BL"
		case "InPlace":
			body += "MOVQ BX,AX\n"
			operand = "AX"
		case "PhysicalAlias":
			body += "MOVQ BX,DI\n"
			operand = "BH"
		}
		body += "CMPQ BX,$0\n"
		if test.mode == "PhysicalBytes" {
			body += x86ExtensionNumericalRawBytes(test.op)
		} else {
			body += fmt.Sprintf("%s %s,AX\n", test.op, operand)
		}
		body += "JE done\nADDQ $7,AX\ndone:\nMOVQ AX,(DX)"
		machine := strings.ReplaceAll(x86CallerFixtureAssembly, "·kernel", "·"+test.name)
		machine = strings.Replace(machine, "MOVL $7,AX\nMOVL AX,(DX)", body, 1)
		assembly.WriteString(machine)
	}
	return declarations.String(), assembly.String()
}

func x86ExtensionActualGoNumerical(t *testing.T, declaration, assembly string, runner []string) {
	t.Helper()
	var tests strings.Builder
	tests.WriteString(`package caller
import "testing"
func reference(input uint64, source, result uint, signed, inPlace bool) uint64 {
	mask := uint64(1)<<source - 1
	value := input & mask
	if signed && value&(uint64(1)<<(source-1)) != 0 {
		value |= ^mask
	}
	if result == 16 {
		seed := uint64(0x5a6b7c8d9eaf1021)
		if inPlace { seed = input }
		value = seed & ^uint64(65535) | value & 65535
	} else if result == 32 {
		value = uint64(uint32(value))
	}
	if input != 0 { value += 7 }
	return value
}
func TestOriginalExtensionNumerical(t *testing.T) {
`)
	for _, test := range x86ExtensionNumericalCases() {
		fmt.Fprintf(&tests, `
	for iteration := 0; iteration < 16; iteration++ {
		for _, input := range []uint64{0, 1, 127, 128, 65535, 1<<31, 1<<63, ^uint64(0)} {
			x := []uint64{input, 0x1122334455667788}
			y := []uint64{0x8877665544332211, 23}
			canary := [4]uint64{11, 23, 37, 41}
			got := Call%[1]s(x, y)
			want := reference(input, %[2]d, %[3]d, %[4]t, %[5]t)
			if got != want || x[0] != input || x[1] != 0x1122334455667788 ||
				y[0] != 0x8877665544332211 || y[1] != 23 || canary != [4]uint64{11,23,37,41} {
				t.Fatalf("%[1]s got=%%#x want=%%#x input=%%#x canary=%%v", got, want, input, canary)
			}
		}
	}
`, test.name, test.source, test.result, test.signed, test.mode == "InPlace")
	}
	tests.WriteString("}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": declaration,
		"value_amd64.s": assembly, "value_test.go": tests.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	binary := filepath.Join(dir, "original.test")
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-c", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go extension build: %v\n%s", err, output)
	}
	arguments := append(append([]string(nil), runner...), binary, "-test.v", "-test.timeout=2m")
	command = exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go extension numerical/canary: %v\n%s", err, output)
	}
}

func x86ExtensionCOracle() string {
	var declarations, checks strings.Builder
	for _, test := range x86ExtensionNumericalCases() {
		fmt.Fprintf(&declarations, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", test.name, test.name)
		fmt.Fprintf(&checks, "    if (check(%s, %d, %d, %t, %t)) return %d;\n",
			test.name, test.source, test.result, test.signed, test.mode == "InPlace", 1+len(strings.Split(checks.String(), "\n")))
	}
	return `#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
` + declarations.String() + `
static uint64_t reference(uint64_t input, unsigned source, unsigned result, bool sign, bool in_place) {
    uint64_t mask = (UINT64_C(1)<<source)-1;
    uint64_t value = input & mask;
    if (sign && (value & (UINT64_C(1)<<(source-1)))) value |= ~mask;
    if (result == 16) {
        uint64_t seed = in_place ? input : UINT64_C(0x5a6b7c8d9eaf1021);
        value = (seed & ~UINT64_C(65535)) | (value & UINT64_C(65535));
    } else if (result == 32) {
        value = (uint32_t)value;
    }
    return value + (input != 0 ? 7 : 0);
}
static int check(void (*fn)(void*,void*,void*,void*), unsigned source, unsigned result, bool sign, bool in_place) {
    const uint64_t inputs[] = {0, 1, 127, 128, 65535, UINT64_C(1)<<31, UINT64_C(1)<<63, UINT64_MAX};
    for (unsigned iteration = 0; iteration < 16; iteration++) {
        for (unsigned index = 0; index < sizeof(inputs)/sizeof(inputs[0]); index++) {
            uint64_t x[] = {inputs[index], UINT64_C(0x1122334455667788)};
            uint64_t y[] = {UINT64_C(0x8877665544332211), 23}, length = 2;
            unsigned char output[10];
            memset(output, 0xa5, sizeof(output));
            fn(x, y, output+1, &length);
            uint64_t got;
            memcpy(&got, output+1, sizeof(got));
            if (got != reference(inputs[index], source, result, sign, in_place) ||
                output[0] != 0xa5 || output[9] != 0xa5 || length != 2 ||
                x[0] != inputs[index] || x[1] != UINT64_C(0x1122334455667788) ||
                y[0] != UINT64_C(0x8877665544332211) || y[1] != 23) return 1;
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + "    return 0;\n}\n"
}

func TestX86ExtensionInitializedCallerNumericalFamily(t *testing.T) {
	var runner []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		runner = []string{"/usr/bin/arch", "-x86_64"}
		t.Log("actual Darwin/amd64 Go and LLVM executions use Rosetta; not native AMD64 evidence")
	} else if runtime.GOARCH != "amd64" {
		t.Skip("requires the independently required Linux/amd64 execution counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	declaration, source := x86ExtensionNumericalSource()
	requireX86GoAssemblerResult(t, "amd64", source, true)
	x86ExtensionActualGoNumerical(t, declaration, source, runner)
	pkg := x86CallerRuntimePackage(t, declaration, source)
	file := pkg.SourceSelection.Assembly["value_amd64.s"]
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "extension-text", triple, ir, x86ExtensionCOracle(), runner)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	compileAndRunRuntimeTestForTarget(t, llc, clang, "extension-module", triple, module.String(), x86ExtensionCOracle(), runner)
	ctx = llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple, ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	compileAndRunRuntimeTestForTarget(t, llc, clang, "extension-go-module", triple, translation.Module.String(), x86ExtensionCOracle(), runner)
}
