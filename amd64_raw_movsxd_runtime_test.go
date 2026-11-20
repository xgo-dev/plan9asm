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

type x86MOVSXDNumericalForm struct {
	name     string
	encoding []byte
	bits     int
	offset   int
	setup    string
	result   string
	inPlace  bool
	flagSeed int
}

func x86MOVSXDNumericalForms() []x86MOVSXDNumericalForm {
	forms := []x86MOVSXDNumericalForm{
		{name: "wordBX", encoding: []byte{0x66, 0x63, 0xc3}, bits: 16},
		{name: "wordSI", encoding: []byte{0x66, 0x63, 0xc6}, bits: 16, setup: "MOVQ BX,SI\n"},
		{name: "wordR9", encoding: []byte{0x66, 0x41, 0x63, 0xc1}, bits: 16, setup: "MOVQ BX,R9\n"},
		{name: "wordR8", encoding: []byte{0x66, 0x44, 0x63, 0xc3}, bits: 16, result: "MOVQ R8,AX\n"},
		{name: "wordAlias", encoding: []byte{0x66, 0x63, 0xc0}, bits: 16, setup: "MOVQ BX,AX\n", inPlace: true},
		{name: "longBX", encoding: []byte{0x63, 0xc3}, bits: 32},
		{name: "longR9", encoding: []byte{0x41, 0x63, 0xc1}, bits: 32, setup: "MOVQ BX,R9\n"},
		{name: "longR8", encoding: []byte{0x44, 0x63, 0xc3}, bits: 32, result: "MOVQ R8,AX\n"},
		{name: "longAlias", encoding: []byte{0x63, 0xc0}, bits: 32, setup: "MOVQ BX,AX\n", inPlace: true},
		{name: "longMemory", encoding: []byte{0x63, 0x07}, bits: 32},
		{name: "longUnaligned", encoding: []byte{0x63, 0x47, 0x01}, bits: 32, offset: 1},
		{name: "longOffset4", encoding: []byte{0x63, 0x47, 0x04}, bits: 32, offset: 4},
		{name: "longIndexed", encoding: []byte{0x63, 0x04, 0x8f}, bits: 32, setup: "MOVQ $0,CX\n"},
		{name: "quadBX", encoding: []byte{0x48, 0x63, 0xc3}, bits: 64},
		{name: "quadR9", encoding: []byte{0x49, 0x63, 0xc1}, bits: 64, setup: "MOVQ BX,R9\n"},
		{name: "quadR8", encoding: []byte{0x4c, 0x63, 0xc3}, bits: 64, result: "MOVQ R8,AX\n"},
		{name: "quadAlias", encoding: []byte{0x48, 0x63, 0xc0}, bits: 64, setup: "MOVQ BX,AX\n", inPlace: true},
		{name: "quadMemory", encoding: []byte{0x48, 0x63, 0x07}, bits: 64},
		{name: "quadUnaligned", encoding: []byte{0x48, 0x63, 0x47, 0x01}, bits: 64, offset: 1},
		{name: "quadOffset4", encoding: []byte{0x48, 0x63, 0x47, 0x04}, bits: 64, offset: 4},
		{name: "quadIndexed", encoding: []byte{0x48, 0x63, 0x04, 0x8f}, bits: 64, setup: "MOVQ $0,CX\n"},
		{name: "quadOperandOverride", encoding: []byte{0x66, 0x48, 0x63, 0x07}, bits: 64},
	}
	var seeded []x86MOVSXDNumericalForm
	for _, form := range forms {
		for seed, suffix := range []string{"", "Carry", "Overflow"} {
			variant := form
			variant.name += suffix
			variant.flagSeed = seed
			seeded = append(seeded, variant)
		}
	}
	return seeded
}

func x86MOVSXDFlagSeed(seed int) string {
	switch seed {
	case 1:
		// 0-1: CF=1, OF=0, SF=1, PF=1, ZF=0.
		return "MOVQ $0,R15\nCMPQ R15,$1\n"
	case 2:
		// INT64_MIN-1: CF=0, OF=1, SF=0, PF=1, ZF=0.
		return "MOVQ $0x8000000000000000,R15\nCMPQ R15,$1\n"
	default:
		return "CMPQ BX,$0\n"
	}
}

func x86MOVSXDNumericalSource() (string, string) {
	var declarations, assembly strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	for _, form := range x86MOVSXDNumericalForms() {
		declaration := strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint64")
		declaration = declaration[strings.Index(declaration, "//go:noescape"):]
		declaration = strings.ReplaceAll(declaration, "kernel", form.name)
		declaration = strings.Replace(declaration, "func Call(", "func Call"+form.name+"(", 1)
		declarations.WriteString(declaration)
		body := "MOVQ (DI),BX\nMOVQ $0x5a6b7c8d9eaf1021,AX\nMOVQ AX,R8\n" + form.setup
		body += x86MOVSXDFlagSeed(form.flagSeed) + x86MOVSXDBytes(form.encoding) + form.result
		// Neutral MOVs capture each modeled flag before any arithmetic. The
		// branch joins preserve definite numeric bytes, not guessed values.
		body += `MOVQ $0,R9
MOVQ $0,R10
MOVQ $0,R11
MOVQ $0,R12
MOVQ $0,R13
JCC noCarry
MOVQ $1,R9
noCarry:
JOC noOverflow
MOVQ $2,R10
noOverflow:
JPL noSign
MOVQ $4,R11
noSign:
JPC noParity
MOVQ $8,R12
noParity:
JNE noZero
MOVQ $16,R13
noZero:
JE done
ADDQ $7,AX
done:
ORQ R9,R10
ORQ R11,R10
ORQ R12,R10
ORQ R13,R10
SHLQ $48,R10
XORQ R10,AX
MOVQ AX,(DX)`
		machine := strings.ReplaceAll(x86CallerFixtureAssembly, "·kernel", "·"+form.name)
		assembly.WriteString(strings.Replace(machine, "MOVL $7,AX\nMOVL AX,(DX)", body, 1))
	}
	return declarations.String(), assembly.String()
}

func x86MOVSXDGoOracle() string {
	var source strings.Builder
	source.WriteString(`package caller
import "testing"
func reference(input uint64, bits, offset uint, inPlace bool, flagSeed uint) uint64 {
	value := uint64(uint32(input >> (offset*8)))
	if bits == 16 {
		seed := uint64(0x5a6b7c8d9eaf1021)
		if inPlace { seed = input }
		value = seed & ^uint64(65535) | input & 65535
	} else if bits == 64 {
		value = uint64(int64(int32(value)))
	}
	if input != 0 || flagSeed != 0 { value += 7 }
	flags := uint64(0)
	if input>>63 != 0 { flags |= 4 }
	var ones uint
	for byteValue := uint8(input); byteValue != 0; byteValue >>= 1 { ones += uint(byteValue&1) }
	if ones%2 == 0 { flags |= 8 }
	if input == 0 { flags |= 16 }
	if flagSeed == 1 { flags = 1 | 4 | 8 }
	if flagSeed == 2 { flags = 2 | 8 }
	return value ^ (flags<<48)
}
func TestOriginalMOVSXDNumerical(t *testing.T) {
`)
	for _, form := range x86MOVSXDNumericalForms() {
		fmt.Fprintf(&source, `
	for iteration := 0; iteration < 16; iteration++ {
		for _, input := range []uint64{0, 1, 127, 128, 65535, 1<<31, 1<<63, ^uint64(0)} {
			x := []uint64{input, 0x1122334455667788}
			y := []uint64{0x8877665544332211, 23}
			canary := [4]uint64{11, 23, 37, 41}
			got := Call%[1]s(x, y)
			want := reference(input, %[2]d, %[3]d, %[4]t, %[5]d)
			if got != want || x[0] != input || x[1] != 0x1122334455667788 ||
				y[0] != 0x8877665544332211 || y[1] != 23 || canary != [4]uint64{11,23,37,41} {
				t.Fatalf("%[1]s got=%%#x want=%%#x input=%%#x canary=%%v", got, want, input, canary)
			}
		}
	}
`, form.name, form.bits, form.offset, form.inPlace, form.flagSeed)
	}
	source.WriteString("}\n")
	return source.String()
}

func x86MOVSXDActualGo(t *testing.T, execute bool) {
	t.Helper()
	declaration, assembly := x86MOVSXDNumericalSource()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": declaration,
		"value_amd64.s": assembly, "value_test.go": x86MOVSXDGoOracle(),
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
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go original raw MOVSXD build: %v\n%s", err, output)
	}
	if !execute {
		return // Object/Go entry transport evidence is not runtime success.
	}
	command = exec.CommandContext(ctx, binary, "-test.v", "-test.timeout=2m")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Linux/amd64 MOVSXD mathematical/canary oracle: %v\n%s", err, output)
	}
}

func x86MOVSXDCOracle() string {
	var declarations, checks strings.Builder
	for index, form := range x86MOVSXDNumericalForms() {
		fmt.Fprintf(&declarations, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", form.name, form.name)
		fmt.Fprintf(&checks, "    if (check(%s, %d, %d, %t, %d)) return %d;\n",
			form.name, form.bits, form.offset, form.inPlace, form.flagSeed, index+1)
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
static uint64_t reference(uint64_t input, unsigned bits, unsigned offset, bool in_place, unsigned flag_seed) {
    uint64_t value = (uint32_t)(input >> (offset*8));
    if (bits == 16) {
        uint64_t seed = in_place ? input : UINT64_C(0x5a6b7c8d9eaf1021);
        value = (seed & ~UINT64_C(65535)) | (input & UINT64_C(65535));
    } else if (bits == 64) {
        value = (uint64_t)(int64_t)(int32_t)value;
    }
    value += input != 0 || flag_seed != 0 ? 7 : 0;
    uint64_t flags = input >> 63 ? 4 : 0;
    unsigned ones = 0;
    for (unsigned byte_value = (unsigned char)input; byte_value; byte_value >>= 1) ones += byte_value & 1;
    if (!(ones & 1)) flags |= 8;
    if (!input) flags |= 16;
    if (flag_seed == 1) flags = 1 | 4 | 8;
    if (flag_seed == 2) flags = 2 | 8;
    return value ^ (flags << 48);
}
static int check(void (*fn)(void*,void*,void*,void*), unsigned bits, unsigned offset, bool in_place, unsigned flag_seed) {
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
            if (got != reference(inputs[index], bits, offset, in_place, flag_seed) ||
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

func x86MOVSXDLLVMNumerical(t *testing.T, runner []string) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	declaration, assembly := x86MOVSXDNumericalSource()
	pkg := x86CallerRuntimePackage(t, declaration, assembly)
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
	compileAndRunRuntimeTestForTarget(t, llc, clang, "movsxd-text", triple, ir, x86MOVSXDCOracle(), runner)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "movsxd-module", triple, module.String(), x86MOVSXDCOracle(), runner)
	ctx = llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple, ResolveSym: resolve,
	})
	if translation != nil && !translation.Module.IsNil() {
		defer translation.Module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "movsxd-go-module", triple, translation.Module.String(), x86MOVSXDCOracle(), runner)
}

func TestX86RawMOVSXDOriginalGoBuild(t *testing.T) {
	x86MOVSXDActualGo(t, false)
}

func TestX86RawMOVSXDLLVMHostNumerical(t *testing.T) {
	var runner []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		runner = []string{"/usr/bin/arch", "-x86_64"}
		t.Log("LLVM numerical diagnostic uses Rosetta; the original no-REX 63 environment failure is retained separately")
	} else if runtime.GOARCH != "amd64" {
		t.Skip("requires the mandatory Linux/amd64 original-Go plus LLVM counterpart")
	}
	x86MOVSXDLLVMNumerical(t, runner)
}

func TestCrossLinuxRuntimeMatrixAMD64MOVSXDNativeWidths(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("required actual Linux/amd64 original-Go and LLVM counterpart; Darwin/Rosetta is not equivalent")
	}
	x86MOVSXDActualGo(t, true)
	x86MOVSXDLLVMNumerical(t, nil)
}
