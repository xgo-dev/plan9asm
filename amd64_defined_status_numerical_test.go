//go:build unix

package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type x86DefinedStatusKernel struct {
	name, instruction string
	kind, bits        int
}

func x86DefinedStatusKernels() []x86DefinedStatusKernel {
	var kernels []x86DefinedStatusKernel
	add := func(instruction string, kind, bits int) {
		kernels = append(kernels, x86DefinedStatusKernel{
			fmt.Sprintf("status%d", len(kernels)), instruction, kind, bits,
		})
	}
	for _, width := range []struct {
		suffix string
		bits   int
	}{{"W", 16}, {"L", 32}, {"Q", 64}} {
		add("POPCNT"+width.suffix+" AX,BX", 0, width.bits)
	}
	add("PTEST X0,X1", 1, 128)
	for _, op := range []string{"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM"} {
		kind := 2
		if strings.HasPrefix(op, "PCMPI") {
			kind = 3
		}
		add(op+" $8,X0,X1", kind, 128)
	}
	for _, op := range []string{"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM"} {
		kind := 2
		if strings.HasPrefix(op, "VPCMPI") {
			kind = 3
		}
		add(op+" $8,X0,X1", kind, 128)
	}
	for _, stem := range []string{"KTEST", "KORTEST"} {
		for _, width := range []struct {
			suffix string
			bits   int
		}{{"B", 8}, {"W", 16}, {"D", 32}, {"Q", 64}} {
			kind := 4
			if stem == "KORTEST" {
				kind = 5
			}
			add(stem+width.suffix+" K1,K2", kind, width.bits)
		}
	}
	return kernels
}

func x86DefinedStatusNumericalFixture() (declarations, source string) {
	var decl, assembly strings.Builder
	for _, kernel := range x86DefinedStatusKernels() {
		fmt.Fprintf(&decl, "func %s(out *[8]uint64, left, right, seed uint64)\n", kernel.name)
		fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$0-32
MOVQ out+0(FP),DI
MOVQ left+8(FP),AX
MOVQ right+16(FP),BX
MOVQ seed+24(FP),SI
MOVQ BX,DX
MOVQ AX,X0
MOVQ BX,X1
`, kernel.name)
		if kernel.kind >= 4 {
			assembly.WriteString("KMOVQ AX,K1\nKMOVQ BX,K2\n")
		}
		fmt.Fprintf(&assembly, `
PUSHQ SI
POPFQ
%s
PUSHFQ
POPQ SI
MOVQ SI,0(DI)
LAHF
MOVB AH,8(DI)
RET
`, kernel.instruction)
	}
	return decl.String(), assembly.String()
}

// The baseline original-Go root executes SSE4.2/POPCNT, not AVX512 masks.
// Its exact source includes the mask objects, but no mask body is called here.
func x86DefinedStatusOriginalGoNumerical(t *testing.T) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	declarations, source := x86DefinedStatusNumericalFixture()
	driver := x86DefinedStatusOriginalGoDriver(false)
	original := x86DefinedStatusBuildOriginal(t, execution, declarations, source, driver)
	output := execution.run(t, original)
	if string(output) != "original defined-status observations 1024 failures 0\n" {
		t.Fatalf("original Go six-bit status/LAHF/canary model: %s", output)
	}
}

func x86DefinedStatusOriginalGoDriver(observe bool) string {
	kernels := x86DefinedStatusKernels()[:8]
	var names, kinds, widths strings.Builder
	for _, kernel := range kernels {
		fmt.Fprintf(&names, "%s,\n", kernel.name)
		fmt.Fprintf(&kinds, "%d,", kernel.kind)
		fmt.Fprintf(&widths, "%d,", kernel.bits)
	}
	return strings.NewReplacer(
		"KERNEL_NAMES", names.String(), "KERNEL_KINDS", kinds.String(),
		"KERNEL_WIDTHS", widths.String(), "ACTUAL_OBSERVATIONS", fmt.Sprint(observe),
	).Replace(x86DefinedStatusGoDriver)
}

func x86DefinedStatusBuildOriginal(t *testing.T, execution x86FloatCompareExecution, declarations, assembly, driver string) string {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":         "module definedstatus\n\ngo 1.20\n",
		"main.go":        driver,
		"decl.go":        "package main\n" + declarations,
		"status_amd64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-go")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-o", executable, ".")
	command.Dir = dir
	goos := runtime.GOOS
	if strings.Contains(execution.triple, "linux") {
		goos = "linux"
	}
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH=amd64", "GOTOOLCHAIN=local",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	return executable
}

func TestX86DefinedStatusLLVMNumerical(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declarations, source := x86DefinedStatusNumericalFixture()
	ir := x86CPUQueryIRFromDeclaration(t, source, declarations, "amd64", execution.triple, "Go")
	var prototypes, kernels strings.Builder
	for _, kernel := range x86DefinedStatusKernels() {
		fmt.Fprintf(&prototypes, "extern void %s(uint64_t *, uint64_t, uint64_t, uint64_t);\n", kernel.name)
		fmt.Fprintf(&kernels, "{%s,%d,%d,\"%s\"},\n", kernel.name, kernel.kind, kernel.bits, kernel.instruction)
	}
	driver := strings.NewReplacer("KERNEL_PROTOTYPES", prototypes.String(),
		"KERNELS", kernels.String()).Replace(x86DefinedStatusCDriver)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			output := execution.compileAndRunLLVM(t, "defined-status", input, driver, level)
			want := fmt.Sprintf("LLVM defined-status observations %d failures 0\n", len(x86DefinedStatusKernels())*128)
			if string(output) != want {
				t.Fatalf("independent six-bit status/LAHF/canary model: %s", output)
			}
		})
	}
}

// The C producer executes entire physical opcodes and captures flags in the
// same inline block, independently of Go's ABI0 wrapper and LLVM lowering.
func x86DefinedStatusOriginalCSource() string {
	instructions := []string{
		"popcntw %%ax,%%bx", "popcntl %%eax,%%ebx", "popcntq %%rax,%%rbx",
		"ptest %%xmm0,%%xmm1",
		"pcmpestri $8,%%xmm0,%%xmm1", "pcmpestrm $8,%%xmm0,%%xmm1",
		"pcmpistri $8,%%xmm0,%%xmm1", "pcmpistrm $8,%%xmm0,%%xmm1",
	}
	var functions, registrations strings.Builder
	for index, kernel := range x86DefinedStatusKernels()[:8] {
		fmt.Fprintf(&functions, `static void %s(uint64_t *out, uint64_t left, uint64_t right, uint64_t seed) {
    uint64_t length = right;
    __asm__ volatile(
        "movq %%%%rax,%%%%xmm0\n\t"
        "movq %%%%rbx,%%%%xmm1\n\t"
        "pushq %%%%rsi\n\t"
        "popfq\n\t"
        "%s\n\t"
        "pushfq\n\t"
        "popq %%%%rsi\n\t"
        "movq %%%%rsi,0(%%%%rdi)\n\t"
        "lahf\n\t"
        "movb %%%%ah,8(%%%%rdi)\n\t"
        : "+a"(left), "+b"(right), "+d"(length), "+S"(seed)
        : "D"(out)
        : "cc", "memory", "xmm0", "xmm1", "rcx");
}

`, kernel.name, instructions[index])
		fmt.Fprintf(&registrations, "{%s,%d,%d,%q},\n", kernel.name, kernel.kind, kernel.bits, kernel.instruction)
	}
	source := strings.NewReplacer("KERNEL_PROTOTYPES", functions.String(),
		"KERNELS", registrations.String()).Replace(x86DefinedStatusCDriver)
	return strings.ReplaceAll(source, "LLVM", "original-C")
}

func x86DefinedStatusIndependentOriginalCNumerical(t *testing.T) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "original.c")
	if err := os.WriteFile(source, []byte(x86DefinedStatusOriginalCSource()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := filepath.Join(dir, "original-c"+level)
			arguments := append([]string(nil), execution.compiler...)
			arguments = append(arguments, level, source, "-o", executable)
			x86FloatCompareCaptureCommand(t, exec.Command(arguments[0], arguments[1:]...))
			output := execution.run(t, executable)
			if string(output) != "original-C defined-status observations 1024 failures 0\n" {
				t.Fatalf("actual C opcodes versus independent six-bit status model: %s", output)
			}
		})
	}
}

// Common emulated-host evidence is exact original-Go/C agreement, not ISA
// conformance. Every original result is retained; native Linux separately
// runs the unchanged strict mathematical oracle. No deviation is a skip.
func TestX86DefinedStatusOriginalGoAndCObservationAgreement(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declarations, assembly := x86DefinedStatusNumericalFixture()
	original := x86DefinedStatusBuildOriginal(t, execution, declarations, assembly, x86DefinedStatusOriginalGoDriver(true))
	observations := execution.run(t, original)
	lines := strings.Split(strings.TrimSuffix(string(observations), "\n"), "\n")
	summary := regexp.MustCompile(`^observed-status observations 1024 model-deviations ([0-9]+) invalid-observations 0$`)
	if len(lines) != 1025 || !summary.MatchString(lines[len(lines)-1]) {
		t.Fatalf("incomplete or invalid actual original-Go observation transcript: %s", observations)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "original.c")
	if err := os.WriteFile(source, []byte("#define OBSERVE_ACTUAL 1\n"+x86DefinedStatusOriginalCSource()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := filepath.Join(dir, "original-c"+level)
			arguments := append([]string(nil), execution.compiler...)
			arguments = append(arguments, level, source, "-o", executable)
			x86FloatCompareCaptureCommand(t, exec.Command(arguments[0], arguments[1:]...))
			actual := execution.run(t, executable)
			if string(actual) != string(observations) {
				t.Fatalf("original Go/C full status/LAHF/canary transcript differs: Go=%x C=%x\n%s\n%s",
					sha256.Sum256(observations), sha256.Sum256(actual), observations, actual)
			}
			t.Logf("original observation agreement sha=%x; %s; not native ISA conformance",
				sha256.Sum256(actual), lines[len(lines)-1])
		})
	}
}

const x86DefinedStatusGoDriver = `package main

import (
    "fmt"
    "os"
)

func mask(bits uint) uint64 {
    if bits == 64 {
        return ^uint64(0)
    }
    return uint64(1)<<bits - 1
}

func flags(kind int, bits uint, left, right uint64) uint64 {
    if kind == 0 {
        if left&mask(bits) == 0 {
            return 64
        }
        return 0
    }
    if kind == 1 {
        var result uint64
        if left&right == 0 {
            result |= 64
        }
        if ^right&left == 0 {
            result |= 1
        }
        return result
    }
    var a, b [16]byte
    for i := 0; i < 8; i++ {
        a[i] = byte(right >> (8*uint(i)))
        b[i] = byte(left >> (8*uint(i)))
    }
    la, lb := 16, 16
    if kind == 2 {
        la, lb = int(int32(left)), int(int32(right))
        if la < 0 {
            la = -la
        }
        if lb < 0 {
            lb = -lb
        }
        if la > 16 {
            la = 16
        }
        if lb > 16 {
            lb = 16
        }
    } else {
        la, lb = 0, 0
        for la < 16 && a[la] != 0 {
            la++
        }
        for lb < 16 && b[lb] != 0 {
            lb++
        }
    }
    var matches uint64
    for i := 0; i < 16; i++ {
        if i >= la && i >= lb || i < la && i < lb && a[i] == b[i] {
            matches |= 1 << uint(i)
        }
    }
    var result uint64
    if matches != 0 {
        result |= 1
    }
    if lb < 16 {
        result |= 64
    }
    if la < 16 {
        result |= 128
    }
    if matches&1 != 0 {
        result |= 2048
    }
    return result
}

func main() {
    const observeActual = ACTUAL_OBSERVATIONS
    kernels := []func(*[8]uint64,uint64,uint64,uint64){KERNEL_NAMES}
    kinds := []int{KERNEL_KINDS}
    widths := []uint{KERNEL_WIDTHS}
    values := []uint64{0,1,0x55,0xaa,0xff,0xffff,0x80000000,^uint64(0)}
    const canary = uint64(0xa7a7a7a7a7a7a7a7)
    observations, failures, invalid := 0, 0, 0
    for index, kernel := range kernels {
        kernelFailures := 0
        for _, left := range values {
            for _, right := range values {
                for _, seed := range []uint64{0x8d7,0x12} {
                    var out [8]uint64
                    for i := range out {
                        out[i] = canary
                    }
                    kernel(&out,left,right,seed)
                    want := flags(kinds[index],widths[index],left,right)
                    invalidObservation := byte(out[1]) != byte(out[0]&0xd5|2) ||
                        out[1]>>8 != canary>>8
                    for i := 2; i < len(out); i++ {
                        invalidObservation = invalidObservation || out[i] != canary
                    }
                    if invalidObservation {
                        invalid++
                    }
                    if observeActual {
                        fmt.Printf("observed-status %d %016x", index, out[0]&0x8d5)
                        for i := 1; i < len(out); i++ {
                            fmt.Printf(" %016x", out[i])
                        }
                        fmt.Println()
                    }
                    bad := out[0]&0x8d5 != want || invalidObservation
                    if bad {
                        if !observeActual && failures < 12 {
                            fmt.Printf("original status kernel=%d left=%x right=%x flags=%x want=%x\n",index,left,right,out[0]&0x8d5,want)
                        }
                        failures++
                        kernelFailures++
                    }
                    observations++
                }
            }
        }
        if !observeActual && kernelFailures != 0 {
            fmt.Printf("original status kernel=%d failures=%d\n",index,kernelFailures)
        }
    }
    if observeActual {
        fmt.Printf("observed-status observations %d model-deviations %d invalid-observations %d\n",observations,failures,invalid)
        if invalid != 0 {
            os.Exit(1)
        }
        return
    }
    fmt.Printf("original defined-status observations %d failures %d\n",observations,failures)
    if failures != 0 {
        os.Exit(1)
    }
}
`

const x86DefinedStatusCDriver = `
#include <stdint.h>
#include <stdio.h>
#ifndef OBSERVE_ACTUAL
#define OBSERVE_ACTUAL 0
#endif
KERNEL_PROTOTYPES

typedef struct {
    void (*run)(uint64_t *, uint64_t, uint64_t, uint64_t);
    unsigned kind, bits;
    const char *name;
} Kernel;

static uint64_t mask(unsigned bits) {
    return bits == 64 ? UINT64_MAX : (UINT64_C(1)<<bits)-1;
}

static uint64_t flags(unsigned kind, unsigned bits, uint64_t left, uint64_t right) {
    if (kind == 0) {
        return (left&mask(bits)) == 0 ? 64 : 0;
    }
    if (kind == 1) {
        return (left&right ? 0 : 64) | (~right&left ? 0 : 1);
    }
    if (kind >= 4) {
        uint64_t m = mask(bits);
        left &= m;
        right &= m;
        if (kind == 4) {
            return (left&right ? 0 : 64) | (left&~right ? 0 : 1);
        }
        uint64_t combined = left|right;
        return (combined ? 0 : 64) | (combined == m ? 1 : 0);
    }
    unsigned char a[16] = {0}, b[16] = {0};
    for (unsigned i = 0; i < 8; i++) {
        a[i] = right>>(8*i);
        b[i] = left>>(8*i);
    }
    unsigned la = 16, lb = 16;
    if (kind == 2) {
        int64_t na = (int32_t)left, nb = (int32_t)right;
        if (na < 0) {
            na = -na;
        }
        if (nb < 0) {
            nb = -nb;
        }
        la = na > 16 ? 16 : (unsigned)na;
        lb = nb > 16 ? 16 : (unsigned)nb;
    } else {
        la = lb = 0;
        while (la < 16 && a[la]) {
            la++;
        }
        while (lb < 16 && b[lb]) {
            lb++;
        }
    }
    unsigned matches = 0;
    for (unsigned i = 0; i < 16; i++) {
        if ((i >= la && i >= lb) || (i < la && i < lb && a[i] == b[i])) {
            matches |= 1u<<i;
        }
    }
    return (matches ? 1 : 0) | (lb < 16 ? 64 : 0) | (la < 16 ? 128 : 0) |
        (matches&1 ? 2048 : 0);
}

int main(void) {
    Kernel kernels[] = {KERNELS};
    const uint64_t values[] = {0,1,0x55,0xaa,0xff,0xffff,0x80000000,UINT64_MAX};
    const uint64_t seeds[] = {0x8d7,0x12};
    const uint64_t canary = UINT64_C(0xa7a7a7a7a7a7a7a7);
    unsigned observations = 0, failures = 0, invalid = 0;
    for (unsigned index = 0; index < sizeof(kernels)/sizeof(kernels[0]); index++) {
        unsigned kernel_failures = 0;
        for (unsigned l = 0; l < 8; l++) {
            for (unsigned r = 0; r < 8; r++) {
                for (unsigned seed = 0; seed < 2; seed++) {
                    uint64_t out[8];
                    for (unsigned i = 0; i < 8; i++) {
                        out[i] = canary;
                    }
                    kernels[index].run(out,values[l],values[r],seeds[seed]);
                    uint64_t want = flags(kernels[index].kind,kernels[index].bits,values[l],values[r]);
                    int invalid_observation = (unsigned char)out[1] != ((out[0]&0xd5)|2) ||
                        (out[1]>>8) != (canary>>8);
                    for (unsigned i = 2; i < 8; i++) {
                        invalid_observation |= out[i] != canary;
                    }
                    invalid += !!invalid_observation;
                    if (OBSERVE_ACTUAL) {
                        printf("observed-status %u %016llx",index,(unsigned long long)(out[0]&0x8d5));
                        for (unsigned i = 1; i < 8; i++) {
                            printf(" %016llx",(unsigned long long)out[i]);
                        }
                        printf("\n");
                    }
                    int bad = (out[0]&0x8d5) != want || invalid_observation;
                    if (bad) {
                        if (!OBSERVE_ACTUAL && failures < 12) {
                            printf("LLVM status kernel=%u left=%llx right=%llx flags=%llx want=%llx\n",
                                index,(unsigned long long)values[l],(unsigned long long)values[r],
                                (unsigned long long)(out[0]&0x8d5),(unsigned long long)want);
                        }
                        failures++;
                        kernel_failures++;
                    }
                    observations++;
                }
            }
        }
        if (!OBSERVE_ACTUAL && kernel_failures) {
            printf("LLVM status family=%s failures=%u\n",kernels[index].name,kernel_failures);
        }
    }
    if (OBSERVE_ACTUAL) {
        printf("observed-status observations %u model-deviations %u invalid-observations %u\n",observations,failures,invalid);
        return invalid ? 1 : 0;
    }
    printf("LLVM defined-status observations %u failures %u\n",observations,failures);
    return failures ? 1 : 0;
}
`
