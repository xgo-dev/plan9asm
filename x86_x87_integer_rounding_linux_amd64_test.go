//go:build linux && amd64

package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A mandatory actual-Linux owner, not a portable test with a host skip.
// Both ISAs use direct execution; missing tools or i386 compatibility fail.
func TestCrossLinuxRuntimeMatrixX86X87SignedI64IdentityOriginalGoAndLLVM(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc, clang, found := findLlcAndClang(t)
	compiler386, compilerErr := exec.LookPath("i686-linux-gnu-gcc")
	if !found || compilerErr != nil {
		t.Fatal("native x87 I64 identity requires LLVM22 and static i686 toolchain", compilerErr)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
				compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
			stack := "movq %%rsp,%0"
			if arch == "386" {
				execution.triple = "i386-unknown-linux-gnu"
				execution.compiler = []string{compiler386, "-static", "-no-pie", "-maccumulate-outgoing-args"}
				stack = "movl %%esp,%0"
			}
			x86X87RunSignedI64Identity(t, arch, stack, execution)
		})
	}
	x87IA32RequireNativeHost(t)
}

func x86X87RunSignedI64Identity(t *testing.T, arch, stack string, execution x86FloatCompareExecution) {
	t.Helper()
	if len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("mandatory original/LLVM identity owner requires direct native transport")
	}
	var goInputs strings.Builder
	for _, value := range x86X87SignedI64IdentityInputs {
		fmt.Fprintf(&goInputs, "0x%x,\n", uint64(value))
	}
	originalDriver := `package main
import "fmt"
` + x86X87SignedI64IdentityDeclaration + `
func main() {
    inputs := []uint64{` + goInputs.String() + `}
    for _, input := range inputs {
        value := Value(int64(input))
        if uint64(value) != input {
            panic(fmt.Sprintf("original Go I64 identity input=%016x got=%016x", input, uint64(value)))
        }
        fmt.Printf("%016x\n", uint64(value))
    }
}
`
	formatted, err := format.Source([]byte(originalDriver))
	if err != nil {
		t.Fatal("actual Go integer oracle driver is malformed", err)
	}
	dir := t.TempDir()
	sources := map[string]string{
		"go.mod":  "module x87identity\n\ngo 1.20\n",
		"main.go": string(formatted), "identity_" + arch + ".s": x86X87SignedI64IdentitySource,
	}
	for name, source := range sources {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("original complete input=%s sha256=%x", name, sha256.Sum256([]byte(source)))
	}
	driver, driverHash := x86LEAActualSDKDriver(t)
	original := filepath.Join(dir, "original")
	command := exec.Command(driver, "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	verifySource := func() {
		for name, source := range sources {
			actual, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(actual) != source {
				t.Fatal("complete original identity source changed", name, err)
			}
		}
		if actual, hash := x86LEAActualSDKDriver(t); actual != driver || hash != driverHash {
			t.Fatal("original compiler driver changed around observation")
		}
	}
	run := func(executable string, args ...string) []byte {
		if arch == "amd64" {
			return execution.run(t, executable, args...)
		}
		sealed, err := x87IA32StaticExecutable(executable)
		if err != nil {
			t.Fatal("original/LLVM i386 execution needs its complete static ELF", err)
		}
		return x87IA32RunDirect(t, sealed, args, os.Environ())
	}
	verifySource()
	records := run(original)
	var expected strings.Builder
	for _, value := range x86X87SignedI64IdentityInputs {
		fmt.Fprintf(&expected, "%016x\n", uint64(value))
	}
	if string(records) != expected.String() {
		t.Fatalf("actual original Go did not execute the complete exact I64 inventory: %s", records)
	}
	reference := filepath.Join(dir, "original.records")
	if err := os.WriteFile(reference, records, 0600); err != nil {
		t.Fatal(err)
	}
	verifyRecords := func() {
		actual, err := os.ReadFile(reference)
		if err != nil || string(actual) != string(records) {
			t.Fatal("original identity records changed around LLVM execution", err)
		}
	}
	want := fmt.Sprintf("x87 I64 original-Go/LLVM identity checks=%d\n", len(x86X87SignedI64IdentityInputs))
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86X87InitializedWordAPI(t, x86X87SignedI64IdentitySource,
			x86X87SignedI64IdentityDeclaration, arch, execution.triple, api, X87Hardware)
		if err != nil || ir == "" {
			t.Fatal("complete hardware integer identity did not translate", err)
		}
		// The output-array canaries below test this explicit observer's
		// boundary, not the original Go caller's ABI0 outgoing stack slots.
		ir += `
define void @ObserveIdentity(ptr %output, i64 %input) {
entry:
  %value = call i64 @Value(i64 %input)
  %middle = getelementptr i64, ptr %output, i32 1
  store i64 %value, ptr %middle, align 1
  ret void
}
`
		for _, optimized := range []bool{false, true} {
			input := ir
			if optimized {
				input = x86MulDivRoundOptimize(t, input)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(fmt.Sprintf("%s/IR_O2=%t/backend%s", api, optimized, level), func(t *testing.T) {
					executable := execution.compileLLVM(t, "x87-i64", input, x86X87I64NativeDriver(stack), level)
					verifySource()
					verifyRecords()
					if actual := run(executable, reference); string(actual) != want {
						t.Fatal("original Go/LLVM full-bit identity or explicit observer/SP boundary mismatch", string(actual))
					}
					verifyRecords()
					verifySource()
				})
			}
		}
	}
	verifyRecords()
	verifySource()
}

func x86X87I64NativeDriver(stack string) string {
	return `#include <stdint.h>
#include <stdio.h>

extern void ObserveIdentity(uint64_t *, int64_t);

static __attribute__((always_inline)) inline uintptr_t stack_pointer(void) {
    uintptr_t value;
    __asm__ volatile("` + stack + `" : "=r"(value) : : "memory");
    return value;
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 1;
    FILE *reference = fopen(argv[1], "r");
    if (!reference)
        return 2;

    unsigned checks = 0;
    unsigned long long expected;
    while (fscanf(reference, "%llx", &expected) == 1) {
        const uint64_t left = UINT64_C(0x1122334455667788),
            right = UINT64_C(0x8877665544332211);
        volatile uint64_t output[] = {left, 0, right};
        const uintptr_t before = stack_pointer();
        ObserveIdentity((uint64_t *)output, (int64_t)(uint64_t)expected);
        const uintptr_t after = stack_pointer();
        if (output[0] != left || output[2] != right || output[1] != (uint64_t)expected || before != after) {
            fprintf(stderr, "x87 I64 input=%016llx got=%016llx SP=%llx/%llx or explicit observer boundary changed\n",
                expected, (unsigned long long)output[1],
                (unsigned long long)before, (unsigned long long)after);
            fclose(reference);
            return 3;
        }
        checks++;
    }
    const int complete = feof(reference);
    const int close_result = fclose(reference);
    if (!complete || close_result)
        return 4;
    printf("x87 I64 original-Go/LLVM identity checks=%u\n", checks);
    return 0;
}
`
}
