package plan9asm

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// Keep this in the required CI cross-runtime regex, not an optional native test.
func TestCrossLinuxRuntimeMatrixBMI2Shift386(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for the required Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime driver requires linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"i686-linux-gnu-gcc", "qemu-i386"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", tool, err)
		}
	}

	// Execute the explicitly separate CX/DX companion. The historical CX/SP
	// source remains covered by complete Go objects and public Context tests;
	// its unrecovered physical ESP write is not a valid ABI0 return program.
	source, sigs, declarations, checks := x86BMI2Shift386Fixture(t, "DX")

	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
` + declarations + x86BMI2ShiftOracleC + `
static void memory_fault(int signal_number) {
    (void)signal_number;
    _exit(98);
}

static int check(uint32_t (*fn)(uint32_t, const uint32_t*), uint32_t *value, int kind) {
    uint32_t values[] = {0, 1, UINT32_MAX, 0x80000000U, 0x7fffffffU, 0xfedcba98U};
    for (unsigned n = 0; n < 256; n++) {
        *value = values[n % 6];
        uint32_t count = n < 128 ? n : UINT32_MAX - n;
        if (fn(count, value) != shift_reference(*value, count, 32, kind)) {
            fprintf(stderr, "386 kind=%d case=%u\n", kind, n);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    if (signal(SIGSEGV, memory_fault) == SIG_ERR) return 92;
    long page = sysconf(_SC_PAGESIZE);
    if (page < 4) return 90;

    uint8_t *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED || mprotect(memory + page, page, PROT_NONE)) return 91;
    uint32_t *value = (uint32_t *)(memory + page - 4);
` + checks + "    return munmap(memory, page * 2) != 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc"}, "bmi2_shift_386",
		"i386-unknown-linux-gnu", ir, mainC, []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
}
