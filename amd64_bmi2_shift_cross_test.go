package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
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

	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range x86BMI2ShiftTestOps {
		kind := 0
		if strings.HasPrefix(op, "SHRX") {
			kind = 1
		} else if strings.HasPrefix(op, "SARX") {
			kind = 2
		}

		for _, raw := range []bool{false, true} {
			for _, destination := range []string{"CX", "SP"} {
				name := fmt.Sprintf("shift386_%d", index)
				index++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-12\n", name)
				source.WriteString("MOVL count+0(FP),AX\nMOVL source+4(FP),BX\n")
				line := fmt.Sprintf("%s AX,(BX),%s\n", op, destination)
				if raw {
					code := assembleX87ControlBytes(t, "386", "TEXT probe(SB),4,$0-0\n"+line+"RET\n")
					for _, b := range code[:len(code)-1] {
						fmt.Fprintf(&source, "BYTE $%#02x\n", b)
					}
				} else {
					source.WriteString(line)
				}
				fmt.Fprintf(&source, "MOVL %s,ret+8(FP)\nRET\n", destination)

				sigs[name] = FuncSig{
					Name: name,
					Args: []LLVMType{I32, Ptr},
					Ret:  I32,
					Frame: FrameLayout{
						Params: []FrameSlot{
							{Offset: 0, Type: I32, Index: 0, Field: -1},
							{Offset: 4, Type: Ptr, Index: 1, Field: -1},
						},
						Results: []FrameSlot{
							{Offset: 8, Type: I32, Index: 0, Field: -1},
						},
					},
				}
				fmt.Fprintf(&declarations, "extern uint32_t %s(uint32_t, const uint32_t*);\n", name)
				fmt.Fprintf(&checks, "    if (check(%s, value, %d)) return %d;\n", name, kind, index)
			}
		}
	}
	if index != 24 {
		t.Fatalf("generated %d functions, want 24", index)
	}

	file, err := Parse(ArchAMD64, source.String())
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
` + declarations.String() + x86BMI2ShiftOracleC + `
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
` + checks.String() + "    return munmap(memory, page * 2) != 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc"}, "bmi2_shift_386",
		"i386-unknown-linux-gnu", ir, mainC, []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
}
