package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Native opcode outcomes, not CPUID advertisements, establish availability and
// fault behavior. This is an instruction-level C observer tied to original Go
// opcode bytes, not execution of the stock Go ABI0 caller or a native CI claim.
func TestX86CMPXCHGOriginalOpcodeOutcomeEquivalence(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	x86CMPXCHGRunFaultCollector(t, execution, false)
}

func x86CMPXCHGRunFaultCollector(t *testing.T, execution x86FloatCompareExecution, native bool) {
	t.Helper()
	var assembly, declarations, prototypes, originals, cases strings.Builder
	declarations.WriteString("package ordering\n")
	for index, row := range x86CMPXCHGOriginalRows {
		for _, locked := range []bool{false, true} {
			name := fmt.Sprintf("cas%d_%t", index, locked)
			body := x86CMPXCHGOriginalBody(index, "(SI)")
			if locked {
				body = "LOCK\n\t" + body
			}
			// Use the source register initialized by the reference: desired low
			// is in CX for scalar forms, and BX/CX for pair forms.
			source := strings.Replace(x86NamedLockOracleSource("amd64", body), "·locked", "·"+name, 1)
			actual := x86OrderingHintGoBytes(t, "amd64", source)
			opcode := []byte{0x0f, 0xb1, 0x0e}
			switch row.bits {
			case 8:
				if !row.pair {
					opcode = []byte{0x0f, 0xb0, 0x0e}
				}
			case 16:
				opcode = append([]byte{0x66}, opcode...)
			case 64:
				if row.pair {
					opcode = []byte{0x0f, 0xc7, 0x0e}
				} else {
					opcode = append([]byte{0x48}, opcode...)
				}
			case 128:
				opcode = []byte{0x48, 0x0f, 0xc7, 0x0e}
			}
			if locked {
				opcode = append([]byte{0xf0}, opcode...)
			}
			if !bytes.HasSuffix(actual, append(append([]byte(nil), opcode...), 0xc3)) {
				t.Fatalf("complete original opcode/prefix binding changed: %s %x", name, actual)
			}
			t.Logf("actual Go %s terminal machine bytes=%x; object identity only", name, opcode)
			assembly.WriteString(source)
			fmt.Fprintf(&declarations, "func %s(p *[32]byte)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(unsigned char *);\n", name)
			fmt.Fprintf(&cases, "    {%s, original_%s, %d, %d},\n", name, name, row.bits/8, index)
			prefix := ""
			if locked {
				prefix = "lock; "
			}
			if row.pair {
				part, mnemonic := "uint32_t", "cmpxchg8b"
				if row.bits == 128 {
					part, mnemonic = "uint64_t", "cmpxchg16b"
				}
				fmt.Fprintf(&originals, `static void original_%s(unsigned char *p) {
    %s low = 2, high = 5;
    __asm__ volatile("%s%s (%%4)"
        : "+a"(low), "+d"(high)
        : "b"((%s)3), "c"((%s)4), "r"(p)
        : "cc", "memory");
}
`, name, part, prefix, mnemonic, part, part)
			} else {
				typ := fmt.Sprintf("uint%d_t", row.bits)
				width := map[int]string{8: "b", 16: "w", 32: "l", 64: "q"}[row.bits]
				fmt.Fprintf(&originals, `static void original_%s(unsigned char *p) {
    %s accumulator = 2;
    __asm__ volatile("%scmpxchg%s %%1, (%%2)"
        : "+a"(accumulator)
        : "c"((%s)4), "r"(p)
        : "cc", "memory");
}
`, name, typ, prefix, width, typ)
			}
		}
	}
	ir, err := x86OrderingHintTranslateAPI(t, "text", assembly.String(), declarations.String(), "amd64", execution.triple)
	if err != nil {
		t.Fatal(err)
	}
	reference := fmt.Sprintf(x86CMPXCHGFaultReference, prototypes.String(), originals.String(), cases.String())
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			executable := execution.compileLLVM(t, "cmpxchg-fault", ir, reference, level)
			observations, deviations := 0, 0
			for index := 0; index < len(x86CMPXCHGOriginalRows)*2; index++ {
				for address := 0; address < 4; address++ {
					original, err := x86CMPXCHGObserveFault(t, execution, executable, index, address, 1)
					if err != nil {
						t.Fatal(err)
					}
					translated, err := x86CMPXCHGObserveFault(t, execution, executable, index, address, 0)
					if err != nil {
						t.Fatal(err)
					}
					if original != translated {
						t.Fatalf("kernel %d address %d: original %s, translated %s", index, address, original, translated)
					}
					misalignedPair := x86CMPXCHGOriginalRows[index/2].bits == 128 && address == 1
					fault := address >= 2 || misalignedPair
					if fault && original != "segv" && original != "bus" || !fault && original != "return" {
						deviations++
					}
					if native && misalignedPair && original != "segv" {
						t.Fatal("native Linux misaligned CMPXCHG16B did not report #GP as SIGSEGV")
					}
					observations += 2
				}
			}
			if observations != 96 || native && deviations != 0 {
				t.Fatalf("CMPXCHG opcode outcomes %d, ISA deviations %d", observations, deviations)
			}
			t.Logf("CMPXCHG opcode outcomes %d; ISA deviations %d; outcome failures 0", observations, deviations)
		})
	}
}

const x86CMPXCHGFaultReference = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
` + x86TestGuardPagesC + `

%s
%s
typedef struct {
    void (*translated)(unsigned char *);
    void (*original)(unsigned char *);
    unsigned width, family;
} Kernel;

static int exercise(Kernel kernel, unsigned index, unsigned address, unsigned original) {
    _Alignas(16) unsigned char raw[64];
    memset(raw, 0xa7, sizeof(raw));
    unsigned char *p = raw + 16;
    if (address == 1) p++;
    if (address == 2) p = NULL;
    if (address == 3) {
        if (setup_guard()) return 82;
        memset(guard, 0xa7, page);
        p = guard + page - (kernel.width - 1);
    }
    unsigned char expected[16] = {0};
    uint64_t low = 2, high = 5, desired_low = 3, desired_high = 4;
    if (kernel.family == 4) {
        uint32_t pair[2] = {2, 5}, desired[2] = {3, 4};
        memcpy(expected, desired, 8);
        if (address < 2) memcpy(p, pair, 8);
    } else if (kernel.family == 5) {
        memcpy(expected, &desired_low, 8);
        memcpy(expected + 8, &desired_high, 8);
        if (address < 2) {
            memcpy(p, &low, 8);
            memcpy(p + 8, &high, 8);
        }
    } else {
        memcpy(expected, &desired_high, kernel.width);
        if (address < 2) memcpy(p, &low, kernel.width);
    }
    if (printf("CMPXCHG enter %%u %%u %%u\n", index, address, original) < 0 || fflush(stdout)) return 87;
    if (original) kernel.original(p);
    else kernel.translated(p);
    if (address == 3 && free_guard()) return 83;
    if (address >= 2) return 84;
    if (memcmp(p, expected, kernel.width)) return 85;
    size_t begin = (size_t)(p - raw);
    for (size_t i = 0; i < sizeof(raw); i++) {
        if ((i < begin || i >= begin + kernel.width) && raw[i] != 0xa7) return 86;
    }
    if (puts("CMPXCHG complete") < 0 || fflush(stdout)) return 88;
    return 0;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 120;
#endif
    Kernel kernels[] = {
%s
    };
    if (argc != 4 || strlen(argv[1]) > 2 || strlen(argv[2]) != 1 || strlen(argv[3]) != 1) return 80;
    unsigned long values[3];
    for (unsigned i = 0; i < 3; i++) {
        char *end;
        if (argv[i+1][0] < '0' || argv[i+1][0] > '9') return 80;
        values[i] = strtoul(argv[i+1], &end, 10);
        if (*end) return 80;
    }
    if (values[0] >= sizeof(kernels)/sizeof(kernels[0]) || values[1] >= 4 || values[2] >= 2) return 80;
    return exercise(kernels[values[0]], (unsigned)values[0], (unsigned)values[1], (unsigned)values[2]);
}
`
