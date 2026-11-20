//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// VEX/EVEX numerical results use the independent original legacy SSE operation
// as reference. This is not native AVX512 execution or an upper-alias oracle;
// the separate complete-byte runtime root owns the alias axis.
func TestCrossLinuxRuntimeMatrixX86ScalarLaneNativeResultsAndFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, rows strings.Builder
	count := 0
	for _, row := range x86ScalarLaneNativeOracle {
		for discarded := 0; discarded < 3; discarded++ {
			if discarded == 2 && !strings.HasSuffix(row.op, "PS") {
				continue // The zero-selector axis belongs only to INSERTPS.
			}
			name, original := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count)
			asm, decl := x86ScalarLaneNativeFixture(name, "amd64", row.op, row.extract, "-1(DX)(BX*1)", false)
			immediate := 255
			if strings.HasSuffix(row.op, "PS") && discarded != 2 {
				immediate = 0xd0
			}
			if discarded == 2 {
				asm = strings.Replace(asm, "$208,", "$255,", 1)
			}
			native := fmt.Sprintf("%s $%d,(DI),X0\n%s,X0,AX\n",
				strings.TrimPrefix(row.op, "V"), immediate, strings.TrimPrefix(row.extract, "V"))
			if discarded == 1 {
				asm = strings.Replace(asm, "MOVQ AX,ret+8(FP)", "MOVQ $0x87654321fedcba98,AX\nMOVQ AX,ret+8(FP)", 1)
				native += "MOVQ $0x87654321fedcba98,AX\n"
			}
			source.WriteString(asm)
			declarations.WriteString(decl)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+native+"RET\n")
			var bytes []string
			for _, b := range code {
				bytes = append(bytes, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\nextern uint64_t %s(const uint8_t*);\n", name, original)
			fmt.Fprintf(&rows, "{%s,%s,%d,%d},\n", name, original, row.width, discarded)
			count++
		}
	}
	if count != 22 {
		t.Fatal("incomplete live/dead/zero scalar insertion family", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	driver := fmt.Sprintf(x86NativeScalarReadRuntimeC, prototypes.String(), originals.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
					text, level := ir, "-O0"
					if optimized {
						text, level = x86MulDivRoundOptimize(t, ir), "-O2"
					}
					output := execution.compileAndRunLLVM(t, "scalar-lane-native", text, driver, level)
					if string(output) != "22 native scalar kernels: numerical 2816, faults 264, tripwires 2; failures 0\n" {
						t.Fatal("original/LLVM scalar insertion results or read widths differ:", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}

// Scalar insertion, widening and GP/X transfer regressions share only their byte-read
// reference and process/fault harness, not their generated Go/LLVM programs.
const x86NativeScalarReadRuntimeC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
%s
%s
typedef uint64_t (*Program)(const uint8_t*);
typedef struct {
    Program translated, original;
    unsigned width, discarded;
    unsigned input_bytes, output_bytes;
} Kernel;
static const Kernel kernels[] = {%s};

static uint64_t reference(Kernel k, const uint8_t *p) {
    if (k.discarded == 1) return UINT64_C(0x87654321fedcba98);
    if (k.discarded == 2) return 0;
    uint64_t value = 0;
    if (k.output_bytes) {
        for (unsigned b = 0; b < 8; b++) {
            unsigned part = b %% k.output_bytes;
            if (part < k.input_bytes) {
                unsigned source = b / k.output_bytes * k.input_bytes + part;
                value |= (uint64_t)p[source] << (8*b);
            }
        }
        return value;
    }
    for (unsigned b = 0; b < k.width; b++) value |= (uint64_t)p[b] << (8*b);
    return value;
}

static int fault(Program run, const uint8_t *p) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
        volatile uint64_t result = run(p);
        (void)result;
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return -2;
    if (WIFEXITED(status)) return WEXITSTATUS(status) ? -3 : 0;
    if (WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS)) return 1;
    return -4;
}

static uint64_t missing_read(const uint8_t *p) { (void)p; return 0; }
static uint64_t too_wide(const uint8_t *p) { return *(volatile const uint64_t*)p; }

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page < 128) return 1;
    uint8_t *memory = mmap(0, 2*page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (memory == MAP_FAILED || mprotect(memory+page, page, PROT_NONE)) return 2;
    memset(memory, 0xa7, page);
    if (fault(missing_read, NULL) != 0 || fault(too_wide, memory+page-4) != 1) return 3;

    unsigned numerical = 0, faults = 0;
    for (unsigned i = 0; i < sizeof(kernels)/sizeof(kernels[0]); i++) {
        Kernel k = kernels[i];
        for (unsigned pattern = 0; pattern < 64; pattern++) {
            uint8_t bytes[64], before[64];
            for (unsigned b = 0; b < sizeof(bytes); b++) bytes[b] = (uint8_t)(pattern*37+b*11);
            memcpy(before, bytes, sizeof(bytes));
            const uint8_t *p = bytes+(pattern&1);
            uint64_t want = reference(k, p);
            if (k.original(p) != want || k.translated(p) != want || memcmp(bytes, before, sizeof(bytes))) {
                fprintf(stderr, "kernel %%u pattern %%u expected %%llx\n", i, pattern, (unsigned long long)want);
                return 4;
            }
            numerical += 2;
        }
        for (unsigned address = 0; address < 6; address++) {
            unsigned available[] = {0, 0, k.width ? k.width-1 : 0, k.width, k.width+1, 0};
            const uint8_t *p = address == 0 ? NULL : address == 5 ? memory+1 : memory+page-available[address];
            int want = k.width != 0 && address < 3;
            if (fault(k.original, p) != want || fault(k.translated, p) != want) {
                fprintf(stderr, "kernel %%u address %%u expected fault %%d\n", i, address, want);
                return 5;
            }
            faults += 2;
        }
    }
    if (munmap(memory, 2*page)) return 6;
    printf("%%zu native scalar kernels: numerical %%u, faults %%u, tripwires 2; failures 0\n",
           sizeof(kernels)/sizeof(kernels[0]), numerical, faults);
    return 0;
}
`
