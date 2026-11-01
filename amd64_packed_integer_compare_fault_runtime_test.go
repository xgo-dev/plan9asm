//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedIntegerCompareNativeMemoryStatus(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, prototypes, references, checks strings.Builder
	count := 0
	for opIndex, op := range x86PackedIntegerCompareTestNames {
		bits := []int{8, 16, 32, 64}[opIndex%4]
		widths := []int{16}
		if opIndex >= 8 {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			variants := []int{0}
			if opIndex >= 8 {
				variants = []int{1, 2}
				if width < 64 {
					variants = append(variants, 0)
				}
				if bits >= 32 {
					variants = append(variants, 3, 4)
				}
			}
			for _, variant := range variants {
				masked, broadcast := variant == 2 || variant == 4, variant >= 3
				name := fmt.Sprintf("faultcompare%d", count)
				count++
				fmt.Fprintf(&declarations, "func %s(input *byte,mask uint64)\n", name)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint64_t);\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ input+0(FP),BX\nMOVQ mask+8(FP),AX\nKMOVQ AX,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n", name)
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				operands := "(BX),X1"
				if opIndex >= 8 {
					mask, destination := "", bank+"0"
					if variant != 0 {
						destination = "K2"
					}
					if masked {
						mask = "K1,"
					}
					operands = fmt.Sprintf("(BX),%s1,%s%s", bank, mask, destination)
				}
				instruction := op
				if broadcast {
					instruction += ".BCST"
				}
				fmt.Fprintf(&source, "%s %s\nRET\n", instruction, operands)
				fmt.Fprintf(&references, "__attribute__((noinline)) static void reference%d(const uint8_t *p,uint64_t mask) {\n", count-1)
				if opIndex < 8 {
					mnemonic := strings.ToLower(strings.ReplaceAll(op, "L", "D"))
					references.WriteString("    typedef int32_t V __attribute__((vector_size(16)));\n    V value = {0,0,0,0};\n")
					fmt.Fprintf(&references, "    __asm__ volatile(\"%s (%%1),%%0\" : \"+x\"(value) : \"r\"(p) : \"memory\");\n", mnemonic)
				} else {
					bytes := bits / 8
					fmt.Fprintf(&references, "    for (int lane = 0; lane < %d; ++lane) {\n", width/bytes)
					if masked {
						references.WriteString("        if (!((mask>>lane)&1)) continue;\n")
					}
					offset := "lane*" + fmt.Sprint(bytes)
					if broadcast {
						offset = "0"
					}
					fmt.Fprintf(&references, "        for (int j = 0; j < %d; ++j) {\n            (void)((const volatile uint8_t*)p)[%s+j];\n        }\n", bytes, offset)
					references.WriteString("    }\n")
				}
				references.WriteString("}\n")
				lanes := width * 8 / bits
				masks := []uint64{0}
				if masked {
					masks = []uint64{0, 1, uint64(1) << uint(lanes-1), ^uint64(0)}
				}
				for _, mask := range masks {
					expectedReadable := "0"
					if opIndex < 8 {
						expectedReadable = "offset == 0 ? 0 : 2"
					}
					fmt.Fprintf(&checks, "    for (int offset = 0; offset < 16; ++offset) {\n        if (compare(reference%d,%s,memory+offset,UINT64_C(%d),%s)) return 1;\n    }\n", count-1, name, mask, expectedReadable)
					for _, offset := range []int{0, 1, bits / 8, 16, 32, 64} {
						expected := x86PackedIntegerCompareMemoryExpectation(opIndex < 8, width, bits/8, masked, broadcast, mask, offset, offset%16 == 0)
						fmt.Fprintf(&checks, "    if (compare(reference%d,%s,boundary-%d,UINT64_C(%d),%d)) return 1;\n", count-1, name, offset, mask, expected)
					}
					expectedNull := x86PackedIntegerCompareMemoryExpectation(opIndex < 8, width, bits/8, masked, broadcast, mask, 0, true)
					fmt.Fprintf(&checks, "    if (compare(reference%d,%s,0,UINT64_C(%d),%d)) return 1;\n", count-1, name, mask, expectedNull)
				}
			}
		}
	}
	x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
	ir, err := x86PackedIntegerCompareAPI(t, source.String(), declarations.String(), "amd64", triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	program := `#include <stdint.h>
#include <cpuid.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes.String() + references.String() + x86PackedIntegerCompareFaultStatusOracle + `
int main(void) {
    struct rlimit noCore = {0,0};
    if (setrlimit(RLIMIT_CORE,&noCore)) return 76;
    unsigned a,b,c,d;
    if (!__get_cpuid(1,&a,&b,&c,&d) || !(c&(1u<<19)) || !(c&(1u<<20))) {
        fprintf(stderr,"packed compare fault root requires actual SSE4.1 and SSE4.2\n");
        return 77;
    }
    __asm__ volatile("pxor %%xmm0,%%xmm0\n\t"
                     "pcmpeqq %%xmm0,%%xmm0\n\t"
                     "pcmpgtq %%xmm0,%%xmm0" : : : "xmm0");
    printf("packed compare fault preflight: CPUID SSE4.1=1 SSE4.2=1; actual PCMPEQQ/PCMPGTQ executed\n");
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || page%64) return 1;
    uint8_t *memory = mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANON,-1,0);
    if (memory == MAP_FAILED) return 1;
    memset(memory,0x87,(size_t)page);
    if (mprotect(memory,(size_t)page,PROT_READ) ||
        mprotect(memory+page,(size_t)page,PROT_NONE)) return 1;
    uint8_t *boundary = memory+page;
` + checks.String() + `
    if (munmap(memory,(size_t)page*2)) return 1;
    return 0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-compare-fault", triple, text, program, prefix)
		})
	}
	t.Logf("%d dead-result programs at mod16/NULL/read-only guard pages, exact native legacy and independent E4 lane-read status at O0/O2; not native EVEX execution", count)
}

// Expected status comes from the independently constructed fixture accesses,
// not a production descriptor. 0 requires normal exit0; 1 requires a memory
// fault. Only readable, unaligned legacy sources use 2: preserve the original
// machine's exact alignment behavior without guessing a vendor's fault policy.
func x86PackedIntegerCompareMemoryExpectation(legacy bool, width, laneBytes int, masked, broadcast bool, mask uint64, available int, aligned bool) int {
	if legacy {
		if available < 16 {
			return 1
		}
		if !aligned {
			return 2
		}
		return 0
	}
	readEnd := 0
	for lane := 0; lane < width/laneBytes; lane++ {
		if masked && mask&(uint64(1)<<uint(lane)) == 0 {
			continue
		}
		end := (lane + 1) * laneBytes
		if broadcast {
			end = laneBytes
		}
		if end > readEnd {
			readEnd = end
		}
	}
	if readEnd > available {
		return 1
	}
	return 0
}

const x86PackedIntegerCompareFaultStatusOracle = `
typedef struct { int signal; int code; } Status;

static int observe(void (*fn)(const uint8_t*,uint64_t),const uint8_t *p,
                   uint64_t mask,Status *out) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        struct rlimit limit = {0,0};
        if (setrlimit(RLIMIT_CORE,&limit)) _exit(3);
        fn(p,mask);
        _exit(0);
    }
    int status;
    if (waitpid(child,&status,0) != child) return 1;
    if (WIFSIGNALED(status)) {
        *out = (Status){WTERMSIG(status),0};
        return 0;
    }
    if (WIFEXITED(status)) {
        *out = (Status){0,WEXITSTATUS(status)};
        return 0;
    }
    return 1;
}

static int compare(void (*original)(const uint8_t*,uint64_t),
                   void (*translated)(const uint8_t*,uint64_t),
                   const uint8_t *p,uint64_t mask,int expectation) {
    Status a,b;
    if (observe(original,p,mask,&a) || observe(translated,p,mask,&b)) return 1;
    int allowedA = a.code == 0 && (a.signal == 0 || a.signal == SIGSEGV || a.signal == SIGBUS);
    int allowedB = b.code == 0 && (b.signal == 0 || b.signal == SIGSEGV || b.signal == SIGBUS);
    if (!allowedA || !allowedB || expectation < 0 || expectation > 2 ||
        (expectation == 0 && (a.signal || b.signal)) ||
        (expectation == 1 && (!a.signal || !b.signal)) ||
        a.signal != b.signal || a.code != b.code) {
        fprintf(stderr,"mod16=%lu mask=%llx original=(%d,%d) translated=(%d,%d)\n",
                (unsigned long)((uintptr_t)p%16),(unsigned long long)mask,
                a.signal,a.code,b.signal,b.code);
        return 1;
    }
    return 0;
}
`

func TestX86PackedIntegerCompareFaultStatusRejectsSymmetricUnexpectedExit(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	// The child observations are real, but these deliberately raised signals
	// test the oracle's status domain, not a memory fault or native opcode.
	// Run on the actual host; this C-only control has no x86 ISA requirement.
	program := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + x86PackedIntegerCompareFaultStatusOracle + `
static int selectedSignal;

static void unexpected(const uint8_t *p,uint64_t mask) {
    if (!selectedSignal) {
        _exit(7);
    }
    raise(selectedSignal);
}

static void complete(const uint8_t *p,uint64_t mask) {}

int main(void) {
    const int rejected[] = {SIGILL,SIGABRT,SIGFPE,SIGTRAP,0};
    for (unsigned i = 0; i < sizeof(rejected)/sizeof(rejected[0]); ++i) {
        selectedSignal = rejected[i];
        if (!compare(unexpected,unexpected,0,0,2)) {
            fprintf(stderr,"symmetric unexpected status accepted: signal=%d\n",selectedSignal);
            return 1;
        }
    }
    return compare(complete,complete,0,0,0);
}
`
	ir := "target triple = \"" + execution.triple + "\"\ndefine void @status_tripwire_object() { ret void }\n"
	execution.compileAndRunLLVM(t, "packed-compare-status-tripwire", ir, program, "-O2")
}

func TestX86PackedIntegerCompareFaultStatusRequiresSuccessfulReadableControl(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	// Deliberately raised memory signals are classification tripwires. They do
	// not replace the independently mapped native-width fixtures above.
	program := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + x86PackedIntegerCompareFaultStatusOracle + `
static void unexpectedMemoryFault(const uint8_t *p,uint64_t mask) {
    raise(SIGSEGV);
}

static void complete(const uint8_t *p,uint64_t mask) {}

int main(void) {
    if (!compare(unexpectedMemoryFault,unexpectedMemoryFault,0,0,0)) {
        fprintf(stderr,"symmetric memory fault replaced required successful control\n");
        return 1;
    }
    if (compare(unexpectedMemoryFault,unexpectedMemoryFault,0,0,1)) return 2;
    return compare(complete,complete,0,0,0);
}
`
	ir := "target triple = \"" + execution.triple + "\"\ndefine void @readable_tripwire_object() { ret void }\n"
	execution.compileAndRunLLVM(t, "packed-compare-readable-tripwire", ir, program, "-O2")
}

func TestX86PackedIntegerCompareFaultExpectedAccessMatrix(t *testing.T) {
	for _, test := range []struct {
		name                      string
		legacy, masked, broadcast bool
		width, bytes, available   int
		mask                      uint64
		aligned                   bool
		want                      int
	}{
		{"legacy-aligned-readable", true, false, false, 16, 8, 16, 0, true, 0},
		{"legacy-unaligned-readable", true, false, false, 16, 8, 16, 0, false, 2},
		{"legacy-guard-overlap", true, false, false, 16, 8, 15, 0, true, 1},
		{"vex-full-readable-unaligned", false, false, false, 32, 4, 32, 0, false, 0},
		{"vex-full-guard-overlap", false, false, false, 32, 4, 31, 0, false, 1},
		{"evex-zero-mask-null", false, true, false, 64, 1, 0, 0, true, 0},
		{"evex-low-lane-readable", false, true, false, 64, 1, 1, 1, false, 0},
		{"evex-high-lane-guard", false, true, false, 64, 1, 63, uint64(1) << 63, false, 1},
		{"evex-high-lane-readable", false, true, false, 64, 1, 64, uint64(1) << 63, false, 0},
		{"broadcast-zero-mask-null", false, true, true, 64, 8, 0, 0, false, 0},
		{"broadcast-readable", false, true, true, 64, 8, 8, 0xff, false, 0},
		{"broadcast-guard-overlap", false, true, true, 64, 8, 7, 0xff, false, 1},
		{"broadcast-irrelevant-mask-null", false, true, true, 16, 8, 0, 4, false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := x86PackedIntegerCompareMemoryExpectation(test.legacy, test.width, test.bytes,
				test.masked, test.broadcast, test.mask, test.available, test.aligned)
			if got != test.want {
				t.Fatalf("independent expected access status=%d, want=%d", got, test.want)
			}
		})
	}
}
