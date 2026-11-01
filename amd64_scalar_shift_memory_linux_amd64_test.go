package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarShiftMemoryNative(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	rows := x86ShiftMemoryRuntimeRows("amd64")
	if len(rows) != 144 {
		t.Fatal("incomplete native defined-count memory family", len(rows))
	}
	for first := 0; first < len(rows); first += 72 {
		t.Run(fmt.Sprint("batch-", first/72), func(t *testing.T) {
			batch := rows[first : first+72]
			source, declaration, driver := x86ShiftMemoryRuntimeFixture("amd64", batch)
			x86LEAActualTargetGoObject(t, "amd64", execution.triple, source)
			var definitions, functions strings.Builder
			definitions.WriteString("#define ORIGINAL_NATIVE 1\n")
			for i, row := range batch {
				name := fmt.Sprint("OriginalMemoryShift", i)
				// SysV supplies p/out/value/count/seed in DI/SI/DX/CX/R8.
				// All touched GPs are caller-clobbered; stack depth is balanced.
				body := "TEXT native(SB),4,$0-0\nMOVQ DX,AX\nPUSHQ R8\nPOPFQ\n" + row.text +
					fmt.Sprintf("\nPUSHFQ\nPOPQ DX\nANDQ $%d,DX\nMOVQ DX,0(SI)\nMOVQ AX,8(SI)\nMOVQ CX,16(SI)\nRET\n", row.flags)
				code := x86OrderingHintGoBytes(t, "amd64", body)
				var bytes []string
				for _, b := range code {
					bytes = append(bytes, fmt.Sprintf("0x%02x", b))
				}
				fmt.Fprintf(&definitions, "extern void %s(uint8_t*,uint64_t*,word,word,word);\n", name)
				fmt.Fprintf(&definitions, "__asm__(%q);\n", ".text\n.globl "+name+"\n"+name+":\n.byte "+strings.Join(bytes, ",")+"\n")
				fmt.Fprintf(&functions, "%s,\n", name)
			}
			fmt.Fprintf(&definitions, "static void (*originals[])(uint8_t*,uint64_t*,word,word,word) = {%s};\n", functions.String())
			definitions.WriteString(x86ShiftMemoryNativeFaultC)
			driver = strings.Replace(driver, "/* Original Go opcode definitions. */", definitions.String(), 1)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, optimized := range []bool{false, true} {
						text := ir
						if optimized {
							text = x86DwordProductIROptimize(t, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
								output := execution.compileAndRunLLVM(t, "scalar-shift-memory-native", text, driver, level)
								want := fmt.Sprintf("scalar shift memory observations %d\n", len(batch)*256*7*2)
								if string(output) != want {
									t.Fatal("native numerical/fault denominator incomplete", string(output), want)
								}
							})
						}
					}
				})
			}
		})
	}
	x87IA32RequireNativeHost(t)
}

const x86ShiftMemoryNativeFaultC = `
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static int outcome(void (*fn)(uint8_t*,uint64_t*,word,word,word), uint8_t *p, word count) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        struct rlimit limit = {0,0};
        if (setrlimit(RLIMIT_CORE,&limit)) _exit(2);
        uint64_t output[8] = {0};
        fn(p,output,UINT64_MAX,count,0x8c7);
        _exit(0);
    }
    int status;
    if (waitpid(child,&status,0) != child) return -1;
    if (WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS)) return 1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    return -1;
}

static int check_faults(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return 1;
    uint8_t *memory = mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (memory == MAP_FAILED || mprotect(memory+page,page,PROT_NONE)) return 1;
    unsigned observations = 0;
    const word counts[] = {0,1,255};
    for (unsigned kernel = 0; kernel < sizeof(kernels)/sizeof(kernels[0]); kernel++) {
        const Kernel k = kernels[kernel];
        void (*implementations[])(uint8_t*,uint64_t*,word,word,word) = {k.fn,originals[kernel]};
        for (unsigned which = 0; which < 2; which++) {
            for (unsigned c = 0; c < 3; c++) {
                uint8_t *last = memory+page-k.bits/8-1;
                if (outcome(implementations[which],last,counts[c]) != 0 ||
                    outcome(implementations[which],last+1,counts[c]) != 1 ||
                    outcome(implementations[which],NULL,counts[c]) != 1) {
                    fprintf(stderr,"kernel%u impl%u count%llu: exact width/NULL fault mismatch\n",
                        kernel,which,(unsigned long long)counts[c]);
                    return 1;
                }
                if (mprotect(memory,page,PROT_READ)) return 1;
                int result = outcome(implementations[which],memory+32,counts[c]);
                if (mprotect(memory,page,PROT_READ|PROT_WRITE)) return 1;
                if (result != (k.kind >= 10 ? 0 : 1)) {
                    fprintf(stderr,"kernel%u impl%u count%llu: read-only RMW fault mismatch\n",
                        kernel,which,(unsigned long long)counts[c]);
                    return 1;
                }
                observations += 4;
            }
        }
    }
    if (munmap(memory,page*2)) return 1;
    return observations != sizeof(kernels)/sizeof(kernels[0])*2*3*4;
}
`
