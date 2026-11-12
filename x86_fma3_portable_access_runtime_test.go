//go:build (darwin && arm64) || (linux && (amd64 || arm64))

package plan9asm

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// ARM64 hosts execute the portable translation natively. Linux/AMD64 has an
// explicit AArch64 cross-runtime counterpart in the existing cross matrix.
// Neither route executes original x86 Go code or certifies x86 FP status.
func TestCrossLinuxRuntimeMatrixX86FMA3AArch64DeadSourceAccess(t *testing.T) {
	x86FMA3PortableAccessGoPrior(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	execution := x86FloatCompareExecution{
		llc: llc, triple: testTargetTriple(runtime.GOOS, "arm64"), compiler: []string{clang},
	}
	if runtime.GOARCH == "amd64" {
		execution.triple = "aarch64-unknown-linux-gnu"
		execution.compiler = []string{"aarch64-linux-gnu-gcc"}
		execution.prefix = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
		t.Log("explicit AArch64 QEMU access execution, not bare native or x86 execution")
	} else {
		t.Log("native ARM64 portable access execution, not original x86 execution")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			var source, declarations, prototypes, metadata strings.Builder
			admitted, contexts, faults := 0, 0, 0
			for index, row := range x86FMA3PortableAccessCases() {
				if row.bytes != 0 {
					faults += 3 // The independent reference's NULL and two guard probes.
				}
				name := fmt.Sprint("Access", index)
				register, declaration, _ := x86FMA3PortableAccessSource(row, name+"Register", false)
				if ir, err := x86ScalarFPBitViewAPI(t, register, declaration, "amd64", execution.triple, api); err != nil || ir == "" {
					t.Fatal("register control did not establish public AArch64 admission", err)
				}
				// Keep these controls in the final module even if every access
				// explicitly remains Context. Reference execution is still real.
				source.WriteString(register)
				declarations.WriteString(declaration)
				program, declaration, instruction := x86FMA3PortableAccessSource(row, name, true)
				ir, err := x86ScalarFPBitViewAPI(t, program, declaration, "amd64", execution.triple, api)
				function := "NULL"
				if x86FMA3PortableAccessContext(t, ir, err, instruction) {
					contexts++
				} else {
					admitted++
					if row.bytes != 0 {
						faults += 3 // The translated program's identical fault probes.
					}
					function = name
					source.WriteString(program)
					declarations.WriteString(declaration)
					fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *);\n", name)
				}
				fmt.Fprintf(&metadata, "{%q,%s,%d},\n", row.name, function, row.bytes)
			}
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("individually admitted portable accesses failed the complete source join", err)
			}
			main := strings.NewReplacer("@PROTOTYPES@", prototypes.String(), "@ROWS@", metadata.String()).Replace(x86FMA3PortableAccessReferenceC)
			for _, pipeline := range []struct {
				name, level string
				optimize    bool
			}{
				{"backend_O0", "-O0", false},
				{"backend_O2", "-O2", false},
				{"IR_O2/backend_O2", "-O2", true},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					text := ir
					if pipeline.optimize {
						text = x86DwordProductIROptimize(t, text)
					}
					executable := execution.compileLLVM(t, "fma-portable-dead-access", text, main, pipeline.level)
					arguments := execution.command(executable)
					ctx, cancel := runtimeOracleStageContext(t)
					output, diagnostics, commandErr := runtimeOracleMachineOutput(ctx,
						exec.CommandContext(ctx, arguments[0], arguments[1:]...))
					cancel()
					if len(diagnostics) != 0 {
						t.Logf("complete guest-child stderr: %q", diagnostics)
					}
					want := fmt.Sprintf("portable FMA dead-q: admitted=%d context=%d reference=%d translated=%d\n",
						admitted, contexts, len(x86FMA3PortableAccessCases())*7, admitted*7)
					if err := x86FMA3PortableAccessReceipt(output, diagnostics, commandErr, want, faults, len(execution.prefix) != 0); err != nil {
						t.Fatalf("incomplete independent volatile reference/access execution: %v; stdout=%q stderr=%q want=%q", err, output, diagnostics, want)
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}

const x86FMA3PortableAccessReferenceC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
@PROTOTYPES@
typedef void (*Program)(const uint8_t *);
typedef struct { const char *name; Program translated; unsigned bytes; } Row;
static const Row rows[] = {@ROWS@};

/* Byte-volatile reads are independent of FMA arithmetic and target vector
 * lowering. No alignment assumption, uninitialized FP value or earlier read
 * can manufacture the expected fault. Empty masks select zero bytes. */
static void reference(const uint8_t *p,unsigned bytes) {
    for(unsigned i=0;i<bytes;i++) {
        uint8_t value=*(const volatile uint8_t *)(p+i);
        (void)value;
    }
}
static int observe(const Row *row,int translated,const uint8_t *p) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        if(translated) row->translated(p); else reference(p,row->bytes);
        _exit(0);
    }
    int status=0;
    if(waitpid(child,&status,0)!=child) return -2;
    if(WIFEXITED(status)) return WEXITSTATUS(status)==0?0:-3;
    if(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) return 1;
    return -4;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<128) return 1;
    uint8_t *memory=mmap(NULL,2*(size_t)page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(memory==MAP_FAILED || mprotect(memory+page,(size_t)page,PROT_NONE)) return 2;
    memset(memory,0,(size_t)page);
    unsigned admitted=0,contexts=0,references=0,translated=0;
    for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);i++) {
        const Row *row=&rows[i];
        admitted+=row->translated!=NULL;
        contexts+=row->translated==NULL;
        unsigned width=row->bytes?row->bytes:1;
        const uint8_t *inputs[]={memory,memory+1,NULL,memory+page,
            memory+page-(width-1),memory+page-width,memory+page-width-1};
        for(unsigned probe=0;probe<7;probe++) {
            int want=row->bytes && probe>=2 && probe<=4;
            int actual=observe(row,0,inputs[probe]);
            references++;
            if(actual!=want) {
                fprintf(stderr,"volatile reference row=%s probe=%u got=%d want=%d\n",row->name,probe,actual,want);
                return 3;
            }
            if(row->translated) {
                actual=observe(row,1,inputs[probe]);
                translated++;
                if(actual!=want) {
                    fprintf(stderr,"dead FMA q access row=%s probe=%u got=%d want=%d\n",row->name,probe,actual,want);
                    return 4;
                }
            }
        }
    }
    if(munmap(memory,2*(size_t)page)) return 5;
    printf("portable FMA dead-q: admitted=%u context=%u reference=%u translated=%u\n",
        admitted,contexts,references,translated);
    return 0;
}
`
