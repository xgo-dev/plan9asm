//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86VectorValueNativePortableFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	var source, declarations, prototypes, checks strings.Builder
	count := 0
	for _, member := range x86NativeVectorValueMembers() {
		for _, mode := range []string{"plain", "merge", "zero"} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && !member.broadcast {
					continue
				}
				body, declaration := x86NativeVectorValueFixture(member, "amd64", "Z", mode, broadcast, true)
				name := fmt.Sprintf("FaultValue%d", count)
				count++
				source.WriteString(strings.ReplaceAll(body, "Value", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
				fmt.Fprintf(&prototypes, "extern uint32_t %s(uint8_t *,uintptr_t);\n", name)
				bits := 8
				if member.unary {
					switch member.name[len(member.name)-1] {
					case 'W':
						bits = 16
					case 'D':
						bits = 32
					case 'Q':
						bits = 64
					}
				}
				// E4 can suppress inactive unary lane reads. Indexed permutes
				// and GFNI are E4NF, including zero masks and dead results.
				suppresses := member.unary && mode != "plain"
				zeroFault, tailFault := 1, 1
				if suppresses {
					zeroFault = 0
					if !broadcast {
						tailFault = 0
					}
				}
				width := 64
				if broadcast {
					width = bits / 8
					if member.immediate || strings.HasSuffix(member.name, "Q") || strings.HasSuffix(member.name, "PD") {
						width = 8
					} else {
						width = 4
					}
				}
				fmt.Fprintf(&checks, "if(observe(%s,0,0,%d,\"%s/null-zero\"))return 1;\n", name, zeroFault, name)
				fmt.Fprintf(&checks, "if(observe(%s,0,UINTPTR_MAX,1,\"%s/null-active\"))return 1;\n", name, name)
				fmt.Fprintf(&checks, "if(observe(%s,storage+page-%d-5,UINTPTR_MAX,0,\"%s/exact-width\"))return 1;\n", name, width, name)
				fmt.Fprintf(&checks, "if(observe(%s,storage+page-%d-4,UINTPTR_MAX,1,\"%s/last-byte\"))return 1;\n", name, width, name)
				if !broadcast {
					fmt.Fprintf(&checks, "if(observe(%s,storage+page-%d-5,1,%d,\"%s/one-lane\"))return 1;\n", name, bits/8, tailFault, name)
				}
			}
		}
	}
	if count != 111 {
		t.Fatal("complete native fault denominator changed", count)
	}
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <unistd.h>\n#include <signal.h>\n" +
		"#include <errno.h>\n#include <string.h>\n#include <sys/mman.h>\n#include <sys/wait.h>\n#include <sys/resource.h>\n" +
		numericalRuntimeFaultObservationC + prototypes.String() + `
static uint8_t *protected_region;
static size_t protected_bytes;
static int observe(uint32_t (*fn)(uint8_t *,uintptr_t),uint8_t *p,uintptr_t mask,int fault,const char *name) {
 pid_t child=fork();
 if(child<0)return 1;
 if(child==0) {
  struct rlimit observed;
  if(getrlimit(RLIMIT_CORE,&observed)||observed.rlim_cur||observed.rlim_max)_exit(120);
  numerical_fault_begin(p ? protected_region : 0,protected_bytes);
  _exit(fn(p,mask)==7?0:1);
 }
 int status;
 pid_t waited;
 do {waited=waitpid(child,&status,0);} while(waited<0&&errno==EINTR);
 if(waited!=child)return 1;
 if(fault ? numerical_fault_status(status) :
             (WIFEXITED(status)&&WEXITSTATUS(status)==0))return 0;
 fprintf(stderr,"%s mask=%llx expected fault=%d wait=%x\n",name,(unsigned long long)mask,fault,status);
 return 1;
}
int main(void) {
 struct rlimit no_core={0,0};
 if(setrlimit(RLIMIT_CORE,&no_core))return 1;
 long page=sysconf(_SC_PAGESIZE);
 if(page<128)return 1;
 uint8_t *storage=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(storage==MAP_FAILED||mprotect(storage+page,page,PROT_NONE))return 1;
 protected_region=storage+page;
 protected_bytes=(size_t)page;
` + checks.String() + "return munmap(storage,2*page)!=0;\n}\n"
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete portable native fault source rejected", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "vector-value-faults", triple, text, driver, nil, level)
				}
			}
		})
	}
}
