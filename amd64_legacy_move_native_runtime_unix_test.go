//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86LegacyMoveNativeBytesAndFaults(t *testing.T) {
	x86LegacyMoveNativeRuntime(t, false)
}

func x86LegacyMoveNativeRuntime(t *testing.T, nativeAlignment bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	boolInt := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	var source, declarations, originals, pairs strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range x86LegacyMoveNativeOracle {
		for _, store := range []bool{false, true} {
			for _, dead := range []bool{false, true} {
				name := fmt.Sprintf("move%d_%t_%t", index, store, dead)
				source.WriteString(x86LegacyMoveNativeSource("amd64", name, row.name, store, dead))
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					}}}
				fmt.Fprintf(&declarations, "extern void %s(uint8_t*,uint8_t*);\n", name)
				operands := "(DI),X1"
				before, after := "stc\\n\\t", "movups %%xmm1,(%1)\\n\\t"
				if store {
					operands = "X1,(DI)"
					before, after = "movups (%1),%%xmm1\\n\\tstc\\n\\t", ""
				} else if dead {
					after = ""
				}
				code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row.name+" "+operands+"\nRET\n")
				if len(code) < 4 || code[len(code)-1] != 0xc3 {
					t.Fatal("missing original Go opcode and ordinary RET", code)
				}
				var bytes []string
				for _, value := range code[:len(code)-1] {
					bytes = append(bytes, fmt.Sprintf("0x%02x", value))
				}
				fmt.Fprintf(&originals, `static void original_%s(uint8_t *p,uint8_t *out) {
    __asm__ volatile("%s.byte %s\n\t%ssetc 16(%%1)"
        : : "D"(p),"r"(out) : "xmm1","memory","cc");
}
`, name, before, strings.Join(bytes, ","), after)
				fmt.Fprintf(&pairs, "{original_%s,%s,%d,%d,%d,16,0},\n", name, name,
					boolInt(row.aligned), boolInt(store), boolInt(dead))
			}
		}
		for lane := 0; lane < 4; lane++ {
			name := fmt.Sprintf("move_result%d_%d", index, lane)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-12\nMOVQ p+0(FP),AX\n%s (AX),X1\nPEXTRD $%d,X1,CX\nMOVL CX,ret+8(FP)\nRET\n", name, row.name, lane)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: I32,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
				}}
			fmt.Fprintf(&declarations, `extern uint32_t %s(uint8_t*);
static void translated_%s(uint8_t *p,uint8_t *out) {
    uint32_t value=%s(p); memcpy(out,&value,4); out[16]=1;
}
`, name, name, name)
			code := x86PackedShiftActualGoBytes(t, "amd64", fmt.Sprintf("TEXT f(SB),4,$0-0\n%s (DI),X1\nPEXTRD $%d,X1,AX\nRET\n", row.name, lane))
			if len(code) < 8 || code[len(code)-1] != 0xc3 {
				t.Fatal("missing original Go load/extract/RET", code)
			}
			var bytes []string
			for _, value := range code[:len(code)-1] {
				bytes = append(bytes, fmt.Sprintf("0x%02x", value))
			}
			fmt.Fprintf(&originals, `static void original_%s(uint8_t *p,uint8_t *out) {
    uint32_t value;
    __asm__ volatile(".byte %s" : "=a"(value) : "D"(p) : "xmm1","memory");
    memcpy(out,&value,4); out[16]=1;
}
`, name, strings.Join(bytes, ","))
			fmt.Fprintf(&pairs, "{original_%s,translated_%s,%d,0,0,4,%d},\n", name, name, boolInt(row.aligned), lane*4)
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const helper = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xmmintrin.h>
typedef void (*operation)(uint8_t*,uint8_t*);
struct pair { operation original,translated; int aligned,store,dead,width,offset; };
static int outcome(operation fn,uint8_t *p) {
    pid_t child=fork();
    if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        uint8_t data[32]; memset(data,0x53,sizeof(data));
        fn(p,data); _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    return WIFSIGNALED(status)?WTERMSIG(status):-2;
}
static int check_bytes(struct pair pair,int offset) {
    for(int sample=0;sample<257;++sample) for(int rc=0;rc<4;++rc) {
        _Alignas(16) uint8_t a[64],b[64],x[64],y[64];
        for(int i=0;i<64;++i) {
            a[i]=b[i]=(uint8_t)(sample*71+i*19);
            x[i]=y[i]=(uint8_t)(sample*31-i*59);
        }
        uint8_t before_a[64],before_x[64];
        memcpy(before_a,a,64); memcpy(before_x,x,64);
        uint32_t saved=_mm_getcsr(),csr=0x1f80|(rc<<13)|(sample&63);
        _mm_setcsr(csr); pair.original(a+offset,x+1); uint32_t original_csr=_mm_getcsr();
        _mm_setcsr(csr); pair.translated(b+offset,y+1); uint32_t translated_csr=_mm_getcsr();
        _mm_setcsr(saved);
        if(original_csr!=csr || translated_csr!=csr || memcmp(a,b,64) || memcmp(x,y,64)) return 1;
        for(int i=0;i<64;++i) {
            uint8_t want_a=pair.store && i>=offset && i<offset+16?before_x[1+i-offset]:before_a[i];
            uint8_t want_x=!pair.store && !pair.dead && i>=1 && i<1+pair.width?before_a[offset+pair.offset+i-1]:before_x[i];
            if(i==17) want_x=1;
            if(a[i]!=want_a || x[i]!=want_x) return 2;
        }
    }
    return 0;
}
`
	main := fmt.Sprintf("#define CHECK_ALIGNMENT %d\n", boolInt(nativeAlignment)) + helper + declarations.String() + originals.String() + "static const struct pair pairs[]={\n" + pairs.String() + `};
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<128) return 1;
    uint8_t *region=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 2;
    for(unsigned op=0;op<sizeof(pairs)/sizeof(*pairs);++op) {
        struct pair pair=pairs[op];
        if(check_bytes(pair,pair.aligned?16:17)) return 3;
        if(CHECK_ALIGNMENT) for(int offset=1;offset<16;++offset) {
            /* Fully mapped storage isolates alignment from page bounds. */
            int a=outcome(pair.original,region+offset),b=outcome(pair.translated,region+offset);
            if(a!=b || (pair.aligned ? a!=SIGSEGV && a!=SIGBUS : a!=0)) {
                fprintf(stderr,"op=%u misalignment=%d original=%d translated=%d\n",op,offset,a,b);
                return 6;
            }
        }
        for(int extent=0;extent<=16;++extent) {
            /* Non-native transports need not reproduce aligned-SSE faults. */
            if(!CHECK_ALIGNMENT && pair.aligned && extent!=0 && extent!=16) continue;
            uint8_t *p=region+page-extent;
            int a=outcome(pair.original,p),b=outcome(pair.translated,p);
            if(a!=b || (extent==16 ? a!=0 : a!=SIGSEGV && a!=SIGBUS)) {
                fprintf(stderr,"op=%u extent=%d original=%d translated=%d\n",op,extent,a,b);
                return 4;
            }
        }
        int a=outcome(pair.original,0),b=outcome(pair.translated,0);
        if(a!=b || (a!=SIGSEGV && a!=SIGBUS)) return 5;
    }
    return munmap(region,2*page)!=0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			execution.compileAndRunLLVM(t, "legacy-move-native", text, main, "-O2")
		})
	}
	t.Logf("7 opcodes, both directions/live-dead, 257x4 byte/CF/MXCSR/canary values and null/guard faults; transport=%s/%s", runtime.GOOS, runtime.GOARCH)
}

func TestX86LegacyMoveNativeFaultChildrenDisableCore(t *testing.T) {
	if err := runtimeOracleFaultCorePolicy(runtimeOracleFaultC(t, "amd64_legacy_move_native_runtime_unix_test.go")); err != nil {
		t.Fatal(err)
	}
}
