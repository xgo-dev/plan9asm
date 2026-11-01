//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedMoveUnalignedPortableFaults(t *testing.T) {
	x86PackedMoveUnalignedRuntime(t, false)
}

func x86PackedMoveUnalignedRuntime(t *testing.T, native bool) {
	x86PackedMoveObservableRuntime(t, native, false)
}

func x86PackedMoveObservableRuntime(t *testing.T, native, aligned bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	if native {
		execution = x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)
	}
	ir, main, count := x86PackedMoveObservableFixture(t, native, aligned, execution.triple)
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			execution.compileAndRunLLVM(t, "packed-move-observable", text, main, "-O2")
		})
	}
	t.Logf("%d independent move cases; original native Go execution=%t; aligned native semantics=%t", count, native, aligned)
}

func x86PackedMoveObservableFixture(t *testing.T, native, aligned bool, triple string) (string, string, int) {
	t.Helper()
	if aligned && !native {
		t.Fatal("aligned fault semantics require the original native counterpart")
	}
	var source, declarations, originals, pairs strings.Builder
	sigs := make(map[string]FuncSig)
	count := 0
	for _, row := range x86PackedMoveResultOracle {
		if row.aligned != aligned {
			continue
		}
		for axis, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			width := 16 << axis
			for _, mode := range []string{"plain-live", "plain-dead", "plain-store", "merge-live", "zero-live", "zero-dead", "mask-store"} {
				masked := strings.HasPrefix(mode, "merge") || strings.HasPrefix(mode, "zero") || mode == "mask-store"
				if row.vexOnly && masked {
					continue
				}
				store, dead, zero := strings.HasSuffix(mode, "store"), strings.HasSuffix(mode, "dead"), strings.HasPrefix(mode, "zero")
				op, mask := row.name, ""
				if masked {
					mask = "K1,"
				}
				if zero {
					op += ".Z"
				}
				operation := fmt.Sprintf("%s (AX),%s%s0\n", op, mask, bank)
				if store {
					operation = fmt.Sprintf("%s %s0,%s(AX)\n", op, bank, mask)
				}
				name := fmt.Sprintf("packed_observable%d", count)
				body := "KMOVQ CX,K1\nVMOVUPS (DI),Z0\nSTC\n" + operation
				if !store && !dead {
					body += "VMOVUPS Z0,(DI)\n"
				}
				body += "SETCS 64(DI)\n"
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ p+0(FP),AX\nMOVQ out+8(FP),DI\nMOVQ mask+16(FP),CX\n%sRET\n", name, body)
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: I64, Index: 2, Field: -1},
					}}}
				fmt.Fprintf(&declarations, "extern void %s(uint8_t*,uint8_t*,uint64_t);\n", name)
				original := "0"
				if native {
					code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+body+"RET\n")
					if len(code) < 2 || code[len(code)-1] != 0xc3 {
						t.Fatal("missing original Go opcode and RET", name, code)
					}
					var bytes []string
					for _, value := range code[:len(code)-1] {
						bytes = append(bytes, fmt.Sprintf("0x%02x", value))
					}
					original = "original_" + name
					fmt.Fprintf(&originals, `__attribute__((target("avx512f,avx512bw,avx512vl")))
static void %s(uint8_t *p,uint8_t *out,uint64_t mask) {
    __asm__ volatile(".byte %s" : : "a"(p),"D"(out),"c"(mask) : "zmm0","k1","memory","cc");
}
`, original, strings.Join(bytes, ","))
				}
				flag := func(value bool) int {
					if value {
						return 1
					}
					return 0
				}
				fmt.Fprintf(&pairs, "{%s,%s,%d,%d,%d,%d,%d,%d},\n", original, name, width, row.bits/8, flag(masked), flag(store), flag(dead), flag(zero))
				count++
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	alignment := "0"
	if aligned {
		alignment = "1"
	}
	main := "#define ALIGNED " + alignment + "\n" + x86PackedMoveObservableRuntimeC + declarations.String() + originals.String() + "static const struct pair pairs[]={\n" + pairs.String() + `};
int main(void) {
    if (pairs[0].original) {
        unsigned a,b,c,d;
        if (!__get_cpuid_count(7,0,&a,&b,&c,&d) || !(b&(1u<<30))) return 78;
    }
    long page=sysconf(_SC_PAGESIZE);
    if(page<256) return 1;
    uint8_t *region=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 2;
    for(unsigned op=0;op<sizeof(pairs)/sizeof(*pairs);++op) {
        struct pair pair=pairs[op];
        if(check_values(pair)) { fprintf(stderr,"bytes op=%u\n",op); return 3; }
        if(ALIGNED) {
            /* Fully mapped addresses separate alignment from page faults.
               In particular zero masking is not assumed to suppress #GP. */
            uint64_t masks[]={0,1,UINT64_C(0x8000000000000000),UINT64_MAX};
            for(int offset=1;offset<pair.width;offset++) for(unsigned m=0;m<4;m++) {
                int want=outcome(pair,region+offset,masks[m],1);
                int got=outcome(pair,region+offset,masks[m],0);
                if((want!=0 && want!=SIGSEGV && want!=SIGBUS) || got!=want) {
                    fprintf(stderr,"alignment op=%u offset=%d mask=%llx original=%d llvm=%d\n",op,offset,(unsigned long long)masks[m],want,got);
                    return 8;
                }
                if((!pair.masked || masks[m]==UINT64_MAX) && want==0) return 9;
            }
        }
        /* Live/merge values are covered above; dead loads and stores isolate
           exceptions from incidental uses of a result. */
        if(!ALIGNED && !pair.dead && !pair.store) continue;
        uint64_t masks[]={0,1,UINT64_C(0x8000000000000000),UINT64_MAX};
        int extents[]={0,pair.lane-1,pair.lane,pair.width-1,pair.width};
        for(unsigned m=0;m<sizeof(masks)/sizeof(*masks);m++) {
            for(unsigned e=0;e<sizeof(extents)/sizeof(*extents);e++) {
                uint8_t *p=region+page-extents[e];
                int expected=expected_fault(pair,masks[m],extents[e]);
                int result=outcome(pair,p,masks[m],0);
                int original=pair.original?outcome(pair,p,masks[m],1):result;
                if(ALIGNED) {
                    if((original!=0 && original!=SIGSEGV && original!=SIGBUS) || original!=result) return 10;
                    continue;
                }
                if((expected ? result!=SIGSEGV && result!=SIGBUS : result!=0)) {
                    fprintf(stderr,"fault op=%u extent=%d mask=%llx got=%d expected=%d\n",op,extents[e],(unsigned long long)masks[m],result,expected);
                    return 4;
                }
                if(pair.original && result!=original) return 5;
            }
            int result=outcome(pair,0,masks[m],0);
            int expected=expected_fault(pair,masks[m],0);
            if((expected ? result!=SIGSEGV && result!=SIGBUS : result!=0)) return 6;
            if(pair.original && result!=outcome(pair,0,masks[m],1)) return 7;
        }
    }
    return munmap(region,2*page)!=0;
}
`
	return ir, main, count
}

const x86PackedMoveObservableRuntimeC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cpuid.h>
#include <xmmintrin.h>
typedef void (*operation)(uint8_t*,uint8_t*,uint64_t);
struct pair { operation original,translated; int width,lane,masked,store,dead,zero; };
static int active(struct pair pair,uint64_t mask,int byte) {
    return !pair.masked || ((mask>>(byte/pair.lane))&1);
}
static int expected_fault(struct pair pair,uint64_t mask,int extent) {
    for(int byte=extent;byte<pair.width;byte++) if(active(pair,mask,byte)) return 1;
    return 0;
}
static int outcome(struct pair pair,uint8_t *p,uint64_t mask,int original) {
    pid_t child=fork();
    if(child<0) return -1;
    if(!child) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        _Alignas(64) uint8_t out[128]; memset(out,0x53,sizeof(out));
        (original?pair.original:pair.translated)(p,out,mask); _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    return WIFSIGNALED(status)?WTERMSIG(status):-2;
}
static int check_values(struct pair pair) {
    const uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0x8000000000000000),UINT64_MAX};
    for(int sample=0;sample<33;sample++) for(unsigned m=0;m<sizeof(masks)/sizeof(*masks);m++) {
        _Alignas(64) uint8_t a[256],b[256],x[256],y[256],want_a[256],want_x[256];
        int in=ALIGNED?64:1,out=ALIGNED?64:3;
        for(int i=0;i<256;i++) {
            a[i]=b[i]=want_a[i]=(uint8_t)(sample*71+i*19);
            x[i]=y[i]=want_x[i]=(uint8_t)(sample*31-i*59);
        }
        for(int i=0;i<64;i++) {
            if(pair.store) {
                if(i<pair.width && active(pair,masks[m],i)) want_a[in+i]=x[out+i];
            } else if(!pair.dead) {
                want_x[out+i]=i>=pair.width?0:active(pair,masks[m],i)?a[in+i]:pair.zero?0:x[out+i];
            }
        }
        want_x[out+64]=1;
        unsigned saved=_mm_getcsr(),csr=0x1f80|((sample&3)<<13)|(sample&63);
        _mm_setcsr(csr); pair.translated(a+in,x+out,masks[m]); unsigned after=_mm_getcsr();
        _mm_setcsr(saved);
        if(after!=csr || memcmp(a,want_a,256) || memcmp(x,want_x,256)) return 1;
        if(pair.original) {
            _mm_setcsr(csr); pair.original(b+in,y+out,masks[m]); after=_mm_getcsr();
            _mm_setcsr(saved);
            if(after!=csr || memcmp(a,b,256) || memcmp(x,y,256)) return 2;
        }
    }
    return 0;
}
`

func TestX86PackedMoveObservableFaultChildrenDisableCore(t *testing.T) {
	if err := runtimeOracleFaultCorePolicy(runtimeOracleFaultC(t, "amd64_packed_vector_move_observable_runtime_unix_test.go")); err != nil {
		t.Fatal(err)
	}
}
