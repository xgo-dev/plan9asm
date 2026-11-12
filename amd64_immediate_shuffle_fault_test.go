//go:build unix

package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ImmediateShuffleLegacyNativeMemory(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, references, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
		// The C oracle executes bytes independently observed from original Go,
		// with fixed RSI/RDI inputs. It does not reuse the production grammar.
		original := "TEXT f(SB),4,$0-0\n" + op + " $27,(SI),X1\nRET\n"
		listing := x86InsertExtractGoListing(t, "amd64", original)
		var code []byte
		for _, line := range strings.Split(string(listing), "\n") {
			code = append(code, x86InsertExtractListedBytes(line)...)
		}
		prefixByte := byte(0x66)
		if op == "PSHUFHW" {
			prefixByte = 0xf3
		} else if op == "PSHUFLW" {
			prefixByte = 0xf2
		}
		if !bytes.Equal(code, []byte{prefixByte, 0x0f, 0x70, 0x0e, 27, 0xc3}) {
			t.Fatalf("independent original Go m128 opcode changed: %s %x", op, code)
		}
		var literals []string
		for _, value := range code[:5] {
			literals = append(literals, fmt.Sprintf("0x%02x", value))
		}
		kind := 0
		if op == "PSHUFHW" {
			kind = 2
		} else if op == "PSHUFLW" {
			kind = 1
		}
		for _, dead := range []bool{false, true} {
			name := fmt.Sprintf("legacymemory%d_%t", index, dead)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ out+0(FP),AX\nMOVQ input+8(FP),BX\nCMPQ BX,BX\nSTC\n%s $27,(BX),X1\n", name, op)
			tail := ""
			if !dead {
				source.WriteString("MOVOU X1,(AX)\nSETCS 16(AX)\nSETNE 17(AX)\n")
				tail = "; movdqu %%xmm1,(%%rdi); setc 16(%%rdi); setnz 17(%%rdi)"
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*);\n", name)
			fmt.Fprintf(&references, `static void original_%s(uint8_t *out,const uint8_t *input) {
    __asm__ volatile("cmpq %%%%rsi,%%%%rsi; stc; .byte %s%s" ::
        "D"(out), "S"(input) : "xmm1", "cc", "memory");
}
`, name, strings.Join(literals, ","), tail)
			fmt.Fprintf(&checks, `
    if(compare(original_%[1]s,%[1]s,region,0,%[2]d,%[3]d) ||
       compare(original_%[1]s,%[1]s,boundary-16,0,%[2]d,%[3]d) ||
       compare(original_%[1]s,%[1]s,region+1,-1,%[2]d,%[3]d) ||
       compare(original_%[1]s,%[1]s,boundary-15,1,%[2]d,%[3]d) ||
       compare(original_%[1]s,%[1]s,0,1,%[2]d,%[3]d)) return 1;
`, name, kind, x86FloatAddSubBoolInt(dead))
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
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + references.String() + `
typedef void (*memoryfn)(uint8_t*,const uint8_t*);
static int observe(memoryfn fn,const uint8_t *input,int kind,int dead) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit limit={0,0};
        if(setrlimit(RLIMIT_CORE,&limit)) _exit(2);
        uint8_t result[20], before[16];
        memset(result,0xc3,sizeof(result));
        // Copy only for a successful readable input; boundary and NULL probes
        // must fault in the tested opcode, not in the independent reference.
        if(input && !((uintptr_t)input & 15)) memcpy(before,input,16);
        fn(result+1,input);
        if(result[0]!=0xc3 || result[19]!=0xc3) _exit(3);
        if(dead) {
            for(unsigned i=1;i<19;i++) if(result[i]!=0xc3) _exit(4);
        } else {
            if(result[17]!=1 || result[18]!=0) _exit(5);
            for(unsigned i=0;i<16;i++) {
                unsigned at=i;
                if(kind==0) at=((27>>(2*(i/4)))&3)*4+i%4;
                else {
                    unsigned word=i/2;
                    if((kind==1 && word<4) || (kind==2 && word>=4))
                        at=(kind==2 ? 8 : 0)+((27>>(2*(word%4)))&3)*2+i%2;
                }
                if(result[i+1]!=input[at]) _exit(6);
            }
            if(!((uintptr_t)input & 15) && memcmp(before,input,16)) _exit(7);
        }
        _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return -1;
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    if(WIFSIGNALED(status)) return 128+WTERMSIG(status);
    return -1;
}
static int compare(memoryfn reference,memoryfn translated,const uint8_t *input,
                   int fault,int kind,int dead) {
    int native=observe(reference,input,kind,dead);
    int got=observe(translated,input,kind,dead);
    int memoryFault=native==128+SIGSEGV || native==128+SIGBUS;
    int valid=fault==1 ? memoryFault : fault==-1 ? native==0 || memoryFault : native==0;
    if(native<0 || native!=got || !valid) {
        fprintf(stderr,"legacy shuffle input=%p native=%d LLVM=%d requiredFault=%d\n",input,native,got,fault);
        return 1;
    }
    return 0;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<64) return 1;
    uint8_t *region=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED || mprotect(region+page,(size_t)page,PROT_NONE)) return 1;
    for(long i=0;i<page;i++) region[i]=(uint8_t)(i*29+197);
    uint8_t *boundary=region+page;
` + checks.String() + `
    return munmap(region,(size_t)page*2)!=0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy-shuffle-native-memory", triple, text, oracle, prefix)
		})
	}
	t.Log("8 live/dead legacy m128 programs, exact original Go/native bytes and LLVM controls; Rosetta alignment is diagnostic, not native AMD64 certification")
}

func TestCrossLinuxRuntimeMatrixX86ImmediateShuffleFullNativeReads(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, op := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, width := range []int{16, 32, 64} {
			for _, masked := range []bool{false, true} {
				broadcasts := []bool{false}
				if op == "VPSHUFD" {
					broadcasts = append(broadcasts, true)
				}
				for _, broadcast := range broadcasts {
					name := fmt.Sprintf("shufflefault%d", count)
					count++
					row := op
					bytes := width
					if broadcast {
						row += ".BCST"
						bytes = 4
					}
					if masked {
						row += ".Z"
					}
					row += " $0,(BX),"
					if masked {
						row += "K1,"
					}
					row += map[int]string{16: "X", 32: "Y", 64: "Z"}[width] + "1"
					// The output is deliberately dead, so O2 cannot use it to keep
					// a plain load live. Zero K still requires the full E4NF tuple.
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ input+0(FP),BX\nMOVL $0,CX\nKMOVQ CX,K1\n%s\nRET\n", name, row)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
					fmt.Fprintf(&declarations, "extern void %s(const uint8_t*);\n", name)
					fmt.Fprintf(&checks, "if(check(%s,0,1) || check(%s,boundary-%d+1,1) || check(%s,boundary-%d,0)) return 1;\n", name, name, bytes, name, bytes)
				}
			}
		}
	}
	if count != 24 {
		t.Fatalf("full tuple/broadcast/mask denominator changed: %d", count)
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
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + `
static int check(void (*program)(const uint8_t*),const uint8_t *input,int fault) {
    pid_t child=fork();
    if(child<0) return 1;
    if(child==0) {
        struct rlimit limit={0,0};
        if(setrlimit(RLIMIT_CORE,&limit)) _exit(2);
        program(input);
        _exit(0);
    }
    int status;
    if(waitpid(child,&status,0)!=child) return 1;
    int got=WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS);
    if(fault ? !got : !WIFEXITED(status) || WEXITSTATUS(status)!=0) {
        fprintf(stderr,"shuffle physical-read input=%p fault=%d status=%x\n",input,fault,status);
        return 1;
    }
    return 0;
}
int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<=0) return 1;
    uint8_t *memory=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(memory==MAP_FAILED || mprotect(memory+page,(size_t)page,PROT_NONE)) return 1;
    uint8_t *boundary=memory+page;
` + checks.String() + `
    return munmap(memory,(size_t)page*2)!=0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "immediate-shuffle-native-reads", triple, text, oracle, prefix)
		})
	}
}
