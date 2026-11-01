//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// E4NF access behavior executes independently of AVX512 hardware. The separate
// native legacy root below compares actual original Go opcode bytes.
func TestX86PackedAlignDeadE4NFReadsFaultAtFullTuple(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable guard-page oracle requires its native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, metadata strings.Builder
	count := 0
	for _, row := range x86PackedAlignRows()[1:] {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && row.bits == 8 {
					continue
				}
				op, bytes := row.op, amd64VectorByteWidth(Reg(bank+"0"))
				if broadcast {
					op, bytes = op+".BCST", row.bits/8
				}
				name := fmt.Sprint("AlignDead", count)
				instruction := x86PackedAlignInstruction(op+".Z", "(AX)", bank, "K1,", 255, 2, false)
				fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\nKMOVQ mask+8(FP),K1\n"+
					"VPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\nRET\n", name, instruction)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *,uint64_t);\n", name)
				fmt.Fprintf(&metadata, "{%s,%d},\n", name, bytes)
				count++
			}
		}
	}
	if count != 15 {
		t.Fatal("incomplete native tuple/broadcast inventory", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes.String() + `
typedef void (*Kernel)(const uint8_t *,uint64_t);
typedef struct {Kernel run;int bytes;} Row;
static const Row rows[]={
` + metadata.String() + `
};
static int fault(Kernel run,const uint8_t *p,uint64_t mask) {
  pid_t child=fork();
  if(child<0) return -1;
  if(!child) {
    struct rlimit limit={0,0};
    if(setrlimit(RLIMIT_CORE,&limit)) _exit(120);
    run(p,mask);
    _exit(0);
  }
  int status=0;
  if(waitpid(child,&status,0)!=child) return -2;
  if(WIFEXITED(status)) return WEXITSTATUS(status)?-3:0;
  return WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)?1:-4;
}
int main(void) {
  long page=sysconf(_SC_PAGESIZE);
  if(page<64) return 1;
  uint8_t *p=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  if(p==MAP_FAILED || mprotect(p+page,(size_t)page,PROT_NONE)) return 1;
  for(long i=0;i<page;i++) p[i]=(uint8_t)(i*17+3);
  const uint64_t masks[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000)};
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++) {
      if(fault(rows[r].run,0,masks[m])!=1 ||
         fault(rows[r].run,p+page-rows[r].bytes,masks[m])!=0 ||
         fault(rows[r].run,p+page-rows[r].bytes+1,masks[m])!=1) {
        fprintf(stderr,"align full-tuple row=%u mask=%u bytes=%d\n",r,m,rows[r].bytes);
        return 1;
      }
    }
  }
  return munmap(p,(size_t)page*2)?1:0;
}
`
	x86ConflictFunnelPortableRuntime(t, llc, clang, "align_dead_native", triple, ir, mainC)
}

func TestCrossLinuxRuntimeMatrixX86PackedAlignLegacyNativeFaults(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, references, metadata strings.Builder
	sigs := make(map[string]FuncSig)
	for _, immediate := range []int{0, 1, 16, 31, 32, 255} {
		code := assembleX87ControlBytes(t, "amd64", fmt.Sprintf("TEXT f(SB),4,$0-0\nPALIGNR $%d,(SI),X1\nRET\n", immediate))
		if len(code) != 7 || code[0] != 0x66 || code[1] != 0x0f || code[2] != 0x3a || code[3] != 0x0f || code[4] != 0x0e || int(code[5]) != immediate || code[6] != 0xc3 {
			t.Fatal("original Go m128 opcode observation changed", immediate, code)
		}
		var literals []string
		for _, value := range code[:6] {
			literals = append(literals, fmt.Sprintf("0x%02x", value))
		}
		for _, dead := range []bool{false, true} {
			name := fmt.Sprintf("AlignLegacy%d_%t", immediate, dead)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ p+8(FP),SI\nMOVQ old+16(FP),DX\n"+
				"MOVOU (DX),X1\nSTC\nPALIGNR $%d,(SI),X1\n", name, immediate)
			tail := ""
			if !dead {
				source.WriteString("MOVOU X1,(DI)\nSETCS 16(DI)\n")
				tail = "; movdqu %%xmm1,(%%rdi); setc 16(%%rdi)"
			}
			source.WriteString("RET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *);\n", name)
			fmt.Fprintf(&references, `static void original_%s(uint8_t *out,const uint8_t *p,const uint8_t *old) {
  __asm__ volatile("movdqu (%%%%rdx),%%%%xmm1; stc; .byte %s%s" :: "D"(out),"S"(p),"d"(old) : "xmm1","cc","memory");
}
`, name, strings.Join(literals, ","), tail)
			fmt.Fprintf(&metadata, "{%s,original_%s,%d,%d},\n", name, name, immediate, x86FloatAddSubBoolInt(dead))
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
	mainC := fmt.Sprintf("#define NATIVE_LINUX %d\n", x86FloatAddSubBoolInt(runtime.GOOS == "linux" && runtime.GOARCH == "amd64")) + `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + references.String() + `
typedef void (*Kernel)(uint8_t *,const uint8_t *,const uint8_t *);
typedef struct {Kernel run,original;int count,dead;} Row;
static const Row rows[]={
` + metadata.String() + `
};
static int observe(Kernel run,const uint8_t *p,int count,int dead) {
  pid_t child=fork();
  if(child<0) return -1;
  if(!child) {
    struct rlimit limit={0,0};
    if(setrlimit(RLIMIT_CORE,&limit)) _exit(120);
    uint8_t old[16],out[19];
    for(int i=0;i<16;i++) old[i]=(uint8_t)(i*13+71);
    memset(out,0xa7,sizeof(out));
    run(out+1,p,old);
    if(out[0]!=0xa7 || out[18]!=0xa7) _exit(2);
    for(int i=0;i<17;i++) {
      uint8_t expected=0xa7;
      if(!dead) {
        int at=i+count;
        expected=i==16?1:at>=32?0:at<16?p[at]:old[at-16];
      }
      if(out[i+1]!=expected) _exit(3);
    }
    _exit(0);
  }
  int status=0;
  if(waitpid(child,&status,0)!=child) return -2;
  if(WIFEXITED(status)) return WEXITSTATUS(status)?-3:0;
  return WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)?1:-4;
}
int main(void) {
  long page=sysconf(_SC_PAGESIZE);
  if(page<64) return 1;
  uint8_t *p=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  if(p==MAP_FAILED || mprotect(p+page,(size_t)page,PROT_NONE)) return 1;
  for(long i=0;i<page;i++) p[i]=(uint8_t)(i*17+3);
  const uint8_t *inputs[]={p,p+page-16,p+1,p+page-15,0};
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    for(unsigned c=0;c<sizeof(inputs)/sizeof(inputs[0]);c++) {
      Row row=rows[r];
      int original=observe(row.original,inputs[c],row.count,row.dead);
      int translated=observe(row.run,inputs[c],row.count,row.dead);
      if(original!=translated || original<0 || (c<2 && original!=0) || (c>=3 && original!=1) || (NATIVE_LINUX && c==2 && original!=1)) {
        fprintf(stderr,"legacy alignment row=%u case=%u original=%d translated=%d\n",r,c,original,translated);
        return 1;
      }
    }
  }
  return munmap(p,(size_t)page*2)?1:0;
}
`
	for _, pipeline := range []struct {
		name      string
		optimized bool
		backend   int
	}{
		{name: "backend_O0"}, {name: "backend_O2", backend: 2}, {name: "IR_O2/backend_O2", optimized: true, backend: 2},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			text := ir
			if pipeline.optimized {
				text = x86DwordProductIROptimize(t, ir)
			}
			compiler := []string{clang}
			if triple != testTargetTriple(runtime.GOOS, runtime.GOARCH) {
				compiler = append(compiler, "-target", triple)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "align_legacy_native", triple, text, mainC, prefix, pipeline.backend)
		})
	}
}
