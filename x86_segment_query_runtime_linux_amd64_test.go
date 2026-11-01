package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86SegmentQueryOriginalFlagsAliasesAndFaults(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, references, rows, goRows, deadRows strings.Builder
	count, nativeReads := 0, 0
	for operation, row := range x86SegmentQueryOracle {
		for role, operand := range []string{"AX", "(SI)", "CX"} {
			query := row.op + " " + operand
			if row.bytes != 0 {
				query += ",CX"
			}
			code := assembleX87ControlBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+query+"\nRET\n")
			want := x86SegmentQueryOriginalOpcode(row.op, role)
			if string(code) != string(append(want, 0xc3)) {
				t.Fatal("complete original Go query opcode changed", row.op, role, code, want)
			}
			var literals []string
			for _, value := range want {
				literals = append(literals, fmt.Sprintf("0x%02x", value))
			}
			for seed := 0; seed < 2; seed++ {
				name := fmt.Sprintf("Query%d_%d_%d", operation, role, seed)
				prepare, cPrepare := x86SegmentQueryNativeFlagSeed(seed == 1)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ selector+8(FP),AX\n"+
					"MOVQ old+16(FP),CX\nMOVQ p+24(FP),SI\n%s%s\nMOVQ CX,0(DI)\nMOVQ AX,10(DI)\n"+
					"LAHF\nMOVB AH,8(DI)\nSETOS 9(DI)\nRET\n", name, prepare, query)
				fmt.Fprintf(&declarations, "func %s(out *[18]byte,selector,old uint64,p *uint16)\n", name)
				fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,uint64_t,uint64_t,const uint16_t *);\n", name)
				fmt.Fprintf(&references, `__attribute__((noinline)) static void original_%s(uint8_t *out,uint64_t selector,uint64_t old,const uint16_t *p) {
  __asm__ volatile("%s.byte %s; movq %%%%rcx,0(%%%%rdi); movq %%%%rax,10(%%%%rdi); lahf; movb %%%%ah,8(%%%%rdi); seto 9(%%%%rdi)"
    : "+a"(selector),"+c"(old) : "D"(out),"S"(p) : "rdx","cc","memory");
}
`, name, cPrepare, strings.Join(literals, ","))
				fmt.Fprintf(&rows, "{%s,original_%s,%d,%d,%d,%d},\n", name, name, operation, role, seed, row.bytes)
				fmt.Fprintf(&goRows, "{%s,%d,%d,%d,%d},\n", name, operation, role, seed, row.bytes)
				count++
				if role == 1 {
					nativeReads++
				}
			}
			if role != 1 {
				continue
			}
			name := fmt.Sprintf("QueryDead%d", operation)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ selector+8(FP),AX\n"+
				"MOVQ old+16(FP),CX\nMOVQ p+24(FP),SI\n%s\nRET\n", name, query)
			fmt.Fprintf(&declarations, "func %s(out *[18]byte,selector,old uint64,p *uint16)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,uint64_t,uint64_t,const uint16_t *);\n", name)
			fmt.Fprintf(&references, `__attribute__((noinline)) static void original_%s(uint8_t *out,uint64_t selector,uint64_t old,const uint16_t *p) {
  (void)out;
  __asm__ volatile(".byte %s" : "+a"(selector),"+c"(old) : "S"(p) : "cc","memory");
}
`, name, strings.Join(literals, ","))
			fmt.Fprintf(&deadRows, "{%s,original_%s},\n", name, name)
			nativeReads++
		}
	}
	if count != 48 || nativeReads != 24 {
		t.Fatal("complete bounded query/native-read inventory changed", count, nativeReads)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, "Go")
	if err != nil {
		t.Fatal("complete original query program rejected", err)
	}
	driver := fmt.Sprintf(x86SegmentQueryNativeC, prototypes.String(), references.String(), rows.String(), deadRows.String())
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			queries := 0
			for _, mnemonic := range []string{"lar", "lsl", "verr", "verw"} {
				queries += strings.Count(pipeline.ir, `asm sideeffect "`+mnemonic)
			}
			if queries != 56 || strings.Count(pipeline.ir, "load volatile i16, ptr") != nativeReads {
				t.Fatal("an observable/dead query lost its native opcode or exact m16 access", queries)
			}
			output := execution.compileAndRunLLVM(t, "segment-query-native", pipeline.ir, driver, pipeline.level)
			if string(output) != "SEGMENT_QUERY_NATIVE_COMPLETE values=768 faults=160 failures=0\n" {
				t.Fatal("missing complete independent original-opcode/native query terminal", string(output))
			}
			t.Log("48 original-Go opcode rows × 16 inputs; full GP aliases, six status flags, canaries; 160 live/dead m16 fault processes")
		})
	}
	originalSource := source.String() + "TEXT ·OriginalCS(SB),4,$0-2\nMOVW CS,AX\nMOVW AX,ret0+0(FP)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", originalSource, "", true)
	x86RunOriginalGoNativeSource(t, execution, "amd64", "package oracle\n"+declarations.String()+"func OriginalCS() uint16\n", originalSource,
		fmt.Sprintf(x86SegmentQueryOriginalGo, goRows.String()))
	x87IA32RequireNativeHost(t)
}

func x86SegmentQueryOriginalOpcode(op string, role int) []byte {
	if op == "VERR" || op == "VERW" {
		modrm := byte(0xe0)
		if role == 1 {
			modrm = 0x26
		} else if role == 2 {
			modrm = 0xe1
		}
		if op == "VERW" {
			modrm += 8
		}
		return []byte{0x0f, 0x00, modrm}
	}
	var code []byte
	if strings.HasSuffix(op, "W") {
		code = append(code, 0x66)
	} else if strings.HasSuffix(op, "Q") {
		code = append(code, 0x48)
	}
	opcode, modrm := byte(2), byte(0xc8)
	if strings.HasPrefix(op, "LSL") {
		opcode = 3
	}
	if role == 1 {
		modrm = 0x0e
	} else if role == 2 {
		modrm = 0xc9
	}
	return append(code, 0x0f, opcode, modrm)
}

const x86SegmentQueryNativeC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
%s
%s
typedef void (*Kernel)(uint8_t *,uint64_t,uint64_t,const uint16_t *);
typedef struct {Kernel run,original;unsigned operation,role,seed,bytes;} Row;
static const Row rows[]={
%s
};
static const struct {Kernel run,original;} dead[]={
%s
};
static uint64_t word(const uint8_t *p) {uint64_t v;memcpy(&v,p,8);return v;}
static int fault(Kernel run,const uint16_t *p) {
  pid_t child=fork();
  if(child<0) return -1;
  if(!child) {
    struct rlimit limit={0,0};
    if(setrlimit(RLIMIT_CORE,&limit)) _exit(120);
    uint8_t out[20];memset(out,0xa7,sizeof(out));
    run(out+1,0,UINT64_C(0x123456789abcdef0),p);
    _exit(out[0]==0xa7 && out[19]==0xa7 ? 0:2);
  }
  int status=0;
  if(waitpid(child,&status,0)!=child) return -2;
  if(WIFEXITED(status)) return WEXITSTATUS(status)?-3:0;
  return WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)?1:-4;
}
int main(void) {
  uint16_t cs;__asm__ volatile("movw %%%%cs,%%0":"=r"(cs));
  const uint64_t high[]={0,UINT64_C(0x123456789abc0000),UINT64_C(0xffffffffffff0000),UINT64_C(0x8000000000000000)};
  const uint64_t oldValues[]={UINT64_C(0x123456789abcdef0),UINT64_C(0xfedcba9876543210)};
  unsigned values=0,faults=0;
  if(sizeof(rows)/sizeof(rows[0])!=48 || sizeof(dead)/sizeof(dead[0])!=8) return 1;
  for(unsigned r=0;r<48;r++) for(unsigned s=0;s<2;s++) for(unsigned h=0;h<4;h++) for(unsigned o=0;o<2;o++) {
    uint16_t selector=s?cs:0;
    uint64_t input=high[h]|selector,old=oldValues[o];
    if(rows[r].role==2) old=(old&~UINT64_C(65535))|selector;
    uint8_t actual[20],original[20];memset(actual,0xa7,sizeof(actual));memset(original,0xa7,sizeof(original));
    rows[r].original(original+1,input,old,&selector);
    rows[r].run(actual+1,input,old,&selector);
    uint64_t mask=rows[r].operation<3 && selector?~UINT64_C(0x000f0000):UINT64_MAX;
    unsigned zf=s && rows[r].operation!=7;
    unsigned lahf=(rows[r].seed?0x93:0x47)&~0x40u;
    lahf|=zf<<6;
    if(actual[0]!=0xa7 || actual[19]!=0xa7 || original[0]!=0xa7 || original[19]!=0xa7 ||
       ((word(actual+1)^word(original+1))&mask) || word(actual+11)!=input || word(original+11)!=input ||
       actual[9]!=lahf || original[9]!=lahf || actual[10]!=rows[r].seed || original[10]!=rows[r].seed) {
      fprintf(stderr,"query row=%%u selector=%%x high=%%u old=%%u got=%%llx want=%%llx flags=%%x/%%x\n",
        r,selector,h,o,(unsigned long long)word(actual+1),(unsigned long long)word(original+1),actual[9],original[9]);
      return 1;
    }
    if((rows[r].operation>=6 && word(actual+1)!=old) ||
       (!selector && ((word(actual+1)^old)&(rows[r].bytes==4?UINT64_C(0xffffffff):UINT64_MAX)))) return 1;
    values++;
  }
  long page=sysconf(_SC_PAGESIZE);
  if(page<64) return 1;
  uint8_t *p=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(p==MAP_FAILED || mprotect(p+page,(size_t)page,PROT_NONE)) return 1;
  memset(p,0,(size_t)page);
  if(mprotect(p,(size_t)page,PROT_READ)) return 1;
  const uint16_t *probes[]={0,(const uint16_t *)(p+page-2),(const uint16_t *)(p+page-1),
    (const uint16_t *)(p+1),(const uint16_t *)p};
  for(unsigned r=0;r<8;r++) for(unsigned probe=0;probe<5;probe++) for(unsigned live=0;live<2;live++) {
    unsigned expected=probe==0 || probe==2;
    Kernel actual=live?rows[r*6+2].run:dead[r].run;
    Kernel original=live?rows[r*6+2].original:dead[r].original;
    int before=fault(original,probes[probe]),after=fault(actual,probes[probe]);faults+=2;
    if(before!=(int)expected || after!=before) {
      fprintf(stderr,"query native fault operation=%%u probe=%%u live=%%u original=%%d translated=%%d\n",r,probe,live,before,after);
      return 1;
    }
  }
  if(values!=768 || faults!=160 || munmap(p,(size_t)page*2)) return 1;
  puts("SEGMENT_QUERY_NATIVE_COMPLETE values=768 faults=160 failures=0");return 0;
}
`

const x86SegmentQueryOriginalGo = `package oracle
import("encoding/binary";"testing")
type query struct {
  run func(*[18]byte,uint64,uint64,*uint16)
  operation,role,seed,bytes uint
}
var queries=[]query{
%s
}
func TestOriginal(t *testing.T) {
  cs:=OriginalCS()
  high:=[]uint64{0,0x123456789abc0000,0xffffffffffff0000,0x8000000000000000}
  oldValues:=[]uint64{0x123456789abcdef0,0xfedcba9876543210}
  outcomes:=0
  if len(queries)!=48 {t.Fatal("incomplete original Go query inventory")}
  for row,q:=range queries {
    for _,selector:=range []uint16{0,cs} {for _,upper:=range high {for _,old:=range oldValues {
      if q.role==2 {old=old&^65535|uint64(selector)}
      input:=upper|uint64(selector)
      var out [20]byte
      for i:=range out {out[i]=0xa7}
      q.run((*[18]byte)(out[1:19]),input,old,&selector)
      zf:=byte(0)
      if selector!=0 && q.operation!=7 {zf=0x40}
      lahf:=byte(0x47)
      if q.seed!=0 {lahf=0x93}
      result:=binary.LittleEndian.Uint64(out[1:9])
      mask:=^uint64(0)
      if q.bytes==4 {mask=0xffffffff}
      if out[0]!=0xa7 || out[19]!=0xa7 || out[9]!=(lahf&^0x40|zf) || out[10]!=byte(q.seed) ||
        binary.LittleEndian.Uint64(out[11:19])!=input || q.operation>=6 && result!=old ||
        selector==0 && (result^old)&mask!=0 {
        t.Fatal("actual original query value/flags/full-buffer mismatch",row,selector,upper,old,out)
      }
      outcomes++
    }}}
  }
  if outcomes!=768 {t.Fatal("incomplete original Go query outcomes",outcomes)}
  t.Log("768 actual original Go query whole-GP/FLAGS/canary outcomes")
}
`
