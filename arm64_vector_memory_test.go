package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are Go's C_LIST arrangements, not a projection of the lowerer's table.
// LD/ST1 concatenate one through four registers; LD/ST2-4 interleave instead.
var arm64VectorMemoryArrangements = []struct {
	name        string
	bits, lanes int
}{
	{"B8", 8, 8}, {"B16", 8, 16}, {"H4", 16, 4}, {"H8", 16, 8},
	{"S2", 32, 2}, {"S4", 32, 4}, {"D1", 64, 1}, {"D2", 64, 2},
}

func arm64VectorMemoryOperands(bytes, mode int, base string) (suffix, memory string) {
	switch mode {
	case 0:
		return "", "(" + base + ")"
	case 1:
		return ".P", fmt.Sprintf("%d(%s)", bytes, base)
	case 2:
		return ".P", "(" + base + ")(R7)"
	default:
		return ".P", "(" + base + ")" // implicit whole-list byte increment
	}
}

func arm64VectorMemoryTranslate(t *testing.T, source, target string, sigs map[string]FuncSig) string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64VectorMemoryTypedWholeTransfers(t *testing.T) {
	// Checking source IR (before optimization) prevents relying on a backend
	// pass to recover SIMD from dozens of independently emitted byte accesses.
	// A transfer may not acquire alignment or read beyond its encoded 8/16 bytes.
	for _, arrangement := range arm64VectorMemoryArrangements {
		for count := 1; count <= 4; count++ {
			for mode := 0; mode < 4; mode++ {
				name := fmt.Sprintf("%s/list%d/mode%d", arrangement.name, count, mode)
				t.Run(name, func(t *testing.T) {
					width := arrangement.bits * arrangement.lanes / 8
					registers := arm64TestVectorList(30, count, arrangement.name)
					loadSuffix, input := arm64VectorMemoryOperands(count*width, mode, "R0")
					storeSuffix, output := arm64VectorMemoryOperands(count*width, mode, "R1")
					source := fmt.Sprintf("TEXT vectorcopy(SB),$0-0\nVLD1%s %s,%s\nVST1%s %s,%s\nRET\n",
						loadSuffix, input, registers, storeSuffix, registers, output)
					ir := arm64VectorMemoryTranslate(t, source, "aarch64-unknown-linux-gnu",
						map[string]FuncSig{"vectorcopy": {Name: "vectorcopy", Ret: Void}})
					arm64VectorMemoryCheckAccesses(t, ir, "vectorcopy", arrangement.bits, arrangement.lanes, count)
				})
			}
		}
	}
}

func TestARM64VectorMemoryLaneAccessesStayExact(t *testing.T) {
	for _, bits := range []int{8, 16, 32, 64} {
		kind := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[bits]
		for lane := 0; lane < 128/bits; lane++ {
			for mode := 0; mode < 3; mode++ {
				t.Run(fmt.Sprintf("%s/lane%d/mode%d", kind, lane, mode), func(t *testing.T) {
					suffix, input := arm64VectorMemoryOperands(bits/8, mode, "R0")
					_, output := arm64VectorMemoryOperands(bits/8, mode, "R1")
					source := fmt.Sprintf("TEXT vectorlane(SB),$0-0\nVLD1%s %s,V30.%s[%d]\nVST1%s V30.%s[%d],%s\nRET\n",
						suffix, input, kind, lane, suffix, kind, lane, output)
					ir := arm64VectorMemoryTranslate(t, source, "aarch64-unknown-linux-gnu",
						map[string]FuncSig{"vectorlane": {Name: "vectorlane", Ret: Void}})
					arm64VectorMemoryCheckAccesses(t, ir, "vectorlane", bits, 0, 1)
				})
			}
		}
	}
}

func arm64VectorMemoryCheckAccesses(t *testing.T, ir, name string, bits, lanes, count int) {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	function := module.NamedFunction(name)
	if function.IsNil() || function.FirstBasicBlock().IsNil() {
		t.Fatal("original memory-transfer function disappeared", name)
	}
	loads, stores := 0, 0
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for ins := block.FirstInstruction(); !ins.IsNil(); ins = llvm.NextInstruction(ins) {
			var pointer llvm.Value
			var typ llvm.Type
			switch ins.InstructionOpcode() {
			case llvm.Load:
				pointer, typ = ins.Operand(0), ins.Type()
			case llvm.Store:
				pointer, typ = ins.Operand(1), ins.Operand(0).Type()
			default:
				continue
			}
			// Register banks and FLAGS are implementation allocas, not native
			// memory accesses. Follow only pointer-preserving derivations.
			for depth := 0; depth < 16 && (!pointer.IsAGetElementPtrInst().IsNil() || !pointer.IsABitCastInst().IsNil()); depth++ {
				pointer = pointer.Operand(0)
			}
			if pointer.IsAIntToPtrInst().IsNil() {
				continue
			}
			if ins.InstructionOpcode() == llvm.Load {
				loads++
			} else {
				stores++
			}
			if ins.Alignment() != 1 {
				t.Errorf("native transfer acquired unsupported alignment: %s", ins.String())
			}
			if lanes != 0 {
				if typ.TypeKind() != llvm.VectorTypeKind || typ.VectorSize() != lanes {
					t.Errorf("whole transfer is not one exact %d-lane vector: %s", lanes, ins.String())
					continue
				}
				typ = typ.ElementType()
			}
			if typ.TypeKind() != llvm.IntegerTypeKind || typ.IntTypeWidth() != bits {
				t.Errorf("native transfer lost its exact i%d element width: %s", bits, ins.String())
			}
		}
	}
	if loads != count || stores != count {
		t.Errorf("native accesses: loads=%d stores=%d, want %d/%d", loads, stores, count, count)
	}
}

func TestCrossLinuxRuntimeMatrixARM64VectorMemorySemantics(t *testing.T) {
	// The shared helper executes natively on Linux/Darwin ARM64, or in the
	// mandatory Linux/amd64 cross matrix. Other hosts retain explicit SKIP.
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	index := 0
	for _, arrangement := range arm64VectorMemoryArrangements {
		for count := 1; count <= 4; count++ {
			for mode := 0; mode < 4; mode++ {
				width := arrangement.bits * arrangement.lanes / 8
				name := fmt.Sprintf("vector_memory_%d", index)
				index++
				registers := arm64TestVectorList(30, count, arrangement.name)
				suffix, input := arm64VectorMemoryOperands(count*width, mode, "R0")
				_, output := arm64VectorMemoryOperands(count*width, mode, "R1")
				fmt.Fprintf(&source, "TEXT %s(SB),$0-0\nMOVD $%d,R7\n", name, count*width+5)
				if width == 8 {
					// Seed every upper byte so preserving an old half cannot
					// impersonate the Q=0 load's required upper-half clearing.
					for register := 0; register < count; register++ {
						fmt.Fprintf(&source, "VMOVI $0xa5,V%d.B16\n", (30+register)%32)
					}
				}
				fmt.Fprintf(&source, "VLD1%s %s,%s\nVST1%s %s,%s\n", suffix, input, registers, suffix, registers, output)
				fmt.Fprint(&source, "MOVD R0,0(R2)\nMOVD R1,8(R2)\nADD $16,R2,R3\n")
				fmt.Fprintf(&source, "VST1 %s,(R3)\nRET\n", arm64TestVectorList(30, count, "B16"))
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, ArgRegs: []Reg{"R0", "R1", "R2"}}
				fmt.Fprintf(&declarations, "extern void %s(const unsigned char *,unsigned char *,void *);\n", name)
				fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d)) return 1;\n", name, width, count, mode)
			}
		}
	}
	// The independent scalar C reference observes every byte, inactive upper
	// halves, wrapping register lists, post-index bases and store canaries.
	// Protected pages additionally reject widening the encoded read or write.
	main := arm64VectorMemoryCOracle + declarations.String() + "int main(void){\n" + checks.String() + "return 0;\n}\n"
	ir := arm64VectorMemoryTranslate(t, source.String(), target, sigs)
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "vector_memory", target, ir, main, runner, optimization)
		})
	}
}

const arm64VectorMemoryCOracle = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef void (*transfer)(const unsigned char *,unsigned char *,void *);
struct observed { uintptr_t input, output; unsigned char vectors[64]; };
static int one(transfer fn,const unsigned char *in,unsigned char *out,
               unsigned width,unsigned count,unsigned mode) {
  struct observed observed;
  memset(&observed,0xa5,sizeof(observed));
  fn(in,out,&observed);
  unsigned size=width*count;
  unsigned increment=mode==0?0:mode==2?size+5:size;
  if(observed.input!=(uintptr_t)in+increment || observed.output!=(uintptr_t)out+increment) {
    fprintf(stderr,"writeback width/count/mode %u/%u/%u\n",width,count,mode); return 1;
  }
  if(memcmp(in,out,size)) { fprintf(stderr,"byte-order/copy mismatch\n"); return 1; }
  for(unsigned reg=0;reg<count;reg++) for(unsigned byte=0;byte<16;byte++) {
    unsigned char want=byte<width?in[reg*width+byte]:0;
    if(observed.vectors[reg*16+byte]!=want) {
      fprintf(stderr,"lane/upper-half mismatch %u/%u/%u/%u/%u\n",width,count,mode,reg,byte); return 1;
    }
  }
  return 0;
}
static int check(transfer fn,unsigned width,unsigned count,unsigned mode) {
  unsigned char input[192],snapshot[192],output[192];
  for(unsigned trial=0;trial<16;trial++) for(unsigned off=0;off<16;off++) {
    for(unsigned i=0;i<192;i++) input[i]=(unsigned char)(i*71+trial*53+19);
    memcpy(snapshot,input,192); memset(output,0xa5,192);
    if(one(fn,input+32+off,output+32+off,width,count,mode)) return 1;
    if(memcmp(input,snapshot,192)) return 1;
    for(unsigned i=0;i<192;i++) if((i<32+off || i>=32+off+width*count) && output[i]!=0xa5) {
      fprintf(stderr,"store canary changed\n"); return 1;
    }
  }
  long page=sysconf(_SC_PAGESIZE);
  if(page<=0) return 1;
  unsigned char *a=mmap(0,(size_t)page*3,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
  unsigned char *b=mmap(0,(size_t)page*3,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);
  if(a==MAP_FAILED || b==MAP_FAILED) return 1;
  if(mprotect(a+page,(size_t)page,PROT_READ|PROT_WRITE) || mprotect(b+page,(size_t)page,PROT_READ|PROT_WRITE)) return 1;
  unsigned size=width*count;
  unsigned char *in=a+2*page-size,*out=b+2*page-size;
  for(unsigned i=0;i<size;i++) in[i]=(unsigned char)(i*37+11);
  int failed=one(fn,in,out,width,count,mode);
  if(munmap(a,(size_t)page*3) || munmap(b,(size_t)page*3)) return 1;
  return failed;
}
`
