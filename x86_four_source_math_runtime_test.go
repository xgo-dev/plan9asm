package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This C computes finite, sequential lane mathematics independently of the
// production opcode and byte-domain tables. It does not model ambient MXCSR,
// exception order or native memory faults; those require the original rare
// instructions, whose actual objects have a separate complete check.
const x86FourSourceMathematicalC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <math.h>
%s
struct Kernel {
  void (*run)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
  unsigned scalar,dot,negative,saturating,alias,mode,dead;
};
static const struct Kernel kernels[]={%s};
struct Bytes { _Alignas(64) uint8_t before[64],value[256],after[64]; };
static uint32_t u32(const uint8_t *p) { uint32_t v;memcpy(&v,p,4);return v; }
static int16_t s16(const uint8_t *p) { int16_t v;memcpy(&v,p,2);return v; }
static float f32(const uint8_t *p) { float v;memcpy(&v,p,4);return v; }
static void put32(uint8_t *p,uint32_t v) { memcpy(p,&v,4); }
static const int16_t edges[]={INT16_MIN,-32767,-257,-1,0,1,256,32766,INT16_MAX};
static const uint64_t masks[]={0,1,UINT64_C(0xaaaa),UINT64_C(0x5555),UINT64_C(0xffff),UINT64_C(1)<<63};
int main(void) {
  for(unsigned ki=0;ki<sizeof(kernels)/sizeof(kernels[0]);ki++) {
    struct Kernel k=kernels[ki];
    for(unsigned sample=0;sample<97;sample++) for(unsigned mi=0;mi<sizeof(masks)/sizeof(masks[0]);mi++) {
      struct Bytes input,old,memory,out;
      memset(&input,0xa7,sizeof(input));memset(&old,0xb9,sizeof(old));
      memset(&memory,0xd5,sizeof(memory));memset(&out,0xc3,sizeof(out));
      if(k.dot) {
        for(unsigned r=0;r<4;r++) for(unsigned lane=0;lane<32;lane++) {
          int16_t v=edges[(sample+r*3+lane)%%9];memcpy(input.value+r*64+lane*2,&v,2);
        }
        for(unsigned word=0;word<8;word++) {
          int16_t v=edges[(sample+word*2)%%9];memcpy(memory.value+word*2,&v,2);
        }
        for(unsigned lane=0;lane<16;lane++) {
          int32_t v=lane%%3==0?INT32_MAX-(int32_t)sample:lane%%3==1?INT32_MIN+(int32_t)sample:-(int32_t)(sample*13);
          memcpy(old.value+lane*4,&v,4);
        }
      } else {
        for(unsigned r=0;r<4;r++) for(unsigned lane=0;lane<16;lane++) {
          uint32_t v=UINT32_C(0x3f800001)+(sample*17+r*23+lane*13);
          if((sample+r+lane)&1)v^=UINT32_C(0x80000000);
          put32(input.value+r*64+lane*4,v);
        }
        for(unsigned lane=0;lane<16;lane++) put32(old.value+lane*4,UINT32_C(0x40000001)+sample*7+lane*11);
        for(unsigned step=0;step<4;step++) put32(memory.value+step*4,UINT32_C(0x3f000001)+step*19+sample*3);
      }
      struct Bytes beforeInput=input,beforeOld=old,beforeMemory=memory;
      uint8_t expected[256];memset(expected,0xc3,sizeof(expected));
      const uint8_t *acc=k.alias?input.value:old.value;
      if(!k.dead) {
        if(k.scalar) { memset(expected,0,64);memcpy(expected,acc,16); }
        for(unsigned lane=0;lane<(k.scalar?1:16);lane++) {
          unsigned active=!k.mode||((masks[mi]>>lane)&1);
          if(!active) {
            if(k.mode==2) memset(expected+lane*4,0,4);
            else memcpy(expected+lane*4,acc+lane*4,4);
          } else if(!k.dot) {
            float value=f32(acc+lane*4);
            for(unsigned step=0;step<4;step++) {
              float source=f32(input.value+step*64+lane*4);
              if(k.negative)source=-source;
              value=fmaf(source,f32(memory.value+step*4),value);
            }
            memcpy(expected+lane*4,&value,4);
          } else {
            uint32_t value=u32(acc+lane*4);
            for(unsigned step=0;step<4;step++) {
              int64_t sum=(int64_t)s16(input.value+step*64+lane*4)*s16(memory.value+step*4)
                         +(int64_t)s16(input.value+step*64+lane*4+2)*s16(memory.value+step*4+2);
              if(k.saturating) {
                int32_t signedValue;memcpy(&signedValue,&value,4);sum+=signedValue;
                if(sum>INT32_MAX)sum=INT32_MAX;if(sum<INT32_MIN)sum=INT32_MIN;
                value=(uint32_t)sum;
              } else value+=(uint32_t)sum;
            }
            put32(expected+lane*4,value);
          }
        }
      }
      expected[64]=1;
      k.run(out.value,input.value,old.value,memory.value,masks[mi]);
      if(memcmp(out.value,expected,sizeof(expected))||memcmp(&input,&beforeInput,sizeof(input))||
         memcmp(&old,&beforeOld,sizeof(old))||memcmp(&memory,&beforeMemory,sizeof(memory))) {
        fprintf(stderr,"private mathematical kernel/sample/mask=%%u/%%u/%%llx mismatch\n",ki,sample,(unsigned long long)masks[mi]);return 1;
      }
      for(unsigned byte=0;byte<64;byte++) if(out.before[byte]!=0xc3||out.after[byte]!=0xc3)return 2;
    }
  }
  return 0;
}
`

func x86FourSourceCompletePrivateMathematics(t *testing.T, memberIndex int) {
	t.Helper()
	x86FourSourceOriginalRuntimeUnchanged(t)
	member := x86FourSourceOracle[memberIndex]
	var source, prototypes, metadata strings.Builder
	signatures := make(map[string]FuncSig)
	count := 0
	flag := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	for mode, masking := range []string{"plain", "merge", "zero"} {
		for _, destination := range []int{0, 6} {
			for _, dead := range []bool{false, true} {
				name := fmt.Sprint("MathFour", count)
				row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot,
					first: 2, dest: destination, mode: masking}
				body, _ := x86FourSourceInitializedSource(row, "amd64", name, dead)
				source.WriteString(body)
				signatures[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: Ptr, Index: 2, Field: -1},
						{Offset: 24, Type: Ptr, Index: 3, Field: -1},
						{Offset: 32, Type: I64, Index: 4, Field: -1},
					}},
				}
				fmt.Fprintf(&prototypes, "extern void InstructionFormat%d(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", count)
				fmt.Fprintf(&metadata, "{InstructionFormat%d,%d,%d,%d,%d,%d,%d,%d},\n", count,
					flag(member.scalar), flag(member.dot), flag(member.negate), flag(member.op == "VP4DPWSSDS"),
					flag(destination == 0), mode, flag(dead))
				count++
			}
		}
	}
	if count != 12 {
		t.Fatal("complete private mode/alias/live/dead mathematical partition changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	file, err := Parse(ArchAMD64, source.String())
	if err != nil || len(file.Funcs) != count {
		t.Fatal("complete initialized mathematical source lost a function", err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := x86FourSourceMathIR(t, file, signatures, triple, count)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("actual-host private lane mathematics requires exact LLVM22 llc/clang")
	}
	t.Logf("private mathematical oracle %s: 12 complete initialized kernels, 97 finite samples, six mask patterns, all bytes/aliases/CF/input and output canaries; not original native MXCSR/fault execution", member.op)
	x86ConflictFunnelPortableRuntime(t, llc, clang, "four-source-lane-mathematics", triple, ir,
		fmt.Sprintf(x86FourSourceMathematicalC, prototypes.String(), metadata.String()))
}

func TestX86FourSourcePrivateMathematicsPackedFMA(t *testing.T) {
	x86FourSourceCompletePrivateMathematics(t, 0)
}

func TestX86FourSourcePrivateMathematicsScalarFMA(t *testing.T) {
	x86FourSourceCompletePrivateMathematics(t, 1)
}

func TestX86FourSourcePrivateMathematicsPackedNegativeFMA(t *testing.T) {
	x86FourSourceCompletePrivateMathematics(t, 2)
}

func TestX86FourSourcePrivateMathematicsScalarNegativeFMA(t *testing.T) {
	x86FourSourceCompletePrivateMathematics(t, 3)
}

func TestX86FourSourcePrivateMathematicsDotWrap(t *testing.T) {
	x86FourSourceCompletePrivateMathematics(t, 4)
}

func TestX86FourSourcePrivateMathematicsDotSaturate(t *testing.T) {
	x86FourSourceCompletePrivateMathematics(t, 5)
}
