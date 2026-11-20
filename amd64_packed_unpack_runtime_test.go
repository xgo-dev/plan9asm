package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// One independent reference is shared by all format programs. Keeping this
// out of main avoids compiling hundreds of copies of the same canary loops.
const x86UnpackBitwiseRuntimeOracle = `
static uint8_t patterns[4][64];
static const uint64_t masks[]={0,1,UINT64_C(0x55aa55aa55aa55aa),UINT64_MAX};
__attribute__((noinline)) static int checkUnpack(
 void (*program)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t),
 const char *name,int width,int lane,int high,int mode,int broadcast,int legacy,int destination,int shift) {
 for(int round=0;round<4;++round) for(int m=0;m<4;++m) {
  _Alignas(64) uint8_t aStorage[96],bStorage[96],output[68];
  uint8_t *a=aStorage+shift,*b=bStorage+3;
  memset(aStorage,0xa7,sizeof(aStorage));
  memset(bStorage,0xb9,sizeof(bStorage));
  memset(output,0xc3,sizeof(output));
  memcpy(a,patterns[round],64);
  memcpy(b,patterns[(round+1)%4],64);
  uint64_t mask=masks[m];
  uint32_t saved,before=0x1f80|(round<<13)|round,after;
  __asm__ volatile("stmxcsr %0" : "=m"(saved));
  __asm__ volatile("ldmxcsr %0" : : "m"(before));
  program(output+1,a,b,mask);
  __asm__ volatile("stmxcsr %0" : "=m"(after));
  __asm__ volatile("ldmxcsr %0" : : "m"(saved));
  if(after!=before || output[0]!=0xc3 || output[67]!=0xc3 || output[65]!=1 || output[66]!=0) {
   fprintf(stderr,"%s round=%d mask=%llx CSR/flags/canary failure\n",name,round,(unsigned long long)mask);
   return 1;
  }
  for(int i=0;i<64;++i) {
   int source=(i/16)*16+high+((i%16)/(2*lane))*lane+i%lane;
   uint8_t selected=(i/lane)%2 ? a[broadcast ? source%lane : source] : b[source];
   const uint8_t *old=destination==1 ? a : b;
   int active=mode==0 || ((mask>>(i/lane))&1);
   uint8_t want=i<width ? (active ? selected : (mode==2 ? 0 : old[i])) : (legacy ? b[i] : 0);
   if(output[i+1]!=want || a[i]!=patterns[round][i] || b[i]!=patterns[(round+1)%4][i]) {
    fprintf(stderr,"%s round=%d mask=%llx byte=%d got=%x want=%x\n",name,round,(unsigned long long)mask,i,output[i+1],want);
    return 1;
   }
  }
  for(int i=0;i<96;++i) {
   if((i<shift || i>=shift+64) && aStorage[i]!=0xa7) return 1;
   if((i<3 || i>=67) && bStorage[i]!=0xb9) return 1;
  }
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86PackedUnpackCompleteSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, opcode := range x86CallerUnpackOpcodes() {
		legacy := !strings.HasPrefix(opcode, "V")
		widths := []int{16}
		if !legacy {
			widths = []int{16, 32, 64}
		}
		lane := x86UnpackTestLaneBytes(opcode)
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, memory := range []string{"register", "memory", "broadcast"} {
				if memory == "broadcast" && (legacy || lane < 4) {
					continue
				}
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					if legacy && mode != "unmasked" {
						continue
					}
					for _, destination := range []int{0, 1, 2} {
						if legacy && destination != 0 {
							continue
						}
						name := fmt.Sprintf("unpack%d", count)
						count++
						first := bank + "1"
						if memory != "register" {
							first = "(BX)"
						}
						operation := opcode
						if memory == "broadcast" {
							operation += ".BCST"
						}
						if mode == "zero" {
							operation += ".Z"
						}
						row := operation + " " + first + "," + bank + "0"
						if !legacy {
							if mode != "unmasked" {
								row += ",K1"
							}
							row += fmt.Sprintf(",%s%d", bank, destination)
						}
						fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (CX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z2\nKMOVQ DX,K1\nCMPQ AX,AX\nSTC\n%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", name, row, destination)
						sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1},
							{Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1},
							{Offset: 24, Type: I64, Index: 3, Field: -1},
						}}}
						fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
						high := 0
						if strings.Contains(opcode, "UNPCKH") {
							high = 8
						}
						// Legacy m128 requires aligned storage. All other forms
						// exercise unaligned input/output pointers and canaries.
						shift := 1
						if legacy && memory == "memory" {
							shift = 16
						}
						modeValue := map[string]int{"unmasked": 0, "merge": 1, "zero": 2}[mode]
						fmt.Fprintf(&checks, "if(checkUnpack(%s,\"%s\",%d,%d,%d,%d,%d,%d,%d,%d)) return 1;\n", name, name,
							width, lane, high, modeValue, x86FloatAddSubBoolInt(memory == "broadcast"), x86FloatAddSubBoolInt(legacy), destination, shift)
					}
				}
			}
		}
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := `#include <stdint.h>
#include <string.h>
#include <stdio.h>
` + declarations.String() + x86UnpackBitwiseRuntimeOracle + `
int main(void) {
 for(int p=0;p<4;++p) for(int i=0;i<64;++i) patterns[p][i]=(uint8_t)(i*19+p*83+7);
 // These include float32/float64 signaling/quiet NaN payloads. An unpack
 // must copy their exact bits and leave even pre-existing MXCSR flags alone.
 const uint64_t specials[]={UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff8fedcba987654),UINT64_C(0x7f812345ffc45678),UINT64_C(0x800000007fc12345)};
 memcpy(patterns[2],specials,sizeof(specials));
 memcpy(patterns[3]+32,specials,sizeof(specials));
` + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "unpack-complete", triple, ir, main, prefix)
	t.Logf("%d opcode/width/memory/mask/alias programs, 16 independent bitwise/MXCSR/flag/canary inputs each", count)
}
