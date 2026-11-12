package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86BroadcastNumericalCase struct {
	row                                                     string
	width, sourceBytes, laneBytes, masking, alias, maskData int
}

func x86BroadcastNumericalCases(original bool) []x86BroadcastNumericalCase {
	var cases []x86BroadcastNumericalCase
	for _, spec := range x86BroadcastTestDirectory {
		if !original && spec.source == "K" {
			for _, bank := range spec.destinations {
				cases = append(cases, x86BroadcastNumericalCase{
					row:         fmt.Sprintf("%s K3,%c2", spec.name, bank),
					width:       map[rune]int{'X': 16, 'Y': 32, 'Z': 64}[bank],
					sourceBytes: spec.bytes, laneBytes: spec.lane, maskData: 1,
				})
			}
			continue
		}
		if spec.source != "X" && spec.source != "XG" {
			continue
		}
		if original && spec.name != "VBROADCASTSS" && spec.name != "VBROADCASTSD" && !strings.HasPrefix(spec.name, "VPBROADCAST") {
			continue
		}
		for _, bank := range spec.destinations {
			if original && bank == 'Z' {
				continue
			}
			for _, input := range spec.source {
				if original && input == 'G' {
					continue
				} // Actual AVX512 GP execution is a separate native axis.
				for alias := 0; alias < 2; alias++ {
					if input == 'G' && alias != 0 {
						continue
					}
					src := map[rune]string{'X': "X1", 'G': "AX"}[input]
					if alias != 0 {
						src = "X2"
					}
					for masking := 0; masking < 3; masking++ {
						if original && masking != 0 {
							continue
						}
						op, mask := spec.name, ""
						if masking != 0 {
							mask = "K3,"
						}
						if masking == 2 {
							op += ".Z"
						}
						cases = append(cases, x86BroadcastNumericalCase{
							row:         fmt.Sprintf("%s %s,%s%c2", op, src, mask, bank),
							width:       map[rune]int{'X': 16, 'Y': 32, 'Z': 64}[bank],
							sourceBytes: spec.bytes, laneBytes: spec.lane, masking: masking, alias: alias,
						})
					}
				}
			}
		}
	}
	return cases
}

func x86BroadcastNumericalSource(t *testing.T, original, raw bool) (string, string, string, string) {
	t.Helper()
	var declarations, source, names, metadata strings.Builder
	bank := "Z"
	if original {
		bank = "Y"
	}
	for index, test := range x86BroadcastNumericalCases(original) {
		name := fmt.Sprint("broadcast", index)
		fmt.Fprintf(&declarations, "func %s(out *[240]byte,src,old *[64]byte,mask uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),R10\nMOVQ src+8(FP),R11\nMOVQ old+16(FP),R12\nMOVQ mask+24(FP),CX\n", name)
		fmt.Fprintf(&source, "VMOVUPS (R11),%s1\nVMOVUPS (R12),%s2\nMOVQ 0(R11),AX\nMOVQ 8(R11),BX\n", bank, bank)
		if test.masking != 0 || test.maskData != 0 {
			source.WriteString("KMOVQ CX,K3\n")
		}
		source.WriteString("STMXCSR 232(R10)\nCMPQ AX,BX\n")
		emitX86GoEncodedTestInstructionForArch(t, &source, test.row, raw, "amd64")
		fmt.Fprintf(&source, "VMOVUPS %s2,0(R10)\nVMOVUPS Y2,64(R10)\nVMOVUPS X2,96(R10)\n", bank)
		src := 1
		if test.alias != 0 {
			src = 2
		}
		fmt.Fprintf(&source, "VMOVUPS %s%d,112(R10)\nVMOVUPS Y%d,176(R10)\nVMOVUPS X%d,208(R10)\n", bank, src, src, src)
		source.WriteString("SETCS 224(R10)\nSETEQ 225(R10)\nSETMI 226(R10)\nSETOS 227(R10)\nLAHF\nMOVB AH,DL\nMOVB DL,228(R10)\nSTMXCSR 236(R10)\nRET\n")
		fmt.Fprintf(&names, "%s,", name)
		fmt.Fprintf(&metadata, "{%d,%d,%d,%d,%d,%d},\n", test.width, test.sourceBytes, test.laneBytes, test.masking, test.alias, test.maskData)
	}
	return declarations.String(), source.String(), names.String(), metadata.String()
}

func TestX86BroadcastOriginalGoNumericalViewsFlagsCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declaration, source, names, metadata := x86BroadcastNumericalSource(t, true, false)
	driver := strings.ReplaceAll(x86BroadcastOriginalGoDriver, "FUNCTIONS", names)
	driver = strings.ReplaceAll(driver, "METADATA", metadata)
	x86WordMultiplyRunOriginalGo(t, execution, "package wordmultiply\n"+declaration, source, driver)
	t.Log("Original Go: 22 VEX kernels x37 samples; physical 32-byte Y/X aliases, input/output guards, flags and MXCSR. No native AVX512 or 386 claim.")
}

func TestX86BroadcastLLVMNumericalViewsFlagsCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	cases := x86BroadcastNumericalCases(false)
	if len(cases) != 174 {
		t.Fatalf("independent numerical directory%d", len(cases))
	}
	var prototypes, rows strings.Builder
	for index, test := range cases {
		fmt.Fprintf(&prototypes, "extern void broadcast%d(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", index)
		fmt.Fprintf(&rows, "{broadcast%d,%d,%d,%d,%d,%d,%d},\n", index, test.width, test.sourceBytes, test.laneBytes, test.masking, test.alias, test.maskData)
	}
	main := strings.ReplaceAll(x86BroadcastLLVMDriver, "PROTOTYPES", prototypes.String())
	main = strings.ReplaceAll(main, "ROWS", rows.String())
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			declaration, source, _, _ := x86BroadcastNumericalSource(t, false, raw)
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, "Go")
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("IR_default_O2=%t", optimized), func(t *testing.T) {
					text := ir
					if optimized {
						text = x86MulDivRoundOptimize(t, text)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run("backend"+level, func(t *testing.T) {
							output := execution.compileAndRunLLVM(t, "register-broadcast", text, main, level)
							if !strings.Contains(string(output), "LLVM_BROADCAST_38628_CASES_PASS") {
								t.Fatal(string(output))
							}
						})
					}
				})
			}
		})
	}
}

func TestX86BroadcastMaskDataPhysicalUpperAliasLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var prototypes, rows strings.Builder
	selected := 0
	for index, test := range x86BroadcastNumericalCases(false) {
		if test.maskData == 0 {
			continue
		}
		selected++
		fmt.Fprintf(&prototypes, "extern void broadcast%d(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", index)
		fmt.Fprintf(&rows, "{broadcast%d,%d,%d,%d,%d,%d,%d},\n", index, test.width, test.sourceBytes, test.laneBytes, test.masking, test.alias, test.maskData)
	}
	if selected != 6 {
		t.Fatal("incomplete mask-data X/Y/Z numerical directory")
	}
	main := strings.ReplaceAll(x86BroadcastLLVMDriver, "PROTOTYPES", prototypes.String())
	main = strings.ReplaceAll(main, "ROWS", rows.String())
	main = strings.ReplaceAll(main, "38628", "1332")
	declaration, source, _, _ := x86BroadcastNumericalSource(t, false, false)
	ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	output := execution.compileAndRunLLVM(t, "mask-data-broadcast", ir, main, "-O0")
	if !strings.Contains(string(output), "LLVM_BROADCAST_1332_CASES_PASS") {
		t.Fatal(string(output))
	}
}

const x86BroadcastOriginalGoDriver = `package wordmultiply
import (
 "encoding/binary"
 "fmt"
 "math/bits"
 "testing"
 "unsafe"
)
func TestOriginal(t *testing.T) {
 programs := []func(*[240]byte,*[64]byte,*[64]byte,uint64){FUNCTIONS}
 rules := []struct {width,sourceBytes,laneBytes,masking,alias,maskData int}{METADATA}
 observations := 0
 for k,program := range programs {
  r := rules[k]
  for sample := 0; sample < 37; sample++ {
   var src,old [64]byte
   for i := range src { src[i]=byte(17+i*7+sample*23); old[i]=byte(199-i*3+sample*31) }
   edges:=[]uint64{0,0x8000000000000000,0x7ff8000012345678,0x7ff0000012345678,0x000000007fc01234,0x000000007f801234,0x7ff0000000000000,0xffffffffffffffff}
   if sample<len(edges) { binary.LittleEndian.PutUint64(src[:8],edges[sample]);binary.LittleEndian.PutUint64(old[:8],edges[(sample+3)%len(edges)]) }
   originalSrc,originalOld := src,old
   var packet,want [272]byte
   for i := range packet { packet[i]=byte(i*37+91) }
   want=packet
   var value [32]byte
   input := src
   if r.alias != 0 { input=old }
   for i := range value { if i<r.width { value[i]=input[i%r.sourceBytes] } }
   copy(want[16:48],value[:])
   copy(want[80:112],value[:])
   copy(want[112:128],value[:16])
   observed := src[:32]
   if r.alias != 0 { observed=value[:] }
   copy(want[128:160],observed)
   copy(want[192:224],observed)
   copy(want[224:240],observed[:16])
   x,y:=binary.LittleEndian.Uint64(src[:8]),binary.LittleEndian.Uint64(src[8:16])
   d:=x-y
   bit:=func(v bool)byte { if v { return 1 }; return 0 }
   cf,zf,sf,of:=bit(x<y),bit(x==y),bit(d>>63!=0),bit(((x^y)&(x^d))>>63!=0)
   pf,af:=bit(bits.OnesCount8(byte(d))%2==0),bit((x^y^d)&16!=0)
   want[240],want[241],want[242],want[243]=cf,zf,sf,of
   want[244]=2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7)
   program((*[240]byte)(unsafe.Pointer(&packet[16])),&src,&old,0)
   if binary.LittleEndian.Uint32(packet[248:252])!=binary.LittleEndian.Uint32(packet[252:256]) { t.Fatal("MXCSR changed") }
   copy(want[248:256],packet[248:256])
   if packet!=want || src!=originalSrc || old!=originalOld { t.Fatalf("kernel%d sample%d got%x want%x",k,sample,packet,want) }
   observations++
  }
 }
 if len(programs)!=22 || observations!=814 { t.Fatalf("incomplete denominator%d/%d",len(programs),observations) }
 fmt.Println("ORIGINAL_BROADCAST_814_CASES_PASS")
}
`

const x86BroadcastLLVMDriver = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
PROTOTYPES
typedef struct {
 void (*program)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
 unsigned width,sourceBytes,laneBytes,masking,alias,maskData;
} rule;
static const rule rules[]={ROWS};
int main(void) {
 const uint64_t masks[]={0,1,2,UINT64_C(0xaaaaaaaa55555555),UINT64_MAX,UINT64_C(1)<<63};
 unsigned observations=0;
 for(unsigned k=0;k<sizeof(rules)/sizeof(rules[0]);k++) {
  const rule r=rules[k];
  for(unsigned sample=0;sample<37;sample++) for(unsigned m=0;m<6;m++) {
   uint8_t src[64],old[64],savedSrc[64],savedOld[64];
   uint8_t packet[272],want[272],value[64];
   for(unsigned i=0;i<64;i++) {src[i]=(uint8_t)(17+i*7+sample*23);old[i]=(uint8_t)(199-i*3+sample*31);}
   const uint64_t edges[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x7ff8000012345678),UINT64_C(0x7ff0000012345678),UINT64_C(0x000000007fc01234),UINT64_C(0x000000007f801234),UINT64_C(0x7ff0000000000000),UINT64_MAX};
   if(sample<8) {memcpy(src,&edges[sample],8);memcpy(old,&edges[(sample+3)%8],8);}
   memcpy(savedSrc,src,64);memcpy(savedOld,old,64);
   for(unsigned i=0;i<272;i++) packet[i]=(uint8_t)(i*37+91);
   memcpy(want,packet,272);
   const uint8_t *input=r.alias?old:src;
   for(unsigned i=0;i<64;i++) {
    unsigned active=!r.masking||((masks[m]>>(i/r.laneBytes))&1);
    uint8_t computed=input[i%r.sourceBytes];
    if(r.maskData) computed=i%r.laneBytes<r.sourceBytes?(uint8_t)(masks[m]>>(8*(i%r.laneBytes))):0;
    value[i]=i>=r.width?0:active?computed:r.masking==2?0:old[i];
   }
   memcpy(want+16,value,64);memcpy(want+80,value,32);memcpy(want+112,value,16);
   const uint8_t *observed=r.alias?value:src;
   memcpy(want+128,observed,64);memcpy(want+192,observed,32);memcpy(want+224,observed,16);
   uint64_t x,y;memcpy(&x,src,8);memcpy(&y,src+8,8);
   uint64_t d=x-y;
   unsigned cf=x<y,zf=x==y,sf=d>>63,of=((x^y)&(x^d))>>63;
   unsigned pf=(__builtin_popcount((uint8_t)d)&1)==0,af=((x^y^d)&16)!=0;
   want[240]=cf;want[241]=zf;want[242]=sf;want[243]=of;
   want[244]=2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7);
   uint32_t saved=_mm_getcsr(),profile=(uint32_t)(0x1f80|((sample%4)<<13)|(sample%64));
   _mm_setcsr(profile);
   r.program(packet+16,src,old,masks[m]);
   uint32_t before,after;memcpy(&before,packet+248,4);memcpy(&after,packet+252,4);
   unsigned csrValid=before==profile&&after==profile&&_mm_getcsr()==profile;
   _mm_setcsr(saved);
   memcpy(want+248,packet+248,8);
   if(!csrValid||memcmp(packet,want,272)||memcmp(src,savedSrc,64)||memcmp(old,savedOld,64)) {
    for(unsigned i=0;i<272;i++) if(packet[i]!=want[i]) fprintf(stderr,"kernel%u sample%u mask%u byte%u got%x want%x\n",k,sample,m,i,packet[i],want[i]);
    return 1;
   }
   observations++;
  }
 }
 if(observations!=38628) return 1;
 puts("LLVM_BROADCAST_38628_CASES_PASS");
 return 0;
}
`
