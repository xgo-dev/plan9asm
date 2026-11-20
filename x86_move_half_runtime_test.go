package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86MoveHalfCompleteBytesFlagsAndUpperAliases(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable whole-byte runtime needs its native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	source, declarations, prototypes, metadata, _ := x86MoveHalfValueProgram()
	// Always retain the complete original x86 DF source and its Go object.
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	driver := fmt.Sprintf(x86MoveHalfWholeBytesC, prototypes, metadata)
	if runtime.GOARCH != "amd64" {
		// STD/CLD are hardware x86 controls, not portable vector operations.
		// This independent companion projects DF out of its value observation;
		// the required Linux native owner executes the original with DF=1.
		source = strings.ReplaceAll(strings.ReplaceAll(source, "STD\n", ""), "CLD\n", "")
		source = strings.ReplaceAll(source, "ANDL $0xcd5,DX", "ANDL $0x8d5,DX")
		driver = strings.Replace(driver, "flags=UINT64_C(0xc91)", "flags=UINT64_C(0x891)", 1)
		t.Log("independent portable half-move companion: DF observation projected to zero; complete original x86 STD/CLD source retained separately, no native-x86 DF execution claim")
	}
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
	if err != nil {
		t.Fatal("complete initialized half-move value source rejected", err)
	}
	x86ConflictFunnelPortableRuntime(t, llc, clang, "move_half_whole_bytes", triple, ir, driver)
}

func x86MoveHalfValueProgram() (string, string, string, string, string) {
	var source, declarations, prototypes, metadata, goRows strings.Builder
	for index, row := range x86MoveHalfOracle {
		for _, alias := range []bool{false, true} {
			name, destination := fmt.Sprintf("Half%d_%t", index, alias), 2
			if alias {
				destination = 1
			}
			args := fmt.Sprintf("(SI),X%d", destination)
			if row.vector {
				args = fmt.Sprintf("(SI),X1,X%d", destination)
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ first+8(FP),BX\n"+
				"MOVQ second+16(FP),CX\nMOVQ half+24(FP),SI\nVMOVDQU64 (BX),Z1\nVMOVDQU64 (CX),Z2\n"+
				"MOVL $127,DX\nADDB $1,DL\nSTC\nSTD\n%s %s\nSETCS 64(AX)\nPUSHFQ\nPOPQ DX\nANDL $0xcd5,DX\nCLD\n"+
				"VMOVDQU64 Z%d,(AX)\nMOVQ DX,72(AX)\n%s X%d,88(AX)\nRET\n", name, row.op, args, destination, row.op, destination)
			fmt.Fprintf(&declarations, "func %s(out *[112]byte,first,second *[64]byte,half *uint64)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,const uint64_t *);\n", name)
			flag := func(value bool) int {
				if value {
					return 1
				}
				return 0
			}
			fmt.Fprintf(&metadata, "{%s,%d,%d,%d},\n", name, flag(row.vector), flag(row.high), flag(alias))
			fmt.Fprintf(&goRows, "{%s,%t,%t,%t},\n", name, row.vector, row.high, alias)
		}
	}
	return source.String(), declarations.String(), prototypes.String(), metadata.String(), goRows.String()
}

const x86MoveHalfOriginalGo = `package oracle
import("bytes";"encoding/binary";"testing")
func TestOriginal(t *testing.T) {
  rows:=[]struct{run func(*[112]byte,*[64]byte,*[64]byte,*uint64);vector,high,alias bool}{%s}
  patterns:=[]uint64{0,^uint64(0),0x8000000000000000,0x7ff0000000000001,0xfff123456789abcd,0x7ff8123456789abc,0xaaaaaaaa55555555,0x0123456789abcdef}
  outcomes:=0
  for r,row:=range rows {for sample:=0;sample<32;sample++ {
    var first,second [64]byte
    var out,want [112]byte
    for b:=range first {first[b]=byte(sample*13+b*17);second[b]=byte(sample*23+b*31+7)}
    for b:=range out {out[b]=0xa5;want[b]=0xa5}
    half:=patterns[sample%%8];if sample>=8 {half^=uint64(sample)<<21}
    base:=second;if row.vector||row.alias {base=first};copy(want[:64],base[:])
    lane:=0;if row.high {lane=8};binary.LittleEndian.PutUint64(want[lane:],half)
    if row.vector {for b:=16;b<64;b++ {want[b]=0}}
    want[64]=1;binary.LittleEndian.PutUint64(want[72:],0xc91);binary.LittleEndian.PutUint64(want[88:],half)
    row.run(&out,&first,&second,&half)
    if !bytes.Equal(out[:],want[:]) {t.Fatalf("original half row=%%d sample=%%d got=%%x want=%%x",r,sample,out,want)}
    outcomes++
  }}
  if outcomes!=512 {t.Fatal("incomplete original whole64/FLAGS/DF/canary observations",outcomes)}
}
`

const x86MoveHalfWholeBytesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
%s
struct row {void (*run)(uint8_t *,const uint8_t *,const uint8_t *,const uint64_t *); int vector,high,alias;};
static const struct row rows[]={%s};
int main(void) {
  const uint64_t patterns[]={0,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000001),
    UINT64_C(0xfff123456789abcd),UINT64_C(0x7ff8123456789abc),UINT64_C(0xaaaaaaaa55555555),UINT64_C(0x0123456789abcdef)};
  unsigned outcomes=0;
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) for(unsigned sample=0;sample<32;sample++) {
    uint8_t first[64],second[64],out[112],want[112];
    for(unsigned b=0;b<64;b++) {first[b]=(uint8_t)(sample*13+b*17);second[b]=(uint8_t)(sample*23+b*31+7);}
    uint64_t half=patterns[sample%%8]^(sample>=8?((uint64_t)sample<<21):0),flags=UINT64_C(0xc91);
    memset(out,0xa5,sizeof(out)); memset(want,0xa5,sizeof(want));
    const uint8_t *base=rows[r].vector||rows[r].alias?first:second;
    memcpy(want,base,64);
    memcpy(want+rows[r].high*8,&half,8);
    if(rows[r].vector) memset(want+16,0,48);
    want[64]=1;
    memcpy(want+72,&flags,8); memcpy(want+88,&half,8);
    rows[r].run(out,first,second,&half);
    if(memcmp(out,want,sizeof(out))) {fprintf(stderr,"half row=%%u sample=%%u\n",r,sample);return 1;}
    outcomes++;
  }
  return outcomes==512?0:2;
}
`
