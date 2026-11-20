package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86PackedAlignWholeBytes(t *testing.T, bank string) {
	t.Helper()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable whole-byte oracle requires its native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, metadata strings.Builder
	count, pending, batches := 0, 0, 0
	flush := func() {
		if pending < 1 || pending > 64 {
			t.Fatal("invalid bounded runtime batch", pending)
		}
		t.Run(fmt.Sprint("batch", batches), func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
			if err != nil {
				t.Fatal("initialized whole-byte source rejected", err)
			}
			mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
typedef void (*Kernel)(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t);
typedef struct {Kernel run;int width,bits,selector,legacy,mode;} Row;
static const Row rows[]={
` + metadata.String() + `
};
int main(void) {
  const uint64_t masks[]={0,UINT64_MAX,UINT64_C(0xa5a5a5a5a5a5a5a5),UINT64_C(0x8000000000000000),1};
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    Row row=rows[r];
    for(int trial=0;trial<32;trial++) {
      uint8_t first[64],second[64],old[64],out[259],want[257];
      for(int i=0;i<64;i++) {
        first[i]=(uint8_t)(i*23+trial*37+19);
        second[i]=(uint8_t)(i*47+trial*13+71);
        old[i]=(uint8_t)(i*11+trial*53+139);
      }
      uint64_t mask=masks[trial%5];
      memset(out,0xa7,sizeof(out));
      memset(want,0,sizeof(want));
      memcpy(want+64,first,64);
      memcpy(want+128,second,64);
      memcpy(want+192,old,64);
      if(row.legacy) memcpy(want+16,old+16,48);
      want[256]=1;
      for(int output=0;output<row.width;output++) {
        uint8_t value=0;
        if(row.bits==8) {
          int at=output%16+row.selector;
          if(at<16) value=first[output/16*16+at];
          else if(at<32) value=(row.legacy?old:second)[output/16*16+at-16];
        } else {
          int bytes=row.bits/8;
          int at=(output/bytes+(row.selector&(row.width/bytes-1)))*bytes+output%bytes;
          value=at<row.width?first[at]:second[at-row.width];
        }
        int lane=output/(row.bits/8);
        if(row.mode && !((mask>>lane)&1)) value=row.mode==2?0:old[output];
        want[output]=value;
      }
      row.run(out+1,first,second,old,mask);
      if(out[0]!=0xa7 || out[258]!=0xa7 || memcmp(out+1,want,sizeof(want))) {
        fprintf(stderr,"align row=%u trial=%d bits=%d width=%d selector=%d legacy=%d mode=%d\n",r,trial,row.bits,row.width,row.selector,row.legacy,row.mode);
        return 1;
      }
    }
  }
  return 0;
}
`
			x86ConflictFunnelPortableRuntime(t, llc, clang, "align_whole_"+bank, triple, ir, mainC)
		})
		batches++
		pending = 0
		source.Reset()
		declarations.Reset()
		prototypes.Reset()
		metadata.Reset()
	}
	for _, row := range x86PackedAlignRows() {
		if row.legacy && bank != "X" {
			continue
		}
		for mode, suffix := range []string{"", "", ".Z"} {
			if row.legacy && mode != 0 {
				continue
			}
			for _, immediate := range []int{0, 1, 15, 16, 17, 31, 32, 255} {
				name, mask, legacy := fmt.Sprint("AlignWhole", count), "", 0
				if mode != 0 {
					mask = "K1,"
				}
				if row.legacy {
					legacy = 1
				}
				instruction := x86PackedAlignInstruction(row.op+suffix, bank+"0", bank, mask, immediate, 2, row.legacy)
				fmt.Fprintf(&declarations, "func %s(out *[257]byte,a,b,old *[64]byte,mask uint64)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),DI\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\nMOVQ old+24(FP),DX\n"+
					"VMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (DX),Z2\nVMOVUPS (DX),Z3\nKMOVQ mask+32(FP),K1\nSTC\n%s\n"+
					"VMOVUPS Z2,0(DI)\nVMOVUPS Z0,64(DI)\nVMOVUPS Z1,128(DI)\nVMOVUPS Z3,192(DI)\nSETCS 256(DI)\nRET\n", name, instruction)
				fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", name)
				fmt.Fprintf(&metadata, "{%s,%d,%d,%d,%d,%d},\n", name, amd64VectorByteWidth(Reg(bank+"0")), row.bits, immediate, legacy, mode)
				count++
				pending++
				if pending == 64 {
					flush()
				}
			}
		}
	}
	want := 72
	if bank == "X" {
		want = 80
	}
	if count != want {
		t.Fatal("incomplete whole-byte family/mask/selector union", count, want)
	}
	if pending != 0 {
		flush()
	}
	if batches != 2 {
		t.Fatal("incomplete bounded runtime union", batches)
	}
}

func TestX86PackedAlignWholeXByteSemantics(t *testing.T) {
	x86PackedAlignWholeBytes(t, "X")
}

func TestX86PackedAlignWholeYByteSemantics(t *testing.T) {
	x86PackedAlignWholeBytes(t, "Y")
}

func TestX86PackedAlignWholeZByteSemantics(t *testing.T) {
	x86PackedAlignWholeBytes(t, "Z")
}
