package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// A portable value oracle, not a claim of native AVX512 execution. Each bank
// retains all source aliases, upper zeros, selection modes and output canaries.
func x86MaskBlendWholeByteRuntime(t *testing.T, bank string) {
	t.Helper()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable values require the native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("mask blend values require LLVM22 llc and clang")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, metadata strings.Builder
	count := 0
	for _, member := range []struct {
		op   string
		lane int
	}{
		{"VBLENDMPS", 4}, {"VBLENDMPD", 8},
		{"VPBLENDMB", 1}, {"VPBLENDMW", 2},
		{"VPBLENDMD", 4}, {"VPBLENDMQ", 8},
	} {
		for mode, suffix := range []string{"", "", ".Z"} {
			for destination := 0; destination < 3; destination++ {
				name := fmt.Sprint("Blend", count)
				mask := ""
				if mode != 0 {
					mask = "K1,"
				}
				fmt.Fprintf(&declarations, "func %s(out *[193]byte,a,b,old *[64]byte,mask uint64)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-40\n"+
					"MOVQ out+0(FP),DI\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\nMOVQ old+24(FP),DX\n"+
					"VMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (DX),Z2\n"+
					"KMOVQ mask+32(FP),K1\nSTC\n%s%s %s0,%s1,%s%s%d\n"+
					"VMOVUPS Z0,0(DI)\nVMOVUPS Z1,64(DI)\nVMOVUPS Z2,128(DI)\nSETCS 192(DI)\nRET\n",
					name, member.op, suffix, bank, bank, mask, bank, destination)
				fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", name)
				fmt.Fprintf(&metadata, "{%s,%d,%d,%d,%d},\n", name, member.lane,
					amd64VectorByteWidth(Reg(bank+"0")), mode, destination)
				count++
			}
		}
	}
	if count != 54 {
		t.Fatal("incomplete independent blend/alias inventory", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal("complete mask blend value source rejected", err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
typedef void (*Kernel)(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t);
typedef struct { Kernel run; int lane,width,mode,destination; } Row;
static const Row rows[]={
` + metadata.String() + `
};
int main(void) {
  static const uint64_t masks[]={0,UINT64_MAX,UINT64_C(0xa55a5aa5a55a5aa5),UINT64_C(1)<<63,1};
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    const Row *row=&rows[r];
    for(unsigned trial=0;trial<20;trial++) {
      uint8_t a[64],b[64],old[64],out[195],want[193];
      for(unsigned i=0;i<64;i++) {
        a[i]=(uint8_t)(i*37+trial*23+19);
        b[i]=(uint8_t)(i*13+trial*43+71);
        old[i]=(uint8_t)(i*29+trial*17+131);
      }
      uint64_t mask=masks[trial%5];
      memset(out,0xa7,sizeof(out));
      memcpy(want,a,64);
      memcpy(want+64,b,64);
      memcpy(want+128,old,64);
      want[192]=1;
      uint8_t *destination=want+row->destination*64;
      memset(destination,0,64);
      for(int i=0;i<row->width;i++) {
        int active=!row->mode || ((mask>>(i/row->lane))&1);
        destination[i]=active?a[i]:row->mode==2?0:b[i];
      }
      row->run(out+1,a,b,old,mask);
      if(out[0]!=0xa7 || out[194]!=0xa7 || memcmp(out+1,want,sizeof(want))) {
        fprintf(stderr,"blend row=%u trial=%u width=%d lane=%d mode=%d destination=%d\n",
                r,trial,row->width,row->lane,row->mode,row->destination);
        return 1;
      }
    }
  }
  return 0;
}
`
	x86ConflictFunnelPortableRuntime(t, llc, clang, "mask_blend_whole_"+bank, triple, ir, mainC)
}

func TestX86MaskBlendWholeXByteSemantics(t *testing.T) {
	x86MaskBlendWholeByteRuntime(t, "X")
}

func TestX86MaskBlendWholeYByteSemantics(t *testing.T) {
	x86MaskBlendWholeByteRuntime(t, "Y")
}

func TestX86MaskBlendWholeZByteSemantics(t *testing.T) {
	x86MaskBlendWholeByteRuntime(t, "Z")
}
