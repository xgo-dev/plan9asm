package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// These are the unchanged original C numerical oracles, compiled for the
// actual host. They do not claim original AVX512 hardware execution.
func x86ConflictFunnelPortableRuntime(t *testing.T, llc, clang, name, triple, ir, mainC string) {
	t.Helper()
	for _, pipeline := range []struct {
		name      string
		optimized bool
		backend   int
	}{
		{name: "backend_O0"},
		{name: "backend_O2", backend: 2},
		{name: "IR_O2/backend_O2", optimized: true, backend: 2},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			text := ir
			if pipeline.optimized {
				text = x86DwordProductIROptimize(t, ir)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, name, triple,
				text, mainC, nil, pipeline.backend)
		})
	}
}

func x86ConflictFunnelWholeByteRuntime(t *testing.T, bank string) {
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
	count := 0
	for _, row := range x86ConflictFunnelRows() {
		for mode, suffix := range []string{"", "", ".Z"} {
			name := fmt.Sprint("Whole", count)
			mask := ""
			if mode != 0 {
				mask = "K1,"
			}
			selector := 255
			if bank == "X" {
				selector = 0
			} else if bank == "Y" {
				selector = row.bits // The immediate wraps modulo the lane width.
			}
			instruction := x86ConflictFunnelInstruction(row.op+suffix, bank, bank+"0", mask, row.unary, row.variable)
			instruction = strings.Replace(instruction, "$255,", fmt.Sprintf("$%d,", selector), 1)
			fmt.Fprintf(&declarations, "func %s(out *[257]byte,a,b,old *[64]byte,mask uint64)\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-40\n"+
				"MOVQ out+0(FP),DI\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\nMOVQ old+24(FP),DX\n"+
				"VMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (DX),Z2\nVMOVUPS (DX),Z3\n"+
				"KMOVQ mask+32(FP),K1\nSTC\n%s\n"+
				"VMOVUPS Z2,0(DI)\nVMOVUPS Z0,64(DI)\nVMOVUPS Z1,128(DI)\nVMOVUPS Z3,192(DI)\nSETCS 256(DI)\nRET\n", name, instruction)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", name)
			kind, left := 0, 0
			if !row.unary {
				kind = 1
				if row.variable {
					kind = 2
				}
				if strings.HasPrefix(row.op, "VPSHL") {
					left = 1
				}
			}
			fmt.Fprintf(&metadata, "{%s,%d,%d,%d,%d,%d,%d},\n", name, kind, row.bits,
				amd64VectorByteWidth(Reg(bank+"0")), left, mode, selector)
			count++
		}
	}
	if count != 42 {
		t.Fatal("incomplete independent whole-byte numerical union", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal("complete original whole-byte source rejected", err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + prototypes.String() + `
typedef void (*Kernel)(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t);
typedef struct { Kernel run; int kind,bits,width,left,mode,selector; } Row;
static const Row rows[] = {
` + metadata.String() + `
};
static uint64_t read_lane(const uint8_t *p,int bytes) {
  uint64_t value=0;
  for(int i=0;i<bytes;i++) value|=(uint64_t)p[i]<<(8*i);
  return value;
}
static void write_lane(uint8_t *p,int bytes,uint64_t value) {
  for(int i=0;i<bytes;i++) p[i]=(uint8_t)(value>>(8*i));
}
int main(void) {
  static const uint64_t masks[]={0,UINT64_MAX,UINT64_C(0xaaaaaaaa55555555),UINT64_C(0x8000000000000000),1};
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    const Row *row=&rows[r];
    for(int trial=0;trial<32;trial++) {
      uint8_t a[64],b[64],old[64],out[259],want[257];
      for(int i=0;i<64;i++) {
        a[i]=(uint8_t)(i*37+trial*23+19);
        b[i]=(uint8_t)(i*13+trial*43+71);
        old[i]=(uint8_t)(i*29+trial*17+131);
      }
      int bytes=row->bits/8,lanes=row->width/bytes;
      if(row->kind==0) {
        for(int lane=0;lane<lanes;lane++) write_lane(a+lane*bytes,bytes,(uint64_t)((lane+trial)%4)*UINT64_C(0x1020304));
      } else if(row->kind==2) {
        const uint64_t counts[]={0,1,(uint64_t)(row->bits-1),(uint64_t)row->bits,(uint64_t)(row->bits+1),UINT64_MAX};
        for(int lane=0;lane<lanes;lane++) write_lane(a+lane*bytes,bytes,counts[(lane+trial)%6]);
      }
      uint64_t mask=masks[trial%5];
      memset(out,0xa7,sizeof(out));
      memset(want,0,sizeof(want));
      memcpy(want+64,a,64);
      memcpy(want+128,b,64);
      memcpy(want+192,old,64);
      want[256]=1;
      for(int lane=0;lane<lanes;lane++) {
        uint64_t first=read_lane(a+lane*bytes,bytes),second=read_lane(b+lane*bytes,bytes);
        uint64_t previous=read_lane(old+lane*bytes,bytes),result=0;
        if(row->kind==0) {
          for(int prior=0;prior<lane;prior++) if(first==read_lane(a+prior*bytes,bytes)) result|=UINT64_C(1)<<prior;
        } else {
          unsigned count=(row->kind==2?(unsigned)first:(unsigned)row->selector)&(row->bits-1);
          uint64_t base=row->kind==2?previous:second,other=row->kind==2?second:first;
          if(!count) result=base;
          else if(row->left) result=(base<<count)|(other>>(row->bits-count));
          else result=(base>>count)|(other<<(row->bits-count));
        }
        if(row->mode && !((mask>>lane)&1)) result=row->mode==2?0:previous;
        write_lane(want+lane*bytes,bytes,result);
      }
      rows[r].run(out+1,a,b,old,mask);
      if(out[0]!=0xa7 || out[258]!=0xa7 || memcmp(out+1,want,sizeof(want))) {
        fprintf(stderr,"whole-byte row=%u trial=%d bits=%d width=%d mode=%d\n",r,trial,row->bits,row->width,row->mode);
        return 1;
      }
    }
  }
  return 0;
}
`
	x86ConflictFunnelPortableRuntime(t, llc, clang, "conflict_funnel_whole_"+bank, triple, ir, mainC)
}

func TestX86ConflictFunnelWholeXByteSemantics(t *testing.T) {
	x86ConflictFunnelWholeByteRuntime(t, "X")
}

func TestX86ConflictFunnelWholeYByteSemantics(t *testing.T) {
	x86ConflictFunnelWholeByteRuntime(t, "Y")
}

func TestX86ConflictFunnelWholeZByteSemantics(t *testing.T) {
	x86ConflictFunnelWholeByteRuntime(t, "Z")
}
