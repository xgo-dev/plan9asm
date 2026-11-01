package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86SingleSourceNarrowingTestNames() []string {
	return strings.Fields(`VPMOVDB VPMOVDW VPMOVQB VPMOVQD VPMOVQW VPMOVWB
		VPMOVSDB VPMOVSDW VPMOVSQB VPMOVSQD VPMOVSQW VPMOVSWB
		VPMOVUSDB VPMOVUSDW VPMOVUSQB VPMOVUSQD VPMOVUSQW VPMOVUSWB`)
}

// Intel SDM's unsigned-source narrowing is distinct from PACK's signed input
// with unsigned output. Exercise the high bit without borrowing PACK's oracle.
// These are portable translated semantics, not original AVX512 execution.
func TestX86SingleSourceNarrowingUnsignedSourceBoundaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("unsigned-source narrowing requires LLVM22 llc/clang")
	}
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, member := range []struct {
		op                            string
		inputBits, outputBits, domain int
	}{
		{"VPMOVUSWB", 16, 8, 2}, {"VPMOVUSDB", 32, 8, 2}, {"VPMOVUSQB", 64, 8, 2},
		{"VPMOVUSDW", 32, 16, 2}, {"VPMOVUSQW", 64, 16, 2}, {"VPMOVUSQD", 64, 32, 2},
		{"VPMOVSWB", 16, 8, 1}, {"VPMOVSDB", 32, 8, 1}, {"VPMOVSQB", 64, 8, 1},
		{"VPMOVSDW", 32, 16, 1}, {"VPMOVSQW", 64, 16, 1}, {"VPMOVSQD", 64, 32, 1},
		{"VPMOVWB", 16, 8, 0}, {"VPMOVDB", 32, 8, 0}, {"VPMOVQB", 64, 8, 0},
		{"VPMOVDW", 32, 16, 0}, {"VPMOVQW", 64, 16, 0}, {"VPMOVQD", 64, 32, 0},
	} {
		for index, bank := range []string{"X", "Y", "Z"} {
			width := 16 << index
			carrier := "X"
			if width*member.outputBits/member.inputBits > 16 {
				carrier = "Y"
			}
			for _, memory := range []bool{false, true} {
				name := fmt.Sprintf("UnsignedNarrow%d", count)
				operation := fmt.Sprintf("%s %s0,%s1\nVMOVUPS Z1,(DX)\n", member.op, bank, carrier)
				memoryFlag := 0
				if memory {
					operation = fmt.Sprintf("MOVQ $0xaaaaaaaaaaaaaaaa,CX\nKMOVQ CX,K1\n%s %s0,K1,(DX)\n", member.op, bank)
					memoryFlag = 1
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ input+0(FP),AX\nMOVQ out+8(FP),DX\n"+
					"VMOVUPS (AX),Z0\nVMOVUPS (AX),Z1\n%sRET\n", name, operation)
				fmt.Fprintf(&declarations, "func %s(input,out *[64]byte)\n", name)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint8_t*);\n", name)
				fmt.Fprintf(&rows, "{%s,\"%s\",%d,%d,%d,%d,%d},\n", name, member.op, width, member.inputBits, member.outputBits, member.domain, memoryFlag)
				count++
			}
		}
	}
	if count != 108 {
		t.Fatal("lost narrowing input domain, member or vector width", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes.String() + `
typedef struct {
 void(*run)(const uint8_t*,uint8_t*);
 const char *op;
 unsigned width,inbits,outbits,domain,memory;
} Row;
static const Row rows[]={
` + rows.String() + `};
int main(void) {
 for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
  const Row *p=rows+r;
  uint64_t maximum=(UINT64_C(1)<<p->outbits)-1;
  uint64_t source_max=UINT64_MAX>>(64-p->inbits),high=UINT64_C(1)<<(p->inbits-1);
  uint64_t signed_max=maximum>>1,signed_min=source_max-signed_max;
  const uint64_t edges[]={0,1,maximum-1,maximum,maximum+1,high,high+1,source_max-1,source_max,
   signed_max-1,signed_max,signed_max+1,signed_min-1,signed_min,signed_min+1};
  for(unsigned sample=0;sample<sizeof(edges)/sizeof(edges[0]);sample++) {
   uint8_t input[64],saved[64],output[66],want[64]={0};
   if(p->memory) memset(want,0xa7,sizeof(want));
   for(unsigned lane=0;lane<64/(p->inbits/8);lane++) {
    uint64_t value=edges[(sample+lane)%(sizeof(edges)/sizeof(edges[0]))];
    for(unsigned b=0;b<p->inbits/8;b++) input[lane*(p->inbits/8)+b]=(uint8_t)(value>>(b*8));
    if(lane<p->width/(p->inbits/8)&&(!p->memory||(lane&1))) {
     uint64_t narrowed=value&maximum;
     if(p->domain==2) narrowed=value>maximum?maximum:value;
     if(p->domain==1) {
      int64_t signed_value;
      if(p->inbits==64) memcpy(&signed_value,&value,sizeof(value));
      else signed_value=(int64_t)value-((value&high)?(INT64_C(1)<<p->inbits):0);
      int64_t upper=(int64_t)signed_max,lower=-upper-1;
      if(signed_value>upper) signed_value=upper;
      if(signed_value<lower) signed_value=lower;
      narrowed=(uint64_t)signed_value&maximum;
     }
     for(unsigned b=0;b<p->outbits/8;b++) want[lane*(p->outbits/8)+b]=(uint8_t)(narrowed>>(b*8));
    }
   }
   memcpy(saved,input,64);
   memset(output,0xa7,sizeof(output));
   p->run(input,output+1);
   if(memcmp(output+1,want,64)||memcmp(input,saved,64)||output[0]!=0xa7||output[65]!=0xa7) {
    fprintf(stderr,"unsigned-source narrow op=%s width=%u sample=%u\n",p->op,p->width,sample);
    return 1;
   }
  }
 }
 return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("initialized unsigned-source narrowing rejected before numerical comparison", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "unsigned-source-narrow", triple, ir, driver)
		})
	}
}

// Preserve all 54 Go-encoded memory.Z forms as terminal architectural traps.
// LLVM22's avx512_trunc_common has rr/rrk/rrkz and mr/mrk, never mrkz;
// this matches the existing whole-vector move/compact undefined-opcode owner.
func TestX86SingleSourceNarrowingMemoryZeroingKeepsGoEncodingAndTerminalTrap(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	var names []string
	for _, op := range x86SingleSourceNarrowingTestNames() {
		for _, bank := range []string{"X", "Y", "Z"} {
			instruction := fmt.Sprintf("%s.Z %s0,K1,(AX)", op, bank)
			code := x86PackedFirstGoInstructionBytes(t, "amd64", instruction)
			if len(code) != 6 || code[0] != 0x62 || code[3]&0x80 == 0 || code[5]>>6 == 3 {
				t.Fatalf("actual Go instruction lacks EVEX.z memory identity: %s %x", instruction, code)
			}
			t.Logf("actual Go memory.Z opcode=%s bytes=%x", instruction, code)
			name := fmt.Sprintf("NarrowTrap%d", len(names))
			source.WriteString(x86PackedZeroStoreInstruction("·"+name, instruction))
			fmt.Fprintf(&declarations, "func %s()\n", name)
			names = append(names, name)
		}
	}
	if len(names) != 54 {
		t.Fatal("a former Go-encoded shape disappeared", len(names))
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("Go-encoded trap failed before object verification", err)
					}
					for _, name := range names {
						if _, err := x86OfficialMoveFaultBody(ir, name); err != nil {
							t.Fatal("trap read a mask/vector/address or retained an ordinary continuation", err)
						}
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, api)
				})
			}
		})
	}
}

func TestX86SingleSourceNarrowingMergeUsesOnlyActiveOldBytes(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT partial(SB),4,$0-0\nVPMOVDB X0,K1,X1\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ins := file.Funcs[0].Instrs[0]
	if ins.Op == OpTEXT {
		ins = file.Funcs[0].Instrs[1]
	}
	effect, known, err := x86TypedSingleSourceNarrowByteEffect(ins.Op, ins, "amd64")
	if !known || err != nil || !effect.operands[1].read || effect.operands[1].requiredBytes != 0xf || effect.operands[1].width != 16 {
		t.Fatal("active result tuple was confused with the physical carrier", effect, err)
	}
	for _, change := range []string{"valid", "source missing", "old missing", "mask missing"} {
		state := x86ResultState{}
		state.xmm[0], state.xmm[1], state.masks[1] = 0xffff, 0xf, true
		switch change {
		case "source missing":
			state.xmm[0] &^= 0x8000
		case "old missing":
			state.xmm[1] &^= 0x8
		case "mask missing":
			state.masks[1] = false
		}
		ok, known := x86ResultSingleSourceNarrowStep(ins, &state, nil, 0, "amd64", false)
		if !known || ok != (change == "valid") || ok && state.vectorBytes(1) != ^uint64(0) {
			t.Fatal("partial old bytes, input obligations or zero upper aliases changed", change, ok, state.vectorBytes(1))
		}
	}
	const body = "TEXT ·PartialNarrow(SB),4,$0-24\nMOVQ input+0(FP),DI\nMOVQ old+8(FP),SI\nMOVQ out+16(FP),DX\n" +
		"VMOVUPS (DI),Z0\nMOVSS (SI),X3\nMOVSS X3,X1\nMOVL $1,AX\nKMOVQ AX,K1\nVPMOVDB X0,K1,X1\nVMOVUPS Z1,(DX)\nRET\n"
	const declaration = "func PartialNarrow(input,old,out *[64]byte)\n"
	for _, api := range []string{"text", "module", "Go"} {
		for _, change := range []string{"valid", "source missing", "old missing"} {
			source := body
			if change == "source missing" {
				source = strings.Replace(source, "VMOVUPS (DI),Z0", "MOVSS X3,X0", 1)
			}
			if change == "old missing" {
				source = strings.Replace(source, "MOVSS X3,X1\n", "", 1)
			}
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if change == "valid" && err != nil || change != "valid" && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
				t.Fatal("public API changed partial-byte admission", api, change, err)
			}
			if change == "valid" {
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM22 llc required for initialized partial-carrier objects")
				}
				x86ResultInitializationObject(t, llc, "x86_64-unknown-linux-gnu", ir, api)
			}
		}
	}
}
