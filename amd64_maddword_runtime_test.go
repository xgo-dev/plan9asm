package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

const x86WordMaddIndependentRuntimeOracle = `
static uint8_t patterns[8][64];
static const uint64_t masks[]={0,1,UINT64_C(0x55aa55aa55aa55aa),UINT64_MAX};
static int32_t word(const uint8_t *p) {
 uint32_t bits=(uint32_t)p[0]|(uint32_t)p[1]<<8;
 return bits<32768 ? (int32_t)bits : (int32_t)bits-65536;
}
__attribute__((noinline)) static int checkMadd(
 void (*program)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t),
 const char *name,int width,int mode,int legacy,int destination,int shift) {
 for(int round=0;round<8;++round) for(int m=0;m<4;++m) {
  _Alignas(64) uint8_t aStorage[96],bStorage[96],output[68];
  uint8_t *a=aStorage+shift,*b=bStorage+3;
  memset(aStorage,0xa7,sizeof(aStorage)); memset(bStorage,0xb9,sizeof(bStorage));
  memset(output,0xc3,sizeof(output));
  memcpy(a,patterns[round],64); memcpy(b,patterns[(round+1)%8],64);
  uint64_t mask=masks[m];
  uint32_t saved,before=0x1f80|((round%4)<<13)|round,after;
  __asm__ volatile("stmxcsr %0" : "=m"(saved));
  __asm__ volatile("ldmxcsr %0" : : "m"(before));
  program(output+1,a,b,mask);
  __asm__ volatile("stmxcsr %0" : "=m"(after));
  __asm__ volatile("ldmxcsr %0" : : "m"(saved));
  if(after!=before || output[0]!=0xc3 || output[67]!=0xc3 || output[65]!=1 || output[66]!=0) {
   fprintf(stderr,"%s round=%d CSR/flags/canary failure\n",name,round); return 1;
  }
  for(int i=0;i<64;i+=4) {
   // Widen independently to signed int64 before summing. Conversion to
   // uint32 implements the specified pair wrap, including 0x80000000.
   uint32_t result=(uint32_t)((int64_t)word(a+i)*word(b+i)+(int64_t)word(a+i+2)*word(b+i+2));
   const uint8_t *old=destination==1 ? a : b;
   int active=mode==0 || ((mask>>(i/4))&1);
   for(int j=0;j<4;++j) {
    uint8_t want=i<width ? (active ? (uint8_t)(result>>(j*8)) : (mode==2 ? 0 : old[i+j])) : (legacy ? b[i+j] : 0);
    if(output[i+j+1]!=want) {
     fprintf(stderr,"%s round=%d mask=%llx byte=%d got=%x want=%x\n",name,round,(unsigned long long)mask,i+j,output[i+j+1],want); return 1;
    }
   }
  }
  for(int i=0;i<96;++i) {
   if((i<shift || i>=shift+64) && aStorage[i]!=0xa7) return 1;
   if((i<3 || i>=67) && bStorage[i]!=0xb9) return 1;
  }
  if(memcmp(a,patterns[round],64) || memcmp(b,patterns[(round+1)%8],64)) return 1;
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86WordMultiplyAddCompleteSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, legacy := range []bool{true, false} {
		widths := []int{16}
		if !legacy {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, memory := range []bool{false, true} {
				for mode := 0; mode < 3; mode++ {
					if legacy && mode != 0 {
						continue
					}
					for destination := 0; destination < 3; destination++ {
						if legacy && destination != 0 {
							continue
						}
						name := fmt.Sprintf("wordmadd%d", count)
						count++
						first := bank + "1"
						if memory {
							first = "(BX)"
						}
						row := "PMADDWL " + first + ",X0"
						if !legacy {
							opcode := "VPMADDWD"
							if mode == 2 {
								opcode += ".Z"
							}
							row = opcode + " " + first + "," + bank + "0"
							if mode != 0 {
								row += ",K1"
							}
							row += fmt.Sprintf(",%s%d", bank, destination)
						}
						fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (CX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z2\nKMOVQ DX,K1\nCMPQ AX,AX\nSTC\n%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", name, row, destination)
						sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
						}}}
						fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
						shift := 1
						if legacy && memory {
							shift = 16
						}
						fmt.Fprintf(&checks, "if(checkMadd(%s,\"%s\",%d,%d,%d,%d,%d)) return 1;\n", name, name, width, mode, x86FloatAddSubBoolInt(legacy), destination, shift)
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
	main := "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n" + declarations.String() + x86WordMaddIndependentRuntimeOracle + `
int main(void) {
 uint32_t state=0x12345678;
 for(int p=0;p<8;++p) for(int i=0;i<64;++i) {state=state*1664525+1013904223; patterns[p][i]=(uint8_t)(state>>24);}
 // Explicit signed extrema and the unique overflowing pair, not merely random data.
 memset(patterns[0],0,64); memset(patterns[1],0,64);
 for(int i=1;i<64;i+=2) {patterns[0][i]=0x80;patterns[1][i]=0x80;}
 memset(patterns[2],0xff,64);
 for(int i=0;i<64;i+=2) {patterns[3][i]=0xff;patterns[3][i+1]=0x7f;}
` + checks.String() + "return 0;\n}\n"
	for _, opt := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", opt), func(t *testing.T) {
			text := ir
			if opt {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "word-madd", triple, text, main, prefix)
		})
	}
	t.Logf("%d opcode/width/memory/mask/alias programs × 32 signed-pair/MXCSR/flags/canary cases at O0 and O2; translated wide-vector execution is not native AVX512 evidence", count)
}

func x86WordMaddLogicalFPAssembly(name string, width, mode int) string {
	bank := map[int]string{8: "M", 16: "X", 32: "Y", 64: "Z"}[width]
	row := "PMADDWL source+0(FP),M1"
	load, store := "MOVQ (AX),M1", "MOVQ M1,(AX)\nEMMS"
	if width != 8 {
		row = "VPMADDWD source+0(FP)," + bank + "1"
		if mode == 2 {
			row = strings.Replace(row, "VPMADDWD ", "VPMADDWD.Z ", 1)
		}
		if mode != 0 {
			row += ",K1"
		}
		row += "," + bank + "1"
		load = "VMOVUPS (AX),Z1"
		store = "VMOVUPS " + bank + "1,(AX)"
	}
	return fmt.Sprintf("TEXT %s(SB),4,$0-80\nMOVQ out+64(FP),AX\nMOVQ mask+72(FP),DX\nKMOVQ DX,K1\n%s\n%s\n%s\nRET\n", name, load, row, store)
}

func TestCrossLinuxRuntimeMatrixX86WordMultiplyAddLogicalFPFields(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var definitions, wrappers, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	index := 0
	for _, width := range []int{8, 16, 32, 64} {
		for mode := 0; mode < 3; mode++ {
			if width == 8 && mode != 0 {
				continue
			}
			name := fmt.Sprintf("wordmaddfp%d", index)
			index++
			declaration := fmt.Sprintf("func %s(source [64]byte,out *byte,mask uint64)\n", name)
			pkg := mustGoPackage(t, "oracle", "package oracle\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			sigs[name] = sig
			definitions.WriteString(x86WordMaddLogicalFPAssembly(name, width, mode))
			fmt.Fprintf(&wrappers, "define void @check_%s(ptr %%input,ptr %%output,i64 %%mask){\n", name)
			packed := "poison"
			for i := 0; i < 64; i++ {
				fmt.Fprintf(&wrappers, " %%address%d=getelementptr i8,ptr %%input,i64 %d\n %%byte%d=load i8,ptr %%address%d,align 1\n %%pack%d=insertvalue [64 x i8] %s,i8 %%byte%d,%d\n", i, i, i, i, i, packed, i, i)
				packed = fmt.Sprintf("%%pack%d", i)
			}
			fmt.Fprintf(&wrappers, " call void @%s([64 x i8] %s,ptr %%output,i64 %%mask)\n ret void\n}\n", name, packed)
			fmt.Fprintf(&declarations, "extern void check_%s(const uint8_t*,uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&checks, `
 for(int round=0;round<16;++round) for(unsigned m=0;m<4;++m) {
  uint8_t input[66],output[66];memset(input,0xa7,66);memset(output,0xc3,66);
  for(int i=0;i<64;++i) input[i+1]=(uint8_t)(i*17+round*31);
  for(int i=0;i<64;i+=2) {output[i+1]=1;output[i+2]=0;}
  check_%[1]s(input+1,output+1,masks[m]);
  for(int i=0;i<64;i+=4) {
   int32_t pair=word(input+i+1)+word(input+i+3);
   int active=%[2]d==0 || ((masks[m]>>(i/4))&1);
   uint32_t want=i<%[3]d ? (active ? (uint32_t)pair : (%[2]d==2 ? 0 : UINT32_C(0x00010001))) : UINT32_C(0x00010001);
   for(int j=0;j<4;++j) if(output[i+j+1]!=(uint8_t)(want>>(8*j))) return 1;
  }
  if(input[0]!=0xa7 || input[65]!=0xa7 || output[0]!=0xc3 || output[65]!=0xc3) return 1;
  for(int i=0;i<64;++i) if(input[i+1]!=(uint8_t)(i*17+round*31)) return 1;
 }
`, name, mode, width)
		}
	}
	requireX86GoAssemblerResult(t, "amd64", definitions.String(), true)
	file, err := Parse(ArchAMD64, definitions.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + x86WordMaddIndependentRuntimeOracle + "int main(void){\n" + checks.String() + "return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir + wrappers.String()
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "word-madd-logical-fp", triple, text, main, prefix)
		})
	}
	t.Logf("%d logical FP programs × 64 independent signed-pair cases; signatures derived from actual Go [64]byte declarations; explicit LLVM array carrier is not native stack/alignment or MMX tag proof", index)
}
