package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

const x86PackedAddIndependentOracle = `
static const uint64_t masks[]={0,1,UINT64_C(0x55aa55aa55aa55aa),UINT64_MAX};
static uint64_t lane(const uint8_t *p,int bytes) {
 uint64_t v=0;for(int j=0;j<bytes;++j) v|=(uint64_t)p[j]<<(8*j);return v;
}
__attribute__((noinline)) static int checkAdd(
 void (*fn)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t),
 const char *name,int width,int bytes,int mode,int legacy,int destination,int memory,int broadcast) {
 for(int round=0;round<12;++round) for(int m=0;m<4;++m) {
  _Alignas(64) uint8_t aStorage[96],bStorage[96],output[68];
  int shift=legacy&&memory ? 16 : 1;
  uint8_t *a=aStorage+shift,*b=bStorage+3;
  memset(aStorage,0xa7,96);memset(bStorage,0xb9,96);memset(output,0xc3,68);
  for(int i=0;i<64;++i) {a[i]=(uint8_t)(i*17+round*31);b[i]=(uint8_t)(i*23+round*53);}
  if(round<3) {memset(a,round==0?0xff:round==1?0x80:0,64);memset(b,round==0?1:round==1?0x80:0xff,64);}
  uint64_t mask=masks[m];uint32_t saved,before=0x1f80|((round%4)<<13)|round,after;
  __asm__ volatile("stmxcsr %0" : "=m"(saved));__asm__ volatile("ldmxcsr %0" : : "m"(before));
  fn(output+1,a,b,mask);
  __asm__ volatile("stmxcsr %0" : "=m"(after));__asm__ volatile("ldmxcsr %0" : : "m"(saved));
  if(after!=before || output[0]!=0xc3 || output[67]!=0xc3 || output[65]!=1 || output[66]!=0) return 1;
  for(int i=0;i<64;i+=bytes) {
   uint64_t sum=lane(a+(broadcast?0:i),bytes)+lane(b+i,bytes);
   const uint8_t *old=destination==1 ? a : b;
   int active=mode==0 || ((mask>>(i/bytes))&1);
   for(int j=0;j<bytes;++j) {
    uint8_t want=i<width ? (active ? (uint8_t)(sum>>(j*8)) : mode==2 ? 0 : old[i+j]) : legacy ? b[i+j] : 0;
    if(output[i+j+1]!=want) {fprintf(stderr,"%s round=%d mask=%llx byte=%d got=%x want=%x\n",name,round,(unsigned long long)mask,i+j,output[i+j+1],want);return 1;}
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

func x86PackedAddMMXAssembly(name, opcode, input string) string {
	return fmt.Sprintf("TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (CX),Z0\nVMOVUPS Z0,(AX)\nCMPQ AX,AX\nSTC\nMOVQ (CX),M0\nMOVQ (BX),M1\n%s %s,M0\nMOVQ M0,(AX)\nEMMS\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", name, opcode, input)
}

func TestCrossLinuxRuntimeMatrixX86PackedWrappingAddCompleteSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for index, opcode := range x86WrappingAddOpcodes {
		bits := 8 << uint(index%4)
		legacy := !strings.HasPrefix(opcode, "V")
		widths := []int{16}
		if !legacy {
			widths = []int{16, 32, 64}
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, kind := range []string{"register", "memory", "broadcast"} {
				if kind == "broadcast" && (legacy || bits < 32) {
					continue
				}
				for mode := 0; mode < 3; mode++ {
					if legacy && mode != 0 {
						continue
					}
					destination := mode
					if legacy {
						destination = 0
					}
					name := fmt.Sprintf("packedadd%d", count)
					count++
					first := bank + "1"
					if kind != "register" {
						first = "(BX)"
					}
					row := opcode + " " + first + ",X0"
					if !legacy {
						suffix := ""
						if kind == "broadcast" {
							suffix = ".BCST"
						}
						if mode == 2 {
							suffix += ".Z"
						}
						row = opcode + suffix + " " + first + "," + bank + "0"
						if mode != 0 {
							row += ",K1"
						}
						row += fmt.Sprintf(",%s%d", bank, destination)
					}
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (CX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z2\nKMOVQ DX,K1\nCMPQ AX,AX\nSTC\n%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", name, row, destination)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
					}}}
					fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
					fmt.Fprintf(&checks, "if(checkAdd(%s,\"%s\",%d,%d,%d,%d,%d,%d,%d)) return 1;\n", name, name, width, bits/8, mode, x86FloatAddSubBoolInt(legacy), destination, x86FloatAddSubBoolInt(kind != "register"), x86FloatAddSubBoolInt(kind == "broadcast"))
				}
			}
		}
	}
	for index, opcode := range []string{"PADDB", "PADDW", "PADDL"} {
		for _, memory := range []bool{false, true} {
			name := fmt.Sprintf("packedadd%d", count)
			count++
			first := "M1"
			if memory {
				first = "(BX)"
			}
			source.WriteString(x86PackedAddMMXAssembly(name, opcode, first))
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&checks, "if(checkAdd(%s,\"%s\",8,%d,0,1,0,%d,0))return 1;\n", name, name, 1<<uint(index), x86FloatAddSubBoolInt(memory))
		}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n" + declarations.String() + x86PackedAddIndependentOracle + "int main(void){\n" + checks.String() + "return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "wrapping-add", triple, text, main, prefix)
		})
	}
	t.Logf("%d complete opcode/width/memory/broadcast/mask/alias programs × 48 independent wrap/CSR/flags/canary cases at O0/O2; not native AVX512 execution", count)
}

func TestCrossLinuxRuntimeMatrixX86PackedWrappingAddLogicalFPFields(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var definitions, wrappers, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for index, opcode := range []string{"VPADDB", "VPADDW", "VPADDD", "VPADDQ"} {
		bits := 8 << uint(index)
		for _, broadcast := range []bool{false, true} {
			if broadcast && bits < 32 {
				continue
			}
			for _, width := range []int{16, 32, 64} {
				for mode := 0; mode < 3; mode++ {
					name := fmt.Sprintf("packedaddfp%d", count)
					count++
					pkg := mustGoPackage(t, "oracle", fmt.Sprintf("package oracle\nfunc %s(source [64]byte,out *byte,mask uint64)\n", name))
					sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
					if err != nil {
						t.Fatal(err)
					}
					sigs[name] = sig
					bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
					row := opcode
					if broadcast {
						row += ".BCST"
					}
					if mode == 2 {
						row += ".Z"
					}
					row += " source+0(FP)," + bank + "1"
					if mode != 0 {
						row += ",K1"
					}
					row += "," + bank + "1"
					fmt.Fprintf(&definitions, "TEXT %s(SB),4,$0-80\nMOVQ out+64(FP),AX\nMOVQ mask+72(FP),DX\nKMOVQ DX,K1\nVMOVUPS (AX),Z1\n%s\nVMOVUPS %s1,(AX)\nRET\n", name, row, bank)
					fmt.Fprintf(&wrappers, "define void @check_%s(ptr %%input,ptr %%output,i64 %%mask){\n", name)
					packed := "poison"
					for i := 0; i < 64; i++ {
						fmt.Fprintf(&wrappers, " %%address%d=getelementptr i8,ptr %%input,i64 %d\n %%byte%d=load i8,ptr %%address%d,align 1\n %%pack%d=insertvalue [64 x i8] %s,i8 %%byte%d,%d\n", i, i, i, i, i, packed, i, i)
						packed = fmt.Sprintf("%%pack%d", i)
					}
					fmt.Fprintf(&wrappers, " call void @%s([64 x i8] %s,ptr %%output,i64 %%mask)\n ret void\n}\n", name, packed)
					fmt.Fprintf(&declarations, "extern void check_%s(const uint8_t*,uint8_t*,uint64_t);\n", name)
					fmt.Fprintf(&checks, `
 for(int round=0;round<16;++round) for(int m=0;m<4;++m) {
  uint8_t input[66],output[66],before[64];memset(input,0xa7,66);memset(output,0xc3,66);
  for(int i=0;i<64;++i) {input[i+1]=(uint8_t)(i*17+round*31);before[i]=(uint8_t)(i*23+round*41);output[i+1]=before[i];}
  check_%[1]s(input+1,output+1,masks[m]);
  for(int i=0;i<%[2]d;i+=%[3]d) {
   uint64_t sum=lane(input+1+(%[4]d?0:i),%[3]d)+lane(before+i,%[3]d);
   int active=%[5]d==0 || ((masks[m]>>(i/%[3]d))&1);
   for(int j=0;j<%[3]d;++j) {
    uint8_t want=active?(uint8_t)(sum>>(8*j)):%[5]d==2?0:before[i+j];
    if(output[i+j+1]!=want) {fprintf(stderr,"%[1]s FP byte=%%d got=%%x want=%%x\n",i+j,output[i+j+1],want);return 1;}
   }
  }
  if(input[0]!=0xa7 || input[65]!=0xa7 || output[0]!=0xc3 || output[65]!=0xc3) return 1;
 }
`, name, width, bits/8, x86FloatAddSubBoolInt(broadcast), mode)
				}
			}
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
	ir += wrappers.String()
	main := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + x86PackedAddIndependentOracle + "int main(void){\n" + checks.String() + "return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "wrapping-add-fp", triple, text, main, prefix)
		})
	}
	t.Logf("%d complete independent-byte FP programs × 64 logical-value cases at O0/O2; no native FP backing or alignment claim", count)
}
