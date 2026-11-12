package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This list follows Go's four yxm and four _yvaddsubpd opcode rows. It is
// deliberately independent of the production parser and emitter.
func x86HorizontalFloatFormats() []string {
	var rows []string
	for _, op := range []string{"HADDPS", "HADDPD", "HSUBPS", "HSUBPD"} {
		rows = append(rows, op+" X0,X1", op+" (BX),X1")
	}
	for _, op := range []string{"VHADDPS", "VHADDPD", "VHSUBPS", "VHSUBPD"} {
		for _, bank := range []string{"X", "Y"} {
			rows = append(rows, fmt.Sprintf("%s %s0,%s1,%s2", op, bank, bank, bank), fmt.Sprintf("%s (BX),%s1,%s2", op, bank, bank))
		}
	}
	return rows
}

func x86HorizontalFloatSemanticsFormats() []string {
	rows := x86HorizontalFloatFormats()
	for _, row := range x86HorizontalFloatFormats() {
		if !strings.HasPrefix(row, "V") || strings.Contains(row, "(BX)") {
			continue
		}
		for _, destination := range []string{"0", "1"} {
			rows = append(rows, strings.TrimSuffix(row, "2")+destination)
		}
	}
	return rows
}

// A real SSE3 horizontal instruction supplies the entire 128-bit result,
// not a scalar ADD/SUB reconstruction. VEX Y results concatenate two such
// independent blocks. MXCSR is observed before restoring the caller state.
const x86HorizontalFloatSSEOracle = `#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint64_t vector128 __attribute__((vector_size(16)));
static unsigned last_horizontal_csr;
static void horizontal_result(void *out,const void *second,const void *first,unsigned bits,int sub,unsigned csr) {
 unsigned saved;vector128 a,b;memcpy(&a,second,16);memcpy(&b,first,16);
 __asm__ volatile("stmxcsr %0":"=m"(saved));__asm__ volatile("ldmxcsr %0"::"m"(csr));
 if(bits==32) {
  if(sub)__asm__ volatile("hsubps %1,%0":"+x"(a):"x"(b));
  else __asm__ volatile("haddps %1,%0":"+x"(a):"x"(b));
 } else {
  if(sub)__asm__ volatile("hsubpd %1,%0":"+x"(a):"x"(b));
  else __asm__ volatile("haddpd %1,%0":"+x"(a):"x"(b));
 }
 memcpy(out,&a,16);__asm__ volatile("stmxcsr %0":"=m"(last_horizontal_csr));
 __asm__ volatile("ldmxcsr %0"::"m"(saved));
}
`

func TestCrossLinuxRuntimeMatrixX86HorizontalFloatCompletePhysicalSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range x86HorizontalFloatSemanticsFormats() {
		op := strings.Fields(row)[0]
		bits, width, dest, legacy := 32, 16, 2, !strings.HasPrefix(op, "V")
		if strings.HasSuffix(op, "PD") {
			bits = 64
		}
		if strings.Contains(row, "Y") {
			width = 32
		}
		if legacy {
			dest = 1
		} else {
			dest = int(row[len(row)-1] - '0')
		}
		name := fmt.Sprintf("horizontal%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nSTC\n%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nRET\n", name, row, dest)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(void*,const void*,const void*);\n", name)
		fmt.Fprintf(&checks, `
 for(unsigned vector=0;vector<20;vector++)for(unsigned mode=0;mode<4;mode++)for(unsigned control=0;control<6;control++) {
  _Alignas(16) uint8_t aStorage[96],bStorage[96];uint8_t out[67],expected[64],beforeA[64],beforeB[64];
  unsigned offset=%[7]d?17:16;uint8_t *a=aStorage+offset,*b=bStorage+offset;memset(aStorage,0xa7,96);memset(bStorage,0xb9,96);memset(out,0xc3,67);
  for(unsigned lane=0;lane<64/%[2]d;lane++) {
   uint64_t av=edges%[3]d[(vector+lane)%%20],bv=edges%[3]d[(vector*3+lane*7)%%20];
   memcpy(a+lane*%[2]d,&av,%[2]d);memcpy(b+lane*%[2]d,&bv,%[2]d);
  }
  memcpy(beforeA,a,64);memcpy(beforeB,b,64);
  unsigned csr=controls[control]|(mode<<13),observed,flags=0;
  __asm__ volatile("ldmxcsr %%0"::"m"(csr));%[1]s(out+1,a,b);
  __asm__ volatile("stmxcsr %%0":"=m"(observed));
  if(%[4]d)memcpy(expected,beforeB,64);else memset(expected,0,64);
  for(unsigned block=0;block<%[5]d;block+=16) {
   horizontal_result(expected+block,beforeB+block,beforeA+block,%[3]d,%[6]d,csr);flags|=last_horizontal_csr&63;
  }
  for(unsigned byte=0;byte<64;byte++)if(out[1+byte]!=expected[byte]) {
   fprintf(stderr,"%[1]s vector/mode/csr=%%u/%%u/%%x byte=%%u got=%%x want=%%x\n",vector,mode,csr,byte,out[1+byte],expected[byte]);return 1;
  }
  if(observed!=(csr|flags)){fprintf(stderr,"%[1]s MXCSR=%%x want=%%x\n",observed,csr|flags);return 2;}
  if(out[0]!=0xc3 || out[65]!=1 || out[66]!=0xc3)return 3;
  if(memcmp(a,beforeA,64) || memcmp(b,beforeB,64))return 5;
  for(unsigned byte=0;byte<offset;byte++)if(aStorage[byte]!=0xa7 || bStorage[byte]!=0xb9)return 4;
  for(unsigned byte=offset+64;byte<96;byte++)if(aStorage[byte]!=0xa7 || bStorage[byte]!=0xb9)return 4;
 }
`, name, bits/8, bits, x86FloatAddSubBoolInt(legacy), width, x86FloatAddSubBoolInt(strings.Contains(op, "SUB")), x86FloatAddSubBoolInt(!legacy && strings.Contains(row, "(BX)")))
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
	main := x86HorizontalFloatSSEOracle + declarations.String() + `int main(void) {
 const uint64_t edges32[]={0,0x80000000,1,0x80000001,0x7fffff,0x800000,0x7f7fffff,0xff7fffff,
  0x3f800000,0xbf800000,0x3f800001,0x33800000,0x7f800000,0xff800000,
  0x7fc12345,0xffc45678,0x7f812345,0xff845678,0x40000000,0xc0400000};
 const uint64_t edges64[]={0,UINT64_C(0x8000000000000000),1,UINT64_C(0x8000000000000001),
  UINT64_C(0xfffffffffffff),UINT64_C(0x10000000000000),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),
  UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x3ff0000000000001),UINT64_C(0x3ca0000000000000),
  UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8123456789abc),UINT64_C(0xfff8fedcba987654),
  UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff0fedcba987654),UINT64_C(0x4000000000000000),UINT64_C(0xc008000000000000)};
 const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};
` + checks.String() + "unsigned csr=0x1f80;__asm__ volatile(\"ldmxcsr %0\"::\"m\"(csr));return 0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "horizontal-complete-semantics", triple, ir, main, prefix)
	t.Log("24 real Go formats +16 source/destination aliases x480 IEEE/MXCSR/physical-alias/canary inputs")
}
