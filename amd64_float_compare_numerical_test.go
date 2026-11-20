package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86FloatCompareOracleCase struct {
	row                           string
	bits, width, predicate        int
	scalar, legacy, maskResult    bool
	memory, broadcast, suppressed bool
	destination                   int
}

// Enumerate this matrix from explicit architectural axes, not the production
// grammar, predicate table, memory-shape classifier or caller effect registry.
func x86FloatCompareOracleCases(opcode string) []x86FloatCompareOracleCase {
	bits := 32
	if strings.HasSuffix(opcode, "PD") || strings.HasSuffix(opcode, "SD") {
		bits = 64
	}
	scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
	legacy := !strings.HasPrefix(opcode, "V")
	predicates := 32
	if legacy {
		predicates = 8
	}
	var cases []x86FloatCompareOracleCase
	for predicate := 0; predicate < predicates; predicate++ {
		for variant := 0; variant < 2; variant++ {
			width := 16
			if !legacy && !scalar && predicate%2 != 0 {
				width = 32
			}
			bank := map[int]string{16: "X", 32: "Y"}[width]
			first, destination := bank+"1", predicate%3
			if variant == 1 {
				first = "(CX)"
			}
			row := fmt.Sprintf("%s $%d,%s,%s0,%s%d", opcode, predicate, first, bank, bank, destination)
			if legacy {
				destination = 0
				row = fmt.Sprintf("%s %s,X0,$%d", opcode, first, predicate)
			}
			cases = append(cases, x86FloatCompareOracleCase{row: row, bits: bits, width: width,
				predicate: predicate, scalar: scalar, legacy: legacy, memory: variant == 1, destination: destination})
		}
		if legacy {
			continue
		}
		for variant := 0; variant < 4; variant++ {
			width := []int{16, 32, 64}[predicate%3]
			if scalar {
				width = 16
			}
			if variant == 3 && !scalar {
				width = 64 // Go only permits packed SAE at Z width.
			}
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			first, operation := bank+"1", opcode
			memory, broadcast := variant == 1 || variant == 2, variant == 2 && !scalar
			if memory {
				first = "(CX)"
			}
			if broadcast {
				operation += ".BCST"
			}
			if variant == 3 {
				operation += ".SAE"
			}
			row := fmt.Sprintf("%s $%d,%s,%s0,K1,K2", operation, predicate, first, bank)
			cases = append(cases, x86FloatCompareOracleCase{row: row, bits: bits, width: width,
				predicate: predicate, scalar: scalar, maskResult: true, memory: memory,
				broadcast: broadcast, suppressed: variant == 3})
		}
	}
	return cases
}

func x86FloatCompareOracleAssembly(cases []x86FloatCompareOracleCase, dead bool) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for index, c := range cases {
		name := fmt.Sprintf("compare%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nVMOVUPS (BX),Z0\nVMOVUPS (BX),Z2\n", name)
		if !c.memory {
			source.WriteString("VMOVUPS (CX),Z1\n")
		}
		source.WriteString("KMOVQ DX,K1\nKMOVQ DX,K2\nSTC\n" + c.row + "\n")
		if !dead {
			if c.maskResult {
				source.WriteString("KMOVQ K2,8(AX)\n")
			} else {
				fmt.Fprintf(&source, "VMOVUPS Z%d,8(AX)\n", c.destination)
			}
		}
		source.WriteString("SETCS 72(AX)\nRET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
	}
	return source.String(), sigs
}

func x86FloatCompareOracleMain(cases []x86FloatCompareOracleCase, dead bool) string {
	var declarations, descriptors strings.Builder
	for index, c := range cases {
		fmt.Fprintf(&declarations, "extern void compare%d(void*,const void*,const void*,uint64_t);\n", index)
		fmt.Fprintf(&descriptors, "{compare%d,%d,%d,%d,%d,%d,%d,%d,%d,%d},\n", index, c.bits, c.width, c.predicate,
			x86FloatAddSubBoolInt(c.scalar), x86FloatAddSubBoolInt(c.legacy), x86FloatAddSubBoolInt(c.maskResult),
			x86FloatAddSubBoolInt(c.memory), x86FloatAddSubBoolInt(c.broadcast), x86FloatAddSubBoolInt(c.suppressed))
	}
	return x86FloatCompareIndependentC + declarations.String() + `
typedef void (*compare_fn)(void*,const void*,const void*,uint64_t);
struct comparison {compare_fn call;unsigned bits,width,predicate,scalar,legacy,mask_result,memory,broadcast,sae;};
static const struct comparison comparisons[]={
` + descriptors.String() + fmt.Sprintf(`
};
int main(void){
 const uint64_t masks[]={0,1,UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_MAX};
 unsigned saved;__asm__ volatile("stmxcsr %%0":"=m"(saved));
 for(unsigned index=0;index<sizeof(comparisons)/sizeof(comparisons[0]);index++){
  const struct comparison *c=comparisons+index;unsigned bytes=c->bits/8;
  const uint64_t *edges=c->bits==32?edges32:edges64;
  for(unsigned pair=0;pair<18;pair++) for(unsigned m=0;m<4;m++) for(unsigned control=0;control<6;control++){
   _Alignas(64) uint8_t aStorage[192],bStorage[192];
   uint8_t *a=aStorage+64,*b=bStorage+64,out[81],want[64];
   memset(aStorage,0xa7,sizeof(aStorage));memset(bStorage,0xb9,sizeof(bStorage));memset(out,0xc3,sizeof(out));
   for(unsigned lane=0;lane<64/bytes;lane++){
    uint64_t av=edges[(pair+lane)%%18],bv=edges[(pair*7+lane*3+1)%%18];
    // Extended predicates have no actual AVX512 execution oracle here. Keep
    // denormal and NaN coverage, but do not mix them in a single extended
    // comparison: the diagnostic SSE class representative is not a proof of
    // that exception-priority corner (the original legacy matrix retains it).
    if(c->predicate>=8 && ((is_denormal(c->bits,av)&&is_nan(c->bits,bv)) ||
       (is_nan(c->bits,av)&&is_denormal(c->bits,bv)))) {
     if(is_denormal(c->bits,av))av=0;
     if(is_denormal(c->bits,bv))bv=0;
    }
    memcpy(a+lane*bytes,&av,bytes);memcpy(b+lane*bytes,&bv,bytes);
   }
   uint8_t beforeA[192],beforeB[192];memcpy(beforeA,aStorage,192);memcpy(beforeB,bStorage,192);
   unsigned csr=controls[control],after,expectedCSR=csr;uint64_t expectedMask=0;
   memset(want,0,64);
   if(c->legacy)memcpy(want,a,64);else if(c->scalar)memcpy(want,a,16);
   unsigned lanes=c->scalar?1:c->width/bytes;
   for(unsigned lane=0;lane<lanes;lane++){
    int active=!c->mask_result || ((masks[m]>>lane)&1);
    if(!active)continue;
    uint64_t av=read_bits(a+lane*bytes,bytes),bv=read_bits(b+(c->broadcast?0:lane*bytes),bytes);
    int truth=independent_compare(c->bits,av,bv,c->predicate,csr);
    if(truth)expectedMask|=UINT64_C(1)<<lane;
    memset(want+lane*bytes,truth?255:0,bytes);
    if(!c->sae)expectedCSR|=original_effect(c->bits,av,bv,c->predicate,csr)&63;
   }
   __asm__ volatile("ldmxcsr %%0"::"m"(csr));
   const uint8_t *input=c->mask_result&&c->memory&&m==0?0:b;
   c->call(out,a,input,masks[m]);
   __asm__ volatile("stmxcsr %%0":"=m"(after));
   __asm__ volatile("ldmxcsr %%0"::"m"(saved));
   if(after!=expectedCSR){fprintf(stderr,"compare%%u pred=%%u mxcsr=%%x want=%%x mask=%%llx\n",index,c->predicate,after,expectedCSR,(unsigned long long)masks[m]);return 10;}
   if(out[72]!=1||memcmp(aStorage,beforeA,192)||memcmp(bStorage,beforeB,192))return 11;
   for(unsigned byte=0;byte<81;byte++){
    uint8_t expected=0xc3;
    if(byte==72)expected=1;
    if(!%d&&byte>=8&&byte<72){
     if(c->mask_result){if(byte<16)expected=(uint8_t)(expectedMask>>(8*(byte-8)));}
     else expected=want[byte-8];
    }
    if(out[byte]!=expected){fprintf(stderr,"compare%%u pred=%%u byte=%%u got=%%x want=%%x\n",index,c->predicate,byte,out[byte],expected);return 12;}
   }
  }
 }
 __asm__ volatile("ldmxcsr %%0"::"m"(saved));return 0;
}
`, x86FloatAddSubBoolInt(dead))
}

// Keep optimized-away results separate: a compare still has MXCSR/trap and
// memory effects. Both optimization levels execute the same independent C.
func x86FloatCompareRunOptimization(t *testing.T, execution x86FloatCompareExecution, ir, main, level string) {
	t.Helper()
	execution.compileAndRunLLVM(t, "compare-effects", ir, main, level)
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSR(t *testing.T) {
	x86FloatCompareIndependentRuntime(t, x86FloatCompareSSE)
}

func x86FloatCompareIndependentRuntime(t *testing.T, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, axis)
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		cases := x86FloatCompareRuntimeCases(opcode, axis)
		if len(cases) == 0 {
			continue
		}
		t.Run(opcode, func(t *testing.T) {
			assembly, sigs := x86FloatCompareOracleAssembly(cases, false)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			main := x86FloatCompareOracleMain(cases, false)
			execution.compileAndRunLLVM(t, "compare-ieee", ir, main, "-O2")
			t.Logf("%s ISA-axis=%d: %d independently enumerated programs ×432 IEEE/DAZ/full-MXCSR/mask/upper-alias/canary inputs; extended NaN+denormal priority is not covered; actual transport=%v", opcode, axis, len(cases), execution.prefix)
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffects(t *testing.T) {
	x86FloatCompareDeadResultRuntime(t, x86FloatCompareSSE)
}

func x86FloatCompareDeadPredicate(predicate int) bool {
	return predicate == 0 || predicate == 1 || predicate == 11 || predicate == 15 || predicate == 27 || predicate == 31
}

func x86FloatCompareDeadResultRuntime(t *testing.T, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, axis)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			var cases []x86FloatCompareOracleCase
			for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
				for _, c := range x86FloatCompareRuntimeCases(opcode, axis) {
					if x86FloatCompareDeadPredicate(c.predicate) {
						cases = append(cases, c)
					}
				}
			}
			assembly, sigs := x86FloatCompareOracleAssembly(cases, true)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			x86FloatCompareRunOptimization(t, execution, ir, x86FloatCompareOracleMain(cases, true), level)
			t.Logf("dead-result ISA-axis=%d: %d complete programs ×432 inputs, %s, actual transport=%v", axis, len(cases), level, execution.prefix)
		})
	}
}
