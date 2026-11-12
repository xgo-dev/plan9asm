package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Only legacy SSE is executed as native instruction evidence. VEX/EVEX
// numerical expectations come from independent scalar lane arithmetic.
const x86PackedSubtractIndependentOracle = `
static const uint64_t subtractMasks[] = {
 0, 1, UINT64_C(0x55aa55aa55aa55aa), UINT64_MAX
};

static uint64_t subtractLane(const uint8_t *p, int bytes) {
 uint64_t value = 0;
 for (int j = 0; j < bytes; ++j) {
  value |= (uint64_t)p[j] << (8*j);
 }
 return value;
}

static uint64_t subtractValue(uint64_t a, uint64_t b, int bytes, int mode) {
 if (mode == 0) {
  return b-a;
 }
 if (mode == 2) {
  return b < a ? 0 : b-a;
 }
 int bits = bytes*8;
 int64_t sign = INT64_C(1) << (bits-1);
 int64_t left = (a & sign) ? (int64_t)a - (sign*2) : (int64_t)a;
 int64_t right = (b & sign) ? (int64_t)b - (sign*2) : (int64_t)b;
 int64_t result = right-left;
 if (result < -sign) {
  result = -sign;
 }
 if (result > sign-1) {
  result = sign-1;
 }
 return (uint64_t)result;
}

__attribute__((noinline)) static int checkSubtract(
 void (*fn)(uint8_t*, const uint8_t*, const uint8_t*, uint64_t),
 const char *name, int width, int bytes, int arithmetic,
 int maskMode, int legacy, int memory, int broadcast) {
 for (int round = 0; round < 12; ++round) {
  for (int m = 0; m < 4; ++m) {
   _Alignas(64) uint8_t aStorage[96], bStorage[96], output[68];
   int shift = legacy && memory ? 16 : 1;
   uint8_t *a = aStorage+shift;
   uint8_t *b = bStorage+3;
   memset(aStorage, 0xa7, sizeof(aStorage));
   memset(bStorage, 0xb9, sizeof(bStorage));
   memset(output, 0xc3, sizeof(output));
   for (int i = 0; i < 64; ++i) {
    a[i] = (uint8_t)(i*17+round*31);
    b[i] = (uint8_t)(i*23+round*53);
   }
   if (round < 4) {
    memset(a, round == 0 ? 0xff : round == 1 ? 0x80 : round == 2 ? 1 : 0, 64);
    memset(b, round == 0 ? 1 : round == 1 ? 0x7f : round == 2 ? 0 : 0xff, 64);
   }
   uint64_t mask = subtractMasks[m];
   uint32_t saved, before = 0x1f80 | ((round%4)<<13) | round, after;
   __asm__ volatile("stmxcsr %0" : "=m"(saved));
   __asm__ volatile("ldmxcsr %0" : : "m"(before));
   fn(output+1, a, b, mask);
   __asm__ volatile("stmxcsr %0" : "=m"(after));
   __asm__ volatile("ldmxcsr %0" : : "m"(saved));
   if (after != before || output[0] != 0xc3 || output[67] != 0xc3 ||
       output[65] != 1 || output[66] != 0) {
    fprintf(stderr, "%s changed MXCSR, flags or output canaries\n", name);
    return 1;
   }
   for (int i = 0; i < 64; i += bytes) {
    uint64_t result = subtractValue(subtractLane(a+(broadcast ? 0 : i), bytes),
                                    subtractLane(b+i, bytes), bytes, arithmetic);
    int active = maskMode == 0 || ((mask >> (i/bytes)) & 1);
    for (int j = 0; j < bytes; ++j) {
     uint8_t want = i < width ?
       (active ? (uint8_t)(result >> (8*j)) : maskMode == 2 ? 0 : b[i+j]) :
       legacy ? b[i+j] : 0;
     if (output[i+j+1] != want) {
      fprintf(stderr, "%s round=%d mask=%llx byte=%d got=%x want=%x\n",
              name, round, (unsigned long long)mask, i+j, output[i+j+1], want);
      return 1;
     }
    }
   }
   for (int i = 0; i < 96; ++i) {
    if ((i < shift || i >= shift+64) && aStorage[i] != 0xa7) {
     return 1;
    }
    if ((i < 3 || i >= 67) && bStorage[i] != 0xb9) {
     return 1;
    }
   }
  }
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86PackedSubtractCompleteSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	rows := x86PackedSubtractCallerRows()
	for index, row := range rows {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		instruction := file.Funcs[0].Instrs[1]
		form, _, err := x86PackedSubtractProperties(instruction, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		mode := 0
		if form.mask >= 0 {
			mode = 1
			if form.zeroing {
				mode = 2
			}
		}
		name := fmt.Sprintf("packedsubtract%d", index)
		row = strings.ReplaceAll(row, "(DI)", "(BX)")
		register, valid := amd64VectorRegisterIndex(instruction.Args[form.destination].Reg, form.byteWidth)
		if !valid {
			t.Fatal("missing actual vector destination")
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n"+
			"MOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\n"+
			"VMOVUPS (BX),Z0\nVMOVUPS (BX),Z20\n"+
			"VMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nVMOVUPS (CX),Z15\n"+
			"VMOVUPS (CX),Z21\nVMOVUPS (CX),Z22\nKMOVQ DX,K1\n"+
			"CMPQ AX,AX\nSTC\n%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n",
			name, row, register)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
		fmt.Fprintf(&checks, "if(checkSubtract(%s,\"%s\",%d,%d,%d,%d,%d,%d,%d)) return 1;\n",
			name, name, form.byteWidth, form.laneBits/8, form.mode, mode,
			x86FloatAddSubBoolInt(form.legacy), x86FloatAddSubBoolInt(form.memory >= 0),
			x86FloatAddSubBoolInt(form.broadcast))
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
	main := "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n" +
		declarations.String() + x86PackedSubtractIndependentOracle +
		"int main(void){\n" + checks.String() + "return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-subtract-complete", triple, text, main, prefix)
		})
	}
	t.Logf("%d programs × 48 independent wrapping/saturating/mask/upper-view/flags/MXCSR/canary cases at O0/O2; not native AVX512 execution", len(rows))
}
