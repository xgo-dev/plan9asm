package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedShiftPartialResults(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, native, cases strings.Builder
	for index, row := range x86PackedShiftResultRows() {
		name := fmt.Sprint("partialShift", index)
		fmt.Fprintf(&declarations, "func %s(data,count uint32) uint32\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVL data+0(FP),AX\nMOVL count+4(FP),BX\nMOVL $0,CX\n", name)
		for dword := 0; dword < 4; dword++ {
			if row.data&(15<<uint(dword*4)) != 0 {
				fmt.Fprintf(&source, "PINSRD $%d,AX,X1\n", dword)
			}
			if row.count&(15<<uint(dword*4)) != 0 {
				count := "CX"
				if dword == 0 {
					count = "BX"
				}
				fmt.Fprintf(&source, "PINSRD $%d,%s,X0\n", dword, count)
			}
		}
		result := "X1"
		if strings.HasPrefix(row.row, "V") {
			result = "X2"
		}
		fmt.Fprintf(&source, "%s\nPEXTRD $%d,%s,AX\nMOVL AX,ret+8(FP)\nRET\n", row.row, row.lane, result)
		fmt.Fprintf(&native, "extern uint32_t %s(uint32_t,uint32_t);\n", name)
		original := "0"
		if !strings.HasPrefix(row.row, "V") {
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row.row+"\nRET\n")
			if len(code) < 2 || code[len(code)-1] != 0xc3 {
				t.Fatal("missing original opcode/RET", row.row, code)
			}
			var encoded []string
			for _, value := range code[:len(code)-1] {
				encoded = append(encoded, fmt.Sprintf("0x%02x", value))
			}
			original = fmt.Sprint("originalShift", index)
			assembly := "movdqu (%0), %%xmm0; movdqu (%1), %%xmm1; .byte " + strings.Join(encoded, ",") + "; movdqu %%xmm1, (%2)"
			fmt.Fprintf(&native, "static void %s(const uint8_t *counts,const uint8_t *data,uint8_t *out) {\n    __asm__ volatile(%q::\"r\"(counts),\"r\"(data),\"r\"(out):\"xmm0\",\"xmm1\",\"memory\");\n}\n", original, assembly)
		}
		op := strings.Fields(row.row)[0]
		bits := 32
		if strings.HasSuffix(op, "W") {
			bits = 16
		}
		if strings.HasSuffix(op, "Q") {
			bits = 64
		}
		byteShift := strings.HasSuffix(op, "DQ") || strings.HasSuffix(op, "O")
		if byteShift {
			bits = 128
		}
		immediate := -1
		if fields := strings.Split(strings.Fields(row.row)[1], ","); strings.HasPrefix(fields[0], "$") {
			var err error
			immediate, err = strconv.Atoi(strings.TrimPrefix(fields[0], "$"))
			if err != nil {
				t.Fatal(err)
			}
			immediate = int(uint8(immediate))
			if byteShift {
				immediate *= 8
			}
		}
		fmt.Fprintf(&cases, "{%s,%s,%q,%d,%d,%d,%d,%d,%d,%d},\n", name, original, row.row, bits, immediate,
			x86ShiftBoolean(strings.Contains(op, "SLL")), x86ShiftBoolean(strings.Contains(op, "LLV") || strings.Contains(op, "RLV")), row.data, row.count, row.lane)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal(err)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + native.String() + `
struct Case {
    uint32_t (*translated)(uint32_t,uint32_t);
    void (*original)(const uint8_t*,const uint8_t*,uint8_t*);
    const char *row;
    unsigned bits;
    int immediate,left,perlane;
    uint16_t dataKnown,countKnown;
    unsigned lane;
};
static const struct Case cases[]={
` + cases.String() + `};
static uint64_t read_shift_bytes(const uint8_t *bytes,unsigned width) {
    uint64_t value=0;
    for(unsigned i=0;i<width;i++) value|=(uint64_t)bytes[i]<<(i*8);
    return value;
}
int main(void) {
    const uint32_t inputs[]={0,1,UINT32_MAX,0x80000000,0x01234567,0x89abcdef,0x55555555,0xaaaaaaaa};
    const uint32_t counts[]={0,1,7,8,15,16,31,32,63,64,255,UINT32_MAX};
    for(unsigned c=0;c<sizeof(cases)/sizeof(cases[0]);c++)
    for(unsigned sample=0;sample<sizeof(inputs)/sizeof(inputs[0]);sample++)
    for(unsigned n=0;n<sizeof(counts)/sizeof(counts[0]);n++) {
        const struct Case *test=cases+c;
        uint8_t data[16],count[16],want[16]={0},original[16];
        for(unsigned i=0;i<16;i++) {
            data[i]=(uint8_t)(i*71+sample*13+n);
            count[i]=(uint8_t)(i*93+sample*57+n);
            if(test->dataKnown&(1u<<i)) data[i]=(uint8_t)(inputs[sample]>>(i%4*8));
            if(test->countKnown&(1u<<i)) count[i]=i<4?(uint8_t)(counts[n]>>(i*8)):0;
        }
        for(unsigned output=0;output<128;output++) {
            unsigned base=output/test->bits*test->bits;
            uint64_t shift=test->immediate>=0?(unsigned)test->immediate:
                test->perlane?read_shift_bytes(count+base/8,test->bits/8):read_shift_bytes(count,8);
            if(shift>=test->bits) continue;
            int from=(int)(output%test->bits)+(test->left?-(int)shift:(int)shift);
            if(from<0 || from>=(int)test->bits) continue;
            unsigned input=base+(unsigned)from;
            want[output/8]|=((data[input/8]>>(input%8))&1)<<(output%8);
        }
        uint32_t expected=(uint32_t)read_shift_bytes(want+test->lane*4,4);
        uint32_t got=test->translated(inputs[sample],counts[n]);
        if(got!=expected) {
            fprintf(stderr,"%s sample=%u count=%u LLVM=%x want=%x\n",test->row,sample,counts[n],got,expected);
            return 1;
        }
        if(test->original) {
            test->original(count,data,original);
            if(read_shift_bytes(original+test->lane*4,4)!=expected) {
                fprintf(stderr,"%s original Go selected output differs\n",test->row);
                return 2;
            }
        }
    }
    return 0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "shift-partial-result", triple, text, oracle, prefix)
		})
	}
	t.Log("44 partial-state scalar results x 96 inputs; original Go legacy opcodes plus independent bit oracle; no native AVX512 claim")
}
