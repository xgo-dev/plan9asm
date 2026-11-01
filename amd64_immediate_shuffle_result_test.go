package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ImmediateShuffleResultMemoryExtent(t *testing.T) {
	for _, row := range []struct {
		instruction string
		bytes       int
	}{
		{"VPSHUFD $0,value+0(FP),X1", 16},
		{"VPSHUFHW.Z $0,value+0(FP),K1,Y1", 32},
		{"VPSHUFLW.Z $0,value+0(FP),K1,Z1", 64},
		{"VPSHUFD.BCST.Z $0,value+0(FP),K1,Z1", 4},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			ins := x86YMMReadSource(t, row.instruction)
			for missing := -1; missing < 64; missing++ {
				state := x86ResultState{fp: make([]bool, 64)}
				owned := make([]bool, 64)
				for index := range owned {
					owned[index], state.fp[index] = true, index != missing
				}
				state.masks[1] = true
				accepted := x86ResultTransfer(ins, &state, owned, 64, "amd64")
				if want := missing < 0 || missing >= row.bytes; accepted != want {
					t.Fatalf("full original tuple bytes=%d missing=%d accepted=%v", row.bytes, missing, accepted)
				}
			}
		})
	}
	for _, row := range []string{
		"PSHUFHW $0,value+0(FP),X1", "VPSHUFD $0,(AX),X1",
		"VPSHUFD $0,unknown<>(SB),X1", "PSHUFW $0,M0,M1",
	} {
		state := x86ResultState{fp: make([]bool, 16)}
		owned := make([]bool, 16)
		for index := range owned {
			owned[index], state.fp[index] = true, true
		}
		state.pointerGP[0] = true
		if x86ResultTransfer(x86YMMReadSource(t, row), &state, owned, 16, "amd64") {
			t.Fatal("logical storage, pointer or SIMD state acquired native backing/MMX authority", row)
		}
	}
}

func amd64ImmediateShuffleResultMatrix() (source, declarations, harness string) {
	var asm, decl, prototypes, checks strings.Builder
	index := 0
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		width, start := 4, 0
		if strings.HasSuffix(op, "HW") || strings.HasSuffix(op, "LW") {
			width = 2
		}
		if strings.HasSuffix(op, "HW") {
			start = 8
		}
		for _, immediate := range []int{0, 27, 228, 255} {
			for _, destination := range []string{"X0", "X1"} {
				name := fmt.Sprint("shuffle", index)
				fmt.Fprintf(&asm, "TEXT ·%s<ABIInternal>(SB),4,$0-24\nMOVQ AX,X0\nPINSRQ $1,BX,X0\n%s $%d,X0,%s\nPEXTRQ $1,%s,CX\nMOVQ %s,AX\nXORQ CX,AX\nRET\n",
					name, op, immediate, destination, destination, destination)
				fmt.Fprintf(&decl, "func %s(a,b uint64) uint64\n", name)
				fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t,uint64_t);\n", name)
				fmt.Fprintf(&checks, "if(check(%s,%d,%d,%d)){fprintf(stderr,\"%s failed\\n\");return 1;}\n", name, width, start, immediate, name)
				index++
			}
		}
	}
	const reference = `
static int check(uint64_t (*fn)(uint64_t,uint64_t), unsigned width,
                 unsigned start, unsigned imm) {
  const uint64_t values[]={0,UINT64_MAX,UINT64_C(0x1020304050607080),UINT64_C(0xfedcba9876543210)};
  for(unsigned a=0;a<4;a++) {
    for(unsigned b=0;b<4;b++) {
      uint8_t input[16],output[16];
      uint64_t low,high;
      memcpy(input,&values[a],8);
      memcpy(input+8,&values[b],8);
      memcpy(output,input,16);
      for(unsigned lane=0;lane<4;lane++) {
        unsigned selected=(imm>>(2*lane))&3;
        memcpy(output+start+width*lane,input+start+width*selected,width);
      }
      memcpy(&low,output,8);
      memcpy(&high,output+8,8);
      if(fn(values[a],values[b])!=(low^high)) return 1;
    }
  }
  return 0;
}
`
	return asm.String(), decl.String(), "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
		prototypes.String() + reference + "int main(void){\n" + checks.String() + "return 0; }\n"
}

func TestAMD64ImmediateShuffleRegisterResultsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	source, declarations, _ := amd64ImmediateShuffleResultMatrix()
	requireAMD64RegisterResultGoObject(t, source)
	for _, target := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", target, api)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target, ir, "shuffle-result")
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixAMD64ImmediateShuffleRegisterResults(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	source, declarations, harness := amd64ImmediateShuffleResultMatrix()
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimize := range []bool{false, true} {
				text := ir
				if optimize {
					text = x86MulDivRoundOptimize(t, text)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "shuffle-results", triple, text, harness, prefix)
			}
		})
	}
}
