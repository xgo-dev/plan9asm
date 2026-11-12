//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86COMIConstantOracle(axis x86FloatCompareRuntimeISA) (assembly, declarations, original, driver string, functions int) {
	var asm, decl, goCalls, cDecl, cCalls strings.Builder
	index := 0
	for _, name := range []string{"COMISS", "UCOMISS", "COMISD", "UCOMISD"} {
		if axis != x86FloatCompareSSE {
			name = "V" + name
		}
		values, one := []uint64{0x7fc12345, 0x7f812345, 1}, uint64(0x3f800000)
		if strings.HasSuffix(name, "D") {
			values, one = []uint64{0x7ff8123456789abc, 0x7ff0123456789abc, 1}, 0x3ff0000000000000
		}
		forms := []struct{ suffix, source, destination string }{{"", "X0", "X1"}}
		if axis == x86FloatCompareEVEX {
			forms = []struct{ suffix, source, destination string }{
				{"", "X16", "X17"}, {"", "X30", "X31"},
				{".SAE", "X0", "X1"}, {".SAE", "X16", "X17"},
			}
		}
		for _, form := range forms {
			for _, bits := range values {
				for _, dead := range []bool{false, true} {
					function := fmt.Sprintf("comi%d", index)
					fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$8-12\nSTMXCSR saved-4(SP)\nMOVQ out+0(FP),DI\n", function)
					fmt.Fprintf(&asm, "MOVQ $%#x,AX\nMOVQ AX,X0\nMOVQ $%#x,AX\nMOVQ AX,X1\n", bits, one)
					if form.source != "X0" {
						fmt.Fprintf(&asm, "VMOVAPS X0,%s\nVMOVAPS X1,%s\n", form.source, form.destination)
					}
					fmt.Fprintf(&asm, "LDMXCSR csr+8(FP)\n%s%s %s,%s\n", name, form.suffix, form.source, form.destination)
					if dead {
						asm.WriteString("MOVQ $0x77,BX\n")
					} else {
						asm.WriteString("PUSHFQ\nPOPQ BX\nANDQ $0x8d5,BX\n")
					}
					asm.WriteString("MOVQ BX,(DI)\nSTMXCSR 8(DI)\nLDMXCSR saved-4(SP)\nRET\n")
					fmt.Fprintf(&decl, "func %s(out *[4]uint64, csr uint32)\n", function)
					fmt.Fprintf(&goCalls, "check(%d,%s)\n", index, function)
					fmt.Fprintf(&cDecl, "extern void %s(uint64_t*,uint32_t);\n", function)
					fmt.Fprintf(&cCalls, "check(%d,%s);\n", index, function)
					index++
				}
			}
		}
	}
	original = `package main
import "fmt"
func check(index int, fn func(*[4]uint64,uint32)) {
    for mode:=0; mode<8; mode++ {
        out:=[4]uint64{0x1111111111111111,0x2222222222222222,0x3333333333333333,0x4444444444444444}
        csr:=uint32(0x1f80)|uint32(mode&1)<<6|uint32(mode>>1&1)<<15|uint32(mode>>2)<<5
        fn(&out,csr)
        fmt.Printf("%d %d %016x %016x %016x %016x\n",index,mode,out[0],out[1],out[2],out[3])
    }
}
` + decl.String() + "func main(){\n" + goCalls.String() + "}\n"
	driver = `#include <stdint.h>
#include <stdio.h>
static void check(int index,void (*fn)(uint64_t*,uint32_t)) {
    for(unsigned mode=0; mode<8; mode++) {
        uint64_t out[]={UINT64_C(0x1111111111111111),UINT64_C(0x2222222222222222),UINT64_C(0x3333333333333333),UINT64_C(0x4444444444444444)};
        uint32_t csr=0x1f80|((mode&1)<<6)|((mode>>1&1)<<15)|((mode>>2)<<5);
        fn(out,csr);
        printf("%d %u %016llx %016llx %016llx %016llx\n",index,mode,(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2],(unsigned long long)out[3]);
    }
}
` + cDecl.String() + "int main(void){\n" + cCalls.String() + "return 0;}\n"
	return asm.String(), decl.String(), original, driver, index
}

func TestCrossLinuxRuntimeMatrixX86COMIOriginalConstantsAndMXCSR(t *testing.T) {
	x86COMIOriginalConstantsAndMXCSR(t, x86FloatCompareSSE)
}

func TestX86COMICompleteStatusOriginalInventory(t *testing.T) {
	for _, axis := range []x86FloatCompareRuntimeISA{x86FloatCompareSSE, x86FloatCompareVEX, x86FloatCompareEVEX} {
		assembly, _, _, _, functions := x86COMIConstantOracle(axis)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		want := 24
		if axis == x86FloatCompareEVEX {
			want = 96
		}
		if functions != want {
			t.Fatal("changed constant status denominator", axis, functions)
		}
	}
}

func x86COMIOriginalConstantsAndMXCSR(t *testing.T, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, axis)
	assembly, declarations, main, driver, count := x86COMIConstantOracle(axis)
	original := x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, main)
	want := strings.Split(strings.TrimSpace(string(original)), "\n")
	expected := 24
	if axis == x86FloatCompareEVEX {
		expected = 96
	}
	if count != expected || len(want) != expected*8 {
		t.Fatalf("original Go produced %d functions/%d rows, want %d functions x 8 MXCSR controls", count, len(want), expected)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, ir)
				}
				for _, backend := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%v/backend%s", optimized, backend), func(t *testing.T) {
						output := execution.compileAndRunLLVM(t, "comi-status", input, driver, backend)
						got := strings.Split(strings.TrimSpace(string(output)), "\n")
						if len(got) != len(want) {
							t.Fatalf("LLVM rows=%d original=%d", len(got), len(want))
						}
						mismatches := 0
						for index := range want {
							if got[index] != want[index] {
								if mismatches == 0 {
									t.Logf("first mismatch: original %s; LLVM %s", want[index], got[index])
								}
								mismatches++
							}
						}
						if mismatches != 0 {
							t.Errorf("original Go FLAGS/MXCSR/canary mismatches=%d/%d", mismatches, len(want))
						}
					})
				}
			}
		})
	}
}
