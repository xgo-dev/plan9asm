package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Intel's PMADDWD and PMADDUBSW tables specify WIG, unlike EVEX PACK*DW.
// Bind W0 to stock Go's actual instruction, then independently compare the
// complete LLVM MC opcode/operands of the W1 physical counterpart.
func TestX86MADDTypedPhysicalWIGCompleteOperands(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 MC required")
	}
	for _, opcode := range []string{"VPMADDWD", "VPMADDUBSW"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{bank + "1", "16(AX)(CX*2)"} {
				row := opcode + ".Z " + source + "," + bank + "2,K3," + bank + "4"
				code := assembleX87ControlBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				code = code[:len(code)-1]
				if code[0] != 0x62 || code[2]&0x80 != 0 {
					t.Fatal("Go original is not the expected EVEX W0 row", row, code)
				}
				for _, mode := range []int{32, 64} {
					t.Run(fmt.Sprintf("%d/%s", mode, row), func(t *testing.T) {
						var texts [2]string
						for w := 0; w < 2; w++ {
							physical := append([]byte(nil), code...)
							physical[2] |= byte(w << 7)
							var input strings.Builder
							for _, value := range physical {
								fmt.Fprintf(&input, "0x%02x ", value)
							}
							triple := "x86_64"
							if mode == 32 {
								triple = "i386"
							}
							ctx, cancel := runtimeOracleStageContext(t)
							command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple,
								"--mattr=+avx2,+avx512bw,+avx512vl")
							command.Stdin = strings.NewReader(input.String() + "\n")
							output, err := runtimeOracleCombinedOutput(ctx, command)
							cancel()
							if err != nil || strings.Contains(string(output), "warning:") ||
								!strings.Contains(string(output), strings.ToLower(opcode)) {
								t.Fatalf("independent MC rejected %x: %v\n%s", physical, err, output)
							}
							texts[w] = strings.TrimSpace(string(output))
							instruction, size, known, err := decodedX86EVEXPackedMADDInstruction(physical, mode)
							if err != nil || !known || size != len(physical) {
								t.Errorf("Go-bound WIG physical form rejected: %x %d/%t/%v", physical, size, known, err)
								continue
							}
							arch := map[int]string{32: "386", 64: "amd64"}[mode]
							if form, known, err := x86PackedMultiplyAddProperties(instruction.Op, instruction, arch); err != nil || !known || form.mask != 2 {
								t.Errorf("physical MADD missing complete typed grammar: %+v %t/%v", form, known, err)
							}
							if width, write, valid := x86InstructionMemoryShape(instruction, 0, arch); source[0] == '1' &&
								(!valid || write || width != int64(amd64VectorByteWidth(Reg(bank+"0")))) {
								t.Errorf("complete physical memory envelope missing: %d/%t/%t", width, write, valid)
							}
						}
						if texts[0] != texts[1] {
							t.Fatalf("WIG changed complete disassembled operands: W0=%q W1=%q", texts[0], texts[1])
						}
					})
				}
			}
		}
	}
}

func TestX86MADDTypedCallerByteFamily(t *testing.T) {
	rows := []string{"PMADDUBSW X0,X1", "PMADDUBSW X1,X1", "PMADDUBSW (DI),X1"}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, first := range []string{bank + "0", "(DI)"} {
			rows = append(rows,
				"VPMADDUBSW "+first+","+bank+"1,"+bank+"2",
				"VPMADDUBSW "+first+","+bank+"1,K1,"+bank+"2",
				"VPMADDUBSW.Z "+first+","+bank+"1,K1,"+bank+"2")
		}
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			result := "X2"
			if strings.HasPrefix(row, "PMADD") {
				result = "X1"
			}
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal("Go-accepted byte-MADD is missing caller effects", triple, err)
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86MADDTypedXUpperZero(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	assembly := "TEXT ·upper(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nVMOVUPS (CX),Z0\nVMOVUPS (DX),Z1\nVMOVUPS (DX),Z2\nVPMADDUBSW X0,X1,X2\nVMOVUPS Z2,(AX)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	ir := x86NarrowOracleIR(t, assembly, "package narroworacle\nfunc upper(out,a,b *[64]byte)\n", execution.triple)
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void upper(void*,const void*,const void*);
int main(void) {
 uint8_t a[64],b[64],out[66];memset(a,2,64);memset(b,3,64);memset(out,0xc3,66);
 upper(out+1,a,b);
 for(int i=0;i<64;++i) {
  int want=i<16?(i&1?0:12):0;
  if(out[i+1]!=want) {fprintf(stderr,"MADD alias byte%d got=%u want=%u\n",i,out[i+1],want);return 1;}
 }
 if(out[0]!=0xc3||out[65]!=0xc3)return 2;
 return 0;
}
`
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "madd-x-upper", ir, main, level)
		})
	}
}
