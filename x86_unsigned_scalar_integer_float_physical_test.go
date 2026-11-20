package plan9asm

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Intel SDM VCVTUSI2SD/SS explicitly ignores W in non-64-bit mode. Keep the
// raw byte producer independent of Go's canonical N8 table: a disp8 of three
// means +12 for physical mode32, not +24. This observes encodings, not entry
// registers, initialized values, source backing or native CPU execution.
func TestX86UnsignedScalarIntegerFloatPhysicalModeAndCompressedTuple(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc is required for independent unsigned scalar physical decoding")
	}
	for _, mode := range []int{32, 64} {
		arch, triple := "amd64", "x86_64-unknown-linux-gnu"
		if mode == 32 {
			arch, triple = "386", "i386-unknown-linux-gnu"
		}
		for _, pp := range []byte{2, 3} {
			for _, wide := range []bool{false, true} {
				for _, memory := range []bool{false, true} {
					for length := byte(0); length < 3; length++ {
						t.Run(fmt.Sprintf("%s/pp%d/W1=%t/memory=%t/LL%d", arch, pp, wide, memory, length), func(t *testing.T) {
							code := encodeX86EVEXScalarIntegerFloat(true, pp, wide, length, false, 2, 1, 3)
							if memory {
								code[5] = 0x53 // disp8(BX), X1 -> X2.
								code = append(code, 3)
							}
							var input, directives strings.Builder
							for _, value := range code {
								fmt.Fprintf(&input, "0x%02x ", value)
								fmt.Fprintf(&directives, "BYTE $0x%02x\n", value)
							}
							source := "TEXT physical(SB),4,$0-0\n" + directives.String() + "RET\n"
							actual := x86OrderingHintGoBytes(t, arch, source)
							if !bytes.Equal(actual, append(append([]byte(nil), code...), 0xc3)) {
								t.Fatal("actual Go changed the complete original scalar physical bytes", actual, code)
							}
							ctx, cancel := runtimeOracleStageContext(t)
							defer cancel()
							command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+avx512f")
							command.Stdin = strings.NewReader(input.String() + "\n")
							output, err := runtimeOracleCombinedOutput(ctx, command)
							stem := "vcvtusi2ss"
							if pp == 3 {
								stem = "vcvtusi2sd"
							}
							width := 4
							if wide && mode == 64 {
								width = 8
							}
							if err != nil || strings.Contains(string(output), "warning:") || !strings.Contains(string(output), stem) ||
								memory && !strings.Contains(string(output), fmt.Sprint(3*width)+"(") {
								t.Fatal("independent LLVM physical scalar opcode/tuple prior failed", err, string(output))
							}
							ins, length, known, err := decodedX86ScalarIntegerFloatInstruction(code, mode)
							if !known || err != nil || length != len(code) || ins.Op != scalarIntegerFloatRawOp(true, pp, wide) ||
								len(ins.Args) != 3 || ins.Args[1].Reg != "X1" || ins.Args[2].Reg != "X2" {
								t.Fatal("physical source identity or scalar upper/destination changed", ins, length, known, err)
							}
							if memory && (ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != BX || ins.Args[0].Mem.Off != int64(3*width)) ||
								!memory && (ins.Args[0].Kind != OpReg || ins.Args[0].Reg != BX) {
								t.Fatal("WIG mode32 acquired the nominal Q source width/displacement", ins.Args[0], width)
							}
						})
					}
				}
			}
		}
	}
}
