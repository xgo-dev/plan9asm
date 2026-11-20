package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestX86PackedExtendRawWBitMatchesIndependentLLVMDecoder(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	for _, spec := range rawPackedExtendTestSpecs {
		for _, evex := range []bool{false, true} {
			for width := 0; width < 3; width++ {
				if !evex && width == 2 {
					continue
				}
				code := encodeX86VEXPackedExtend(spec.opcode, width != 0, 1, 0)
				code[2] |= 0x80 // All VEX forms are WIG, not W0.
				if evex {
					code = encodeX86EVEXPackedExtend(spec.opcode, byte(width), 1, true, 1, 0)
					code[2] |= 0x80 // EVEX is WIG except signed/unsigned DQ.
				}
				var bytes strings.Builder
				for _, value := range code {
					fmt.Fprintf(&bytes, "0x%02x ", value)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=x86_64", "--mattr=+avx,+avx2,+avx512f,+avx512bw,+avx512vl")
				command.Stdin = strings.NewReader(bytes.String() + "\n")
				output, err := runtimeOracleCombinedOutput(ctx, command)
				cancel()
				invalid := evex && spec.inputBits == 32
				if invalid {
					if !strings.Contains(string(output), "invalid instruction encoding") {
						t.Fatalf("LLVM22 did not reject EVEX DQ W1 %x: %v\n%s", code, err, output)
					}
				} else if err != nil || !strings.Contains(strings.ToUpper(string(output)), string(spec.op)) {
					t.Fatalf("LLVM22 independent WIG decode %x: %v\n%s", code, err, output)
				}
				for _, mode := range []int{32, 64} {
					ins, length, recognized, err := decodedX86PackedExtendInstruction(code, mode)
					if invalid {
						if !recognized || err == nil {
							t.Fatalf("mode%d illegal EVEX DQ W1 acquired widening semantics: %x %+v/%v", mode, code, ins, err)
						}
					} else if !recognized || err != nil || length != len(code) || strings.TrimSuffix(string(ins.Op), ".Z") != string(spec.op) {
						t.Fatalf("mode%d legal WIG %x lost exact family semantics: %+v/%v", mode, code, ins, err)
					}
				}
			}
		}
	}
}

func TestX86PackedZeroExtendActualGoLowMaskedMode32(t *testing.T) {
	rows := x86ZeroExtendLowMaskedMode32Rows(t)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			listing, err := x86ExtensionGoListing(t, "386", row)
			if err != nil {
				t.Fatalf("actual mode32 Go acceptance: %s: %v\n%s", row, err, listing)
			}
			// Keep the complete original uninitialized source. The Go object
			// proves this syntax, not its missing source, K7, merge or address.
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func f()\n", "386", "i386-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("uninitialized original mask form invented numerical inputs", row, api, err)
				}
			}
		})
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for all original private formats")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for batch := 0; batch < 2; batch++ {
			t.Run(fmt.Sprintf("private-formats/%s/batch%d", triple, batch), func(t *testing.T) {
				var source strings.Builder
				for index, row := range rows[batch*36 : (batch+1)*36] {
					fmt.Fprintf(&source, "TEXT Format%d(SB),4,$0-0\n%s\nRET\n", index, row)
				}
				file, signatures := x86UnboundVoidFormatSources(t, source.String(), "386", triple)
				ir := x86InstructionFormatObjectUnit(t, file, signatures, "386", triple, 0,
					func(ctx *amd64Ctx, ins Instr) (bool, bool, error) {
						return ctx.lowerPackedZeroExtendMove(ins.Op, ins)
					})
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		}
	}
}
