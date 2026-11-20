package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86PackedConversionOriginalInitializedNamedRawParity(t *testing.T) {
	named := x86PackedDoubleDwordOriginalAssembly()
	raw := x86PackedDoubleDwordRawAssembly(named)
	if named == raw || strings.Count(raw, "BYTE $") != 20 {
		t.Fatal("original four-conversion raw counterexample changed")
	}
	declaration := "func packeddoubledword(out *byte, doubles *float64, dwords *int32, old *float64, mask uint64)"
	for _, source := range []string{named, raw} {
		goAssemblerOracleOutput(t, "amd64", x86PackedDoubleDwordGoAssemblerSource(source), "", true)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			for _, spelling := range []struct{ name, source string }{{"named", named}, {"raw", raw}} {
				ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Fatalf("same initialized original program, %s conversion identity only: %v", spelling.name, err)
				}
				// LLVM's narrowing memory spelling carries the physical Y
				// source width; it is not the register-source base mnemonic.
				for _, op := range []string{"vcvtdq2pd", "vcvttpd2dqy", "vcvtpd2dq", "cvtpd2dq"} {
					if !strings.Contains(ir, op+" ") {
						t.Fatal("original conversion opcode or exception obligation disappeared", spelling.name, op)
					}
				}
			}
		})
	}
}

// The independent full Go inventories already bind every encoder attribute.
// These rows join their complete register/memory, width, broadcast, mask and
// rounding spellings to the same initialized public named/raw program.
func x86PackedConversionContinuationRows(arch string) []string {
	rows := append([]string(nil), x86PackedConversionOracleRows(arch)...)
	for _, row := range x86SignedPackedValueRows() {
		rows = append(rows, row.op+" "+row.input+","+row.mask+row.bank+"1")
	}
	return rows
}

func x86PackedConversionContinuationFixture(t *testing.T, name, arch, row string) (string, string) {
	t.Helper()
	word, move := 8, "MOVQ"
	high := "VPXORD Z31,Z31,Z31\n"
	if arch == "386" {
		word, move = 4, "MOVL"
		high = ""
	}
	ins := x86ScalarLaneInstruction(t, row)
	destination := ins.Args[len(ins.Args)-1].Reg
	index := strings.TrimLeft(string(destination), "XYZ")
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n"+
		"%s p+0(FP),BX\nMOVL $1,CX\nMOVL $1,DX\nKMOVD CX,K1\nKMOVD CX,K7\n"+
		"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z7,Z7,Z7\n"+
		"%sSTC\n%s\nVPEXTRD $0,X%s,CX\nMOVL CX,ret+%d(FP)\nRET\n",
		name, word+4, move, move, high, row, index, word), fmt.Sprintf("func %s(p *byte) uint32\n", name)
}

func x86PackedConversionContinuationRawRows(t *testing.T, arch string, rows []string) []string {
	t.Helper()
	code := x86PackedShiftActualGoBytes(t, arch, "TEXT raw(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\n")
	mode := 64
	if arch == "386" {
		mode = 32
	}
	var raw []string
	position := 0
	for _, row := range rows {
		_, length, known, err := decodedX86PackedNumericConversionInstruction(code[position:], mode)
		if !known {
			_, length, known, err = decodedX86SameWidthConversionInstruction(code[position:], mode)
		}
		if !known {
			_, length, known, err = decodedX86PackedDoubleDwordInstruction(code[position:], mode)
		}
		if !known {
			instruction, decodeErr := x86asm.Decode(code[position:], mode)
			length, err = instruction.Len, decodeErr
		}
		if err != nil || length < 1 || length > len(code)-position {
			t.Fatal("original complete conversion byte boundary", row, err)
		}
		raw = append(raw, strings.TrimSuffix(x86RawDisplacementDirectives(code[position:position+length]), "\n"))
		position += length
	}
	if position != len(code) {
		t.Fatal("unconsumed original conversion bytes", position, len(code))
	}
	return raw
}
