package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Assemble a bounded batch once and partition every byte by real instruction
// boundaries. Runtime raw cases do not use our mnemonic-to-opcode tables.
func x86PackedConversionOriginalRawRows(t *testing.T, arch string, rows []string) []string {
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
			instruction, decodeErr := x86asm.Decode(code[position:], mode)
			length, err = instruction.Len, decodeErr
		}
		if err != nil || length < 1 || length > len(code)-position {
			t.Fatal("original conversion boundary", row, err)
		}
		var directives strings.Builder
		for _, value := range code[position : position+length] {
			fmt.Fprintf(&directives, "BYTE $%d\n", value)
		}
		raw = append(raw, strings.TrimSuffix(directives.String(), "\n"))
		position += length
	}
	if position != len(code) {
		t.Fatal("original conversion batch has unconsumed bytes")
	}
	return raw
}

func TestX86PackedConversionRawCompleteOriginalGoForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86PackedConversionOracleRows(arch)
		var source strings.Builder
		source.WriteString("TEXT raw(SB),4,$0-0\n")
		for _, row := range rows {
			source.WriteString(row + "\n")
		}
		source.WriteString("RET\n")
		code := x86PackedShiftActualGoBytes(t, arch, source.String())
		decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
		if err != nil {
			t.Fatal(arch, err)
		}
		if len(decoded.Instrs) != len(rows)+1 {
			t.Fatal("whole original Go byte stream lost instructions", arch, len(decoded.Instrs), len(rows)+1)
		}
		for index, row := range rows {
			want, got := x86ScalarLaneInstruction(t, row), decoded.Instrs[index]
			if want.Op != got.Op || len(want.Args) != len(got.Args) {
				t.Fatal("raw opcode/mask mismatch", arch, row, got)
			}
			for operand := range want.Args {
				if want.Args[operand].String() != got.Args[operand].String() {
					t.Fatal("raw physical operand mismatch", arch, row, got)
				}
			}
		}
		t.Logf("%s: %d actual-Go forms, complete raw byte/typed-operand agreement", arch, len(rows))
	}
}

func TestX86PackedConversionRawPrefixAndTruncationBoundaries(t *testing.T) {
	for _, spec := range x86PackedConversionOracleSpecs() {
		if spec.legacy {
			continue
		}
		for _, shape := range spec.shapes() {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
			row := spec.name + ".Z 64(AX)(CX*4),K1," + bank[shape.destination] + "7"
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT raw(SB),4,$0-0\n"+row+"\n")
			ins, length, known, err := decodedX86PackedNumericConversionInstruction(code, 64)
			if err != nil || !known || length != len(code) || ins.Op != Op(spec.name+".Z") {
				t.Fatal(row, fmt.Sprintf("%x", code), ins, length, err)
			}
			for end := 0; end < len(code); end++ {
				if _, _, known, err := decodedX86PackedNumericConversionInstruction(code[:end], 64); known && err == nil {
					t.Fatal("truncated instruction accepted", row, end)
				}
			}
			for _, mutation := range []struct {
				index int
				xor   byte
			}{{1, 0x08}, {2, 0x04}, {2, 0x08}, {3, 0x08}, {3, 0x01}} {
				bad := append([]byte(nil), code...)
				bad[mutation.index] ^= mutation.xor
				if _, _, known, err := decodedX86PackedNumericConversionInstruction(bad, 64); known && err == nil {
					t.Fatal("invalid fixed/vvvv/zero field accepted", row, fmt.Sprintf("%x", bad))
				}
			}
			// Exact high source/destination registers are unavailable in mode32;
			// a legal K1 mask by itself is not a high-register binding.
			if _, _, known, err := decodedX86PackedNumericConversionInstruction(code, 32); !known || err != nil {
				t.Fatal("legal mode32 masked conversion rejected", row, err)
			}
		}
	}
	for _, encoding := range []struct {
		pp, opcode byte
		name       string
	}{
		{1, 0x5b, "VCVTPS2DQ"}, {2, 0x5b, "VCVTTPS2DQ"},
		{3, 0xe6, "VCVTPD2DQX"}, {1, 0xe6, "VCVTTPD2DQX"},
	} {
		for _, mode := range []int{32, 64} {
			for _, w := range []byte{0, 0x80} {
				code := []byte{0xc4, 0xe1, 0x78 | encoding.pp | w, encoding.opcode, 0xc1}
				ins, n, known, err := decodedX86PackedNumericConversionInstruction(code, mode)
				if err != nil || !known || n != len(code) || string(ins.Op) != encoding.name {
					t.Fatal("Intel VEX.WIG must not become W0-only", mode, fmt.Sprintf("%x", code), ins, err)
				}
			}
		}
	}
}
