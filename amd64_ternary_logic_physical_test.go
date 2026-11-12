package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Independent EVEX.66.0F3A.W0/W1.25 /r ib witnesses use only banks 0-2
// and AX+CX*4. Their low-bank physical mode32 encodings are valid even
// though Go's named 386 frontend cannot express four or five operands.
func x86TernaryIndependentFixtureBytes(row x86TernaryOracleRow) []byte {
	p1, p2 := byte(0x75), byte(0x08)
	if row.laneBits == 64 {
		p1 |= 0x80
	}
	switch row.width {
	case 32:
		p2 |= 0x20
	case 64:
		p2 |= 0x40
	}
	if row.mask >= 0 {
		p2 |= 7
	}
	if row.zeroing {
		p2 |= 0x80
	}
	if row.broadcast {
		p2 |= 0x10
	}
	code := []byte{0x62, 0xf3, p1, p2, 0x25}
	if row.memory {
		// ModRM: dst=2, mod01, SIB; SIB: scale4, CX, AX.
		// EVEX disp8 scales by the complete tuple or BCST element.
		code = append(code, 0x54, 0x88, byte(int8(-64/row.sourceWidth)))
	} else {
		code = append(code, 0xd0)
	}
	return append(code, 150)
}

func x86TernaryOriginalRawRows(t *testing.T, rows []x86TernaryOracleRow) []string {
	t.Helper()
	var instructions []string
	var expected []byte
	var raw []string
	for _, row := range rows {
		instructions = append(instructions, row.row)
		code := x86TernaryIndependentFixtureBytes(row)
		expected = append(expected, code...)
		raw = append(raw, strings.TrimSuffix(x86RawDisplacementDirectives(code), "\n"))
	}
	expected = append(expected, 0xc3)
	listing, err := x86ExtensionGoListing(t, "amd64", strings.Join(instructions, "\n"))
	if err != nil {
		t.Fatalf("actual complete ternary Go byte listing: %v\n%s", err, listing)
	}
	var actual []byte
	for _, line := range strings.Split(listing, "\n") {
		actual = append(actual, x86InsertExtractListedBytes(line)...)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("whole Go ternary bytes, including final RET, differ from independent EVEX fields\ngot  %x\nwant %x\n%s", actual, expected, listing)
	}
	return raw
}

func TestX86TernaryPhysicalMode32KeepsCompleteRawClass(t *testing.T) {
	rows := x86TernaryCompleteOracleRows()
	raw := x86TernaryOriginalRawRows(t, rows)
	if len(raw) != 54 {
		t.Fatal("complete physical ternary matrix changed", len(raw))
	}
	var source strings.Builder
	for index, instruction := range raw {
		fmt.Fprintf(&source, "TEXT rawTernary%d(SB),4,$0-0\n%s\nRET\n", index, instruction)
	}
	for _, target := range x86RawReturnTargets {
		if target.arch == "386" {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		}
	}
	for _, row := range rows {
		t.Run(row.row, func(t *testing.T) {
			named := x86ScalarLaneInstruction(t, row.row)
			if _, known, err := x86TernaryLogicProperties(named.Op, named, "386"); !known || err == nil {
				t.Fatal("named386 operand limit must remain independent of physical EVEX support", known, err)
			}
			code := x86TernaryIndependentFixtureBytes(row)
			ins, length, known, err := decodedX86TernaryLogicInstruction(code, 32)
			if !known || err != nil || length != len(code) {
				t.Fatal("legal low-bank physical386 ternary encoding borrowed named frontend rejection", known, length, err)
			}
			form, known, err := x86TernaryLogicProperties(ins.Op, ins, "386")
			if !known || err != nil || !ins.x86Encoded || ins.x86VectorBytes != row.width ||
				form.byteWidth != row.width || form.memoryBytes != row.sourceWidth && row.memory ||
				form.broadcast != row.broadcast || form.zeroing != row.zeroing || form.mask != row.mask {
				t.Fatal("physical mode/width/mask/broadcast metadata lost", ins, form, known, err)
			}
		})
	}
}
