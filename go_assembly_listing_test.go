package plan9asm

import (
	"bytes"
	"strings"
	"testing"
)

func TestGoAssemblyListingByteColumns(t *testing.T) {
	const tail = "  A2 ."
	row := "\t0x0000 41 32 20 c3" + strings.Repeat("   ", 12) + tail
	for _, test := range []struct {
		name, line string
		offset     int
		want       []byte
	}{
		{"hex ASCII", row, 0, []byte{0x41, 0x32, 0x20, 0xc3}},
		{"nonzero offset", strings.Replace(row, "0x0000", "0x12340", 1), 0x12340, []byte{0x41, 0x32, 0x20, 0xc3}},
		{"trailing space", "\t0x0010 20" + strings.Repeat("   ", 15) + "   ", 16, []byte{' '}},
		{"full row", "\t0x0000" + strings.Repeat(" 41", 16) + "  " + strings.Repeat("A", 16), 0, bytes.Repeat([]byte{'A'}, 16)},
	} {
		t.Run(test.name, func(t *testing.T) {
			offset, code, err := goAssemblyListingByteRow(test.line)
			if err != nil || offset != test.offset || !bytes.Equal(code, test.want) {
				t.Fatalf("offset=%d bytes=%x error=%v", offset, code, err)
			}
		})
	}
	for _, bad := range []string{
		"", "\t0x0000 41 32 A2", strings.Replace(row, "0x0000", "bad", 1),
		strings.Replace(row, " 32", "   ", 1), strings.Replace(row, " 32", " zz", 1),
		strings.Replace(row, " 32", "032", 1), strings.TrimSuffix(row, tail),
		strings.TrimSuffix(row, tail) + "  A2 . ", row + "41", strings.Replace(row, "A2", "A3", 1),
	} {
		if _, code, err := goAssemblyListingByteRow(bad); err == nil || code != nil {
			t.Fatalf("malformed byte columns accepted: %q (%x)", bad, code)
		}
	}
}
