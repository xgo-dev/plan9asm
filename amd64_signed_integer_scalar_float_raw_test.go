package plan9asm

import (
	"bytes"
	"strings"
	"testing"
)

func TestX86SignedIntegerScalarFloatMode32WIGActualGoAndRaw(t *testing.T) {
	for _, row := range []struct {
		source string
		code   []byte
		op     Op
	}{
		{"VCVTSI2SSQ AX,X0,X1", []byte{0xc4, 0xe1, 0xfa, 0x2a, 0xc8}, "VCVTSI2SSQ"},
		{"VCVTSI2SDQ AX,X0,X1", []byte{0xc4, 0xe1, 0xfb, 0x2a, 0xc8}, "VCVTSI2SDQ"},
	} {
		listing := x86InsertExtractGoListing(t, "386", "TEXT f(SB),4,$0-0\n"+row.source+"\nRET\n")
		var actual []byte
		for _, line := range strings.Split(string(listing), "\n") {
			actual = append(actual, x86InsertExtractListedBytes(line)...)
		}
		if !bytes.Equal(actual, append(append([]byte{}, row.code...), 0xc3)) {
			t.Fatalf("actual Go mode32 W1 object changed: %x", actual)
		}
		ins, length, recognized, err := decodedX86ScalarIntegerFloatInstruction(row.code, 32)
		if !recognized || err != nil || length != len(row.code) || ins.Op != row.op {
			t.Fatalf("mode32 raw object identity: %+v/%v", ins, err)
		}
		f, recognized, err := x86SignedIntegerFloatProperties(ins, "386")
		if !recognized || err != nil || f.sourceBits != 32 {
			t.Fatalf("WIG did not preserve physical signed32 input: %+v/%v", f, err)
		}
	}
	// EVEX compressed displacement uses the *physical* W0 tuple in mode32,
	// not the W1 tuple obtained by decoding the same bytes as 64-bit code.
	code := []byte{0x62, 0xf1, 0xff, 0x08, 0x2a, 0x48, 0x02}
	for _, mode := range []int{32, 64} {
		ins, _, known, err := decodedX86ScalarIntegerFloatInstruction(code, mode)
		want := int64(16)
		if mode == 32 {
			want = 8
		}
		if !known || err != nil || ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Off != want {
			t.Fatalf("EVEX mode%d displacement: %+v/%v want%d", mode, ins, err, want)
		}
	}
}
