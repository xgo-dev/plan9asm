package plan9asm

import "testing"

// Candidate-only owner. Do not install/run this against baseline, where the
// helper does not exist; a missing symbol would not establish a product RED.
func TestX86RawSegmentPrefixTuples(t *testing.T) {
	for _, test := range []struct {
		code    []byte
		length  int
		segment Reg
		address bool
	}{
		{nil, 0, "", false},
		{[]byte{0x64}, 1, FS, false},
		{[]byte{0x65}, 1, GS, false},
		{[]byte{0x67, 0x67}, 2, "", true},
		{[]byte{0x64, 0x65}, 2, GS, false},
		{[]byte{0x65, 0x64}, 2, FS, false},
		{[]byte{0x65, 0x67, 0x64, 0x67}, 4, FS, true},
		{[]byte{0x64, 0x90, 0x65, 0x67}, 1, FS, false},
	} {
		length, segment, address := x86RawSegmentPrefixes(test.code)
		if length != test.length || segment != test.segment || address != test.address {
			t.Fatalf("%x: got (%d,%s,%v), want (%d,%s,%v)", test.code, length, segment, address, test.length, test.segment, test.address)
		}
	}
	// All 256 next bytes, preceded by each physical segment/address state.
	for _, prefix := range []struct {
		code    []byte
		segment Reg
		address bool
	}{
		{nil, "", false}, {[]byte{0x64}, FS, false}, {[]byte{0x65}, GS, false},
		{[]byte{0x67}, "", true}, {[]byte{0x64, 0x67}, FS, true}, {[]byte{0x65, 0x67}, GS, true},
	} {
		for next := 0; next < 256; next++ {
			code := append(append([]byte(nil), prefix.code...), byte(next), 0x90, 0x65, 0x67)
			wantLength, wantSegment, wantAddress := len(prefix.code), prefix.segment, prefix.address
			switch byte(next) {
			case 0x64:
				wantLength++
				wantSegment = FS
			case 0x65:
				wantLength++
				wantSegment = GS
			case 0x67:
				wantLength++
				wantAddress = true
			}
			length, segment, address := x86RawSegmentPrefixes(code)
			if length != wantLength || segment != wantSegment || address != wantAddress {
				t.Fatalf("%x: got (%d,%s,%v), want (%d,%s,%v)", code, length, segment, address, wantLength, wantSegment, wantAddress)
			}
		}
	}
}
