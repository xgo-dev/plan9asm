package plan9asm

import (
	"fmt"
	"testing"
)

// The bytes retain independent VEX float, EVEX funnel, SHA and scalar
// precision fixtures from their existing raw-family tests.
type rawPrefixQualificationFixture struct {
	name   string
	code   []byte
	decode func([]byte, int) (Instr, int, bool, error)
}

func rawPrefixQualificationFixtures() []rawPrefixQualificationFixture {
	return []rawPrefixQualificationFixture{
		{"vex-float-memory", []byte{0xc4, 0x01, 0xe5, 0x58, 0x64, 0x88, 0x20}, decodedX86VEXBinaryFloatInstruction},
		{"evex-funnel-memory", []byte{0x62, 0xf3, 0xf5, 0xdb, 0x73, 0x50, 0x7f, 0x09}, decodedX86FunnelShiftInstruction},
		{"legacy-sha-register", []byte{0x0f, 0x38, 0xc8, 0xca}, decodedX86SHAInstruction},
		{"scalar-precision-memory", []byte{0x62, 0xf1, 0x56, 0x83, 0x5a, 0x50, 0x02}, decodedX86ScalarPrecisionConvertInstruction},
	}
}

var rawPrefixQualificationSink Instr

func BenchmarkX86RawPrefixDecoders(b *testing.B) {
	for _, fixture := range rawPrefixQualificationFixtures() {
		for _, mode := range []int{32, 64} {
			for _, variant := range []struct {
				name   string
				prefix []byte
				cut    int
			}{
				{"original", nil, len(fixture.code)},
				{"last-segment", []byte{0x65, 0x64}, len(fixture.code)},
				{"address-override", []byte{0x64, 0x67, 0x65}, len(fixture.code)},
				{"nonmatch", []byte{0x90}, len(fixture.code)},
				{"truncated", []byte{0x64}, 1},
			} {
				b.Run(fmt.Sprintf("%s/mode%d/%s", fixture.name, mode, variant.name), func(b *testing.B) {
					code := append(append([]byte(nil), variant.prefix...), fixture.code[:variant.cut]...)
					// Compare acceptance and exact errors outside timing. Cases
					// deliberately include matched, nonmatching and invalid input.
					fixture.decode(code, mode)
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						rawPrefixQualificationSink, _, _, _ = fixture.decode(code, mode)
					}
				})
			}
		}
	}
}
