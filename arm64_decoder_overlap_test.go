package plan9asm

import (
	"strings"
	"testing"
)

// x/arch's decoder corpus includes machine encodings that Go deliberately
// rejects. These two cases formerly made a mixed MOVHU form appear fully
// supported even though writeback would overwrite the loaded destination.
func TestARM64DecoderWritebackOverlapRejectedLikeGo(t *testing.T) {
	for _, instruction := range []string{
		"MOVHU.P 107(R13), R13",
		"MOVHU.W 192(R2), R2",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT decoderOverlap(SB),$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"decoderOverlap": {Name: "decoderOverlap", Ret: Void},
			}})
			if err == nil || !strings.Contains(err.Error(), "base/data register overlap") {
				t.Fatalf("Go-rejected decoder overlap must fail closed, got %v", err)
			}
		})
	}
}
