package plan9asm

import (
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64NativeScratchScalarSourceEffects(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"word_move", "MOVW R1,R4\nMOVD R4,R1"},
		{"word_shift", "MOVW R1,R4\nLSLW $2,R4,R4\nMOVD R4,R1"},
		{"unaligned_word_store", "MOVD R1,R8\nMOVW R1,R4\nMOVW R4,1(R8)\nMOVD R4,R1"},
		{"branch_join", `MOVD R1,R8
MOVW R1,R4
SUBW $1,R4,R4
CMPW $60,R4
BLT oneByte
CMPW $256,R4
BLT twoBytes
threeBytes:
MOVD $0xf4,R2
MOVB R2,0(R8)
MOVW R4,1(R8)
ADD $3,R8,R8
B done
twoBytes:
MOVD $0xf0,R2
MOVB R2,0(R8)
MOVB R4,1(R8)
ADD $2,R8,R8
B done
oneByte:
LSLW $2,R4,R4
MOVB R4,0(R8)
ADD $1,R8,R8
done:
MOVD R8,R1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := strings.Replace(arm64ScratchSelectedSource, "ADD $3,R1", test.body, 1)
			ctx, pkg, _, _, source := arm64ScratchActualBoundSourceWithAssembly(
				t, "linux", "aarch64-unknown-linux-gnu", assembly)
			symbol := pkg.Path + ".Value"
			layout, err := source.actualCalleeSignature(ctx, symbol, symbol)
			if err != nil {
				t.Fatal(err)
			}
			for _, body := range source.native[symbol] {
				t.Logf("actual native admission generated=%v r27=%v local=%v inputs=%v",
					source.originalObjectGenerated(body.source), arm64ScratchNativeDoesNotAccess(body),
					arm64ScratchSourceLocalInputs(source.functions[symbol], layout),
					arm64ScratchSamePackageInputs(source.functions[symbol], layout, body))
				for at, word := range body.code {
					if word == 0 {
						continue
					}
					var bytes [4]byte
					binary.LittleEndian.PutUint32(bytes[:], word)
					instruction, err := arm64asm.Decode(bytes[:])
					effect, valid := arm64ScratchNativeInputEffect(instruction, true)
					t.Logf("word=%d encoding=%08x instruction=%v decode=%v effect=%+v registered=%v",
						at, word, instruction, err, effect, valid)
				}
			}
			// Only input/R27 closure is asserted here. These native source
			// observations supply no pointee extent or runtime execution proof.
			if _, closed := source.closed[symbol]; !closed {
				t.Fatal("Go-accepted scalar source effects failed actual native input closure")
			}
		})
	}
}
