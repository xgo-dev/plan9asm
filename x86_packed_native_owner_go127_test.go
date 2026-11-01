//go:build go1.27

package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86ExistingSDKOwnersPrecedePackedNativeFamilies(t *testing.T) {
	owners := x86CaptureNativeFamilyOwnerOracle(t)
	for _, first := range []string{"X0", "(AX)"} {
		for _, row := range []struct{ family, instruction string }{
			{"integer-minmax/VEX-byte", "VPMINSB " + first + ",X1,X2"},
			{"integer-minmax/VEX", "VPMAXUD " + first + ",X1,X2"},
			{"integer-minmax/EVEX", "VPMAXUD " + first + ",X1,K1,X2"},
			{"reduction/legacy-horizontal", "HADDPS " + first + ",X2"},
			{"reduction/legacy-dot", "DPPS $255," + first + ",X2"},
			{"reduction/named-VEX", "VDPPS $255," + first + ",X1,X2"},
			{"mask-blend/float32", "VBLENDMPS " + first + ",X1,K1,X2"},
			{"mask-blend/float64", "VBLENDMPD " + first + ",X1,K1,X2"},
			{"mask-blend/byte", "VPBLENDMB " + first + ",X1,K1,X2"},
			{"mask-blend/word", "VPBLENDMW " + first + ",X1,K1,X2"},
			{"mask-blend/dword", "VPBLENDMD " + first + ",X1,K1,X2"},
			{"mask-blend/qword", "VPBLENDMQ " + first + ",X1,K1,X2"},
		} {
			t.Run(row.family+"/"+first, func(t *testing.T) {
				text, declaration := x86PackedNativeOwnerProgram(row.instruction)
				owners.checkProgram(t, text, declaration, row.instruction)
			})
		}
		t.Run("reduction/raw-VEX/"+first, func(t *testing.T) {
			modrm := byte(0xd0) // X0, X1, X2: independent VEX.vvvv=1.
			if first == "(AX)" {
				modrm = 0x10
			}
			bytes := []byte{0xc4, 0xe3, 0x71, 0x40, modrm, 0xff}
			text, declaration := x86PackedNativeOwnerProgram(x86RawDisplacementDirectives(bytes))
			owners.checkProgram(t, text, declaration, "VDPPS $255,"+first+",X1,X2")
		})
	}
}

func x86PackedNativeOwnerProgram(instruction string) (string, string) {
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\n"+
			"MOVOU (AX),X0\nMOVOU (BX),X1\nMOVOU X1,X2\nMOVL $-1,DX\nKMOVD DX,K1\nSTC\n%s\n"+
			"MOVOU X2,(DI)\nSETCS 16(DI)\nSTMXCSR 20(DI)\nRET\n", instruction),
		"func Value(out *[24]byte,a,b *[16]byte)\n"
}
