//go:build go1.27

package plan9asm

import (
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestGoAMD64FrameDataWholeMaskAESBoundaries(t *testing.T) {
	var rows []string
	for _, op := range []string{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
		rows = append(rows, op+" literal<>+1(SB),K1", op+" K1,literal<>+1(SB)")
	}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, op := range []string{"VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST"} {
			rows = append(rows, op+" literal<>+1(SB),"+bank+"0,"+bank+"1")
			if bank != "Z" {
				// Force the distinct EVEX.128/256 rows, not only VEX.
				rows = append(rows, op+" literal<>+1(SB),"+bank+"0,"+bank+"16")
			}
		}
	}
	rows = append(rows, "VAESIMC literal<>+1(SB),X0",
		"VAESKEYGENASSIST $255,literal<>+1(SB),X0", "VAESKEYGENASSIST $-128,literal<>+1(SB),X0")
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row+"\nRET")
			if len(pcs) != 2 {
				t.Fatal("independent original instruction inventory changed", pcs)
			}
			decode := decodedX86MaskMoveInstruction
			if strings.HasPrefix(row, "VAES") {
				decode = decodedX86AESInstruction
			}
			if _, _, known, err := decode(code, 64); !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatal("ordinary raw decoding borrowed a physical RIP source", known, err)
			}
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
			if err != nil || len(boundaries) != 2 || boundaries[0].Length != int(pcs[1]) ||
				len(scalar) != 1 || scalar[pcs[1]].Op != x86asm.RET {
				t.Fatal("whole original mask/AES boundary lost physical RIP", boundaries, scalar, err)
			}
			for cut := 1; cut < int(pcs[1]); cut++ {
				if values, _, err := x86NumericalNativeBoundaries(code[:cut], 64); err == nil || values != nil {
					t.Fatal("truncated original mask/AES acquired a boundary", cut, err)
				}
			}
		})
	}
}
