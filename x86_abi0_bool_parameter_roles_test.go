package plan9asm

import (
	"errors"
	"testing"
)

func TestX86ABI0Mode32CanonicalBoolKeepsExistingScalarInputRoles(t *testing.T) {
	for _, row := range []struct {
		name, declaration, source string
		good                      bool
	}{
		{"opaque-pointer-predicate", "func view(p *byte) bool", "TEXT ·view(SB),4,$0-5\nMOVL p+0(FP),AX\nMOVL AX,BX\nTESTL $15,BX\nSETEQ ret+4(FP)\nRET\n", true},
		{"float-existing-typed-effect", "func view(x float32) bool", "TEXT ·view(SB),4,$0-5\nMOVSS x+0(FP),X0\nXORPS X1,X1\nCOMISS X1,X0\nSETNE ret+4(FP)\nRET\n", true},
		{"opaque-pointer-not-numeric", "func view(p *byte) bool", "TEXT ·view(SB),4,$0-5\nMOVL p+0(FP),AX\nMOVB AX,ret+4(FP)\nRET\n", false},
		{"float-not-canonical", "func view(x float32) bool", "TEXT ·view(SB),4,$0-5\nMOVL x+0(FP),AX\nMOVB AX,ret+4(FP)\nRET\n", false},
		{"missing-float-byte", "func view(x float32) bool", "TEXT ·view(SB),4,$0-5\nMOVB x+0(FP),AX\nMOVL AX,X0\nXORPS X1,X1\nCOMISS X1,X0\nSETNE ret+4(FP)\nRET\n", false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration+"\n", "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("canonical bool contract replaced the independent scalar input/effect role", row.good, len(ir), err)
				}
			})
		}
	}
}
