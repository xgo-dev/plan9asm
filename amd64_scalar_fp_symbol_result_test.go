package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

// Go's mode32 SB memory role ignores a Reg annotation and uses an Index.
// Neither spelling is an ABI0 result write. Keep this denominator independent
// of the transfer registry so a new parser representation cannot bypass RET.
func TestX86ScalarFPStaticSymbolStoresCannotReplaceResult(t *testing.T) {
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		for _, destination := range []string{
			"slot<>(SB)", "slot<>(SB)(AX)", "slot<>(SB)(CX*1)", "slot<>(SB)(AX)(CX*2)",
		} {
			t.Run(op+"/"+destination, func(t *testing.T) {
				source := fmt.Sprintf("GLOBL slot<>(SB),16,$16\nTEXT ·view(SB),4,$0-8\nPXOR X0,X0\n%s X0,%s\nRET\n", op, destination)
				goAssemblerOracleOutput(t, "386", source, "", true)
				for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint64\n", "386", triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Errorf("%s %s static store substituted for unwritten result: %v; IR bytes=%d", triple, api, err, len(ir))
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarFPStaticSymbolStoresKeepCFGAndPointerBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, body, declaration string
		args                    int
	}{
		{
			name:        "result absent on one return path",
			body:        "MOVL $1,AX\nCMPL AX,AX\nJE missing\nPXOR X0,X0\nMOVQ X0,ret+0(FP)\nRET\nmissing:\nPXOR X0,X0\nMOVQ X0,slot<>(SB)\nRET",
			declaration: "func view() uint64\n",
			args:        8,
		},
		{
			name:        "pointer bits through X are not numeric output",
			body:        "MOVQ p+0(FP),AX\nMOVQ AX,X0\nMOVQ X0,slot<>(SB)\nPXOR X1,X1\nMOVQ X1,ret+8(FP)\nRET",
			declaration: "func view(p *byte) uint64\n",
			args:        16,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := fmt.Sprintf("GLOBL slot<>(SB),16,$16\nTEXT ·view(SB),4,$0-%d\n%s\n", tc.args, tc.body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, tc.declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("%s borrowed result or pointer authority: %v; IR bytes=%d", api, err, len(ir))
				}
			}
		})
	}
}
