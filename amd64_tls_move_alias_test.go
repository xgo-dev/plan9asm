package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86TLSMoveSourceYrlRangePrecedesMode32Encoding(t *testing.T) {
	var original strings.Builder
	original.WriteString("TEXT f(SB),4,$0-0\n")
	for _, op := range []string{"MOVL", "MOVQ", "MOVD"} {
		for index := 8; index <= 15; index++ {
			row := fmt.Sprintf("%s TLS,R%d", op, index)
			original.WriteString(row + "\n")
			if err := x86SourceTLSMoveError(x86PureGPUnknownInstruction(t, row), "386"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Go's pre-encoding NOP row lost its complete source range: %s: %v", row, err)
			}
		}
	}
	original.WriteString("RET\n")
	x86ScalarCompareTLSGoObject(t, original.String(), "386", "freebsd", false)
	for _, row := range []string{"MOVL 0(R8)(TLS*1),AX", "MOVL AX,0(R15)(TLS*4)"} {
		if err := x86SourceTLSMoveError(x86PureGPUnknownInstruction(t, row), "386"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("direct TLS removed source base became a physical bank rejection: %s: %v", row, err)
		}
		x86ScalarCompareTLSGoObject(t, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "386", "freebsd", false)
	}
}

func TestX86TLSMoveMOVDAliasRetainsCompleteBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, operands := range []string{"8(TLS),X0", "X7,0(CX)(TLS*4)", "8(TLS),M0"} {
			instruction := x86PureGPUnknownInstruction(t, "MOVD "+operands)
			if err := x86SourceTLSMoveError(instruction, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s MOVD %s lost its source TLS contract: %v", arch, operands, err)
			}
		}
		for _, operands := range []string{"TLS,X0", "AX,TLS", "8(TLS),Y0", "$1.5,8(TLS)", "8(TLS),X0,X1"} {
			instruction := x86PureGPUnknownInstruction(t, "MOVD "+operands)
			if err := x86SourceTLSMoveError(instruction, arch); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s invalid MOVD %s hidden by TLS: %v", arch, operands, err)
			}
		}
		var source strings.Builder
		for _, operands := range []string{"8(TLS),X0", "X7,0(CX)(TLS*4)", "8(TLS),M0"} {
			source.WriteString("TEXT f(SB),4,$0-0\n")
			source.WriteString("MOVD " + operands + "\nRET\n")
			// Each independent fixture retains a single native source body.
			x86ScalarCompareTLSGoObject(t, source.String(), arch, "freebsd", false)
			source.Reset()
		}
	}
}
