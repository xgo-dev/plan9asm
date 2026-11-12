package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Retain the complete formerly rejected sources, including their original
// private frame setup and ABI. A successful internal effect probe is not an
// object certificate for these newly accepted machine-bit consumers.
func TestGoAMD64FixedLocalMachineBitsRetainedPolicyObjects(t *testing.T) {
	t.Run("native vector spill", func(t *testing.T) {
		var assembly, declarations strings.Builder
		for index, name := range []string{"PSUBSW", "PMULLD", "PMULHW", "PMULDQ", "PAVGB", "PMADDUBSW"} {
			source, _, _ := x86PrivateAlignedFrameAuditTypedFixture(t, name+" 16(SP),X0",
				"package frameaudit\nfunc Value(a *uint64, b, c, d uint64) uint64\n")
			function := fmt.Sprintf("Value%d", index)
			assembly.WriteString(strings.Replace(source, "·Value", "·"+function, 1))
			fmt.Fprintf(&declarations, "func %s(a *uint64, b, c, d uint64) uint64\n", function)
		}
		fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), 6)
	})
	t.Run("native multiply", func(t *testing.T) {
		var assembly, declarations strings.Builder
		count := 0
		for _, stem := range []string{"MUL", "IMUL"} {
			for _, width := range fixedLocalImplicitMultiplyWidths {
				name := stem + width.suffix
				for _, role := range []string{"accumulator", "source"} {
					body := "MOVQ SI,CX\n" + name + " CX"
					if role == "accumulator" {
						body = "MOVQ SI,AX\n" + name + " 0(SP)"
					}
					_, _, source := fixedLocalInputFixture(t, body)
					function := fmt.Sprintf("Value%d", count)
					assembly.WriteString(strings.Replace(source, "·Value", "·"+function, 1))
					fmt.Fprintf(&declarations, "func %s(p, q *uint64, a uint64) uint64\n", function)
					count++
				}
			}
		}
		if count != 16 {
			t.Fatal("original native multiply source inventory changed", count)
		}
		fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), count)
	})
	t.Run("unused native arithmetic", func(t *testing.T) {
		base := fixedLocalTransportAssembly("Value0", 49, fixedLocalTransportBoolBody)
		body := strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "ADDQ CX,DX", 1)
		assembly := strings.Replace(base, fixedLocalTransportBoolBody, body, 1)
		declaration := "func Value0(" + fixedLocalTransportParams + ") bool"
		fixedLocalCompleteVectorObjects(t, assembly, declaration, 1)
	})
}
