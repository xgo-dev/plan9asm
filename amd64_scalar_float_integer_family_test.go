package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent Go namespace, not derived from the production conversion map.
func x86ScalarFloatIntegerOracleNames() []string {
	var names []string
	for _, precision := range []string{"SS", "SD"} {
		for _, prefix := range []string{"CVT", "CVTT"} {
			for _, width := range []string{"L", "Q"} {
				names = append(names, prefix+precision+"2S"+width)
				vwidth := ""
				if width == "Q" {
					vwidth = "Q"
				}
				names = append(names, "V"+prefix+precision+"2SI"+vwidth)
				names = append(names, "V"+prefix+precision+"2USI"+width)
			}
		}
	}
	return names
}

func TestX86ScalarFloatIntegerMode32WIGOriginalGo(t *testing.T) {
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		if !strings.HasPrefix(name, "V") || !strings.HasSuffix(name, "Q") {
			continue
		}
		for _, operand := range []string{"X0", "7(BX)"} {
			t.Run(name+"/"+operand, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-0\n%s %s,AX\nRET\n", name, operand)
				ir := x86UnboundVoidScalarFormatObject(t, source, "view", "386", "i386-unknown-linux-gnu")
				if !strings.Contains(ir, "call i32 asm sideeffect") || strings.Contains(ir, "call i64 asm sideeffect") {
					t.Fatal("actual Go W1 format lost its mode32 WIG dword output", ir)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM22 llc required")
				}
				compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "mode32-wig.ll", "mode32-wig.o", ir)
			})
		}
	}
}
