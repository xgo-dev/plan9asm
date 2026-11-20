package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86X87ENVLogicalBytesCannotImpersonateNativeBacking(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		var initializedAUTO strings.Builder
		for offset := -28; offset < 0; offset += 4 {
			fmt.Fprintf(&initializedAUTO, "MOVL $0,env%d(SP)\n", offset)
		}
		for _, row := range []struct {
			name, declaration, prefix, read string
			frame                           int
			good                            bool
		}{
			{"separate-FP-fields", "func Value(a,b,c,d,e,f,g uint32) uint16", "", "a+0(FP)", 0, false},
			{"initialized-AUTO", "func Value() uint16", initializedAUTO.String(), "env-28(SP)", 32, false},
			{"actual-pointer", "func Value(env *byte) uint16", move + " env+0(FP),BX\n", "(BX)", 0, true},
			{"NUM-is-not-pointer", "func Value(env *byte) uint16", move + " $32,BX\n", "(BX)", 0, false},
			{"physical-SP", "func Value() uint16", "", "0(SP)", 0, false},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				_, _, sig, _ := x86ResultInitializationFixture(t, arch, row.declaration, "RET")
				if len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Type != I16 {
					t.Fatal("actual typed result layout changed")
				}
				result := sig.Frame.Results[0].Offset
				source := fmt.Sprintf("TEXT ·Value(SB),4,$%d-%d\n%sFLDENV %s\nFCLEX\nXORL AX,AX\nFSTSW AX\nMOVW AX,ret+%d(FP)\nFINIT\nRET\n",
					row.frame, result+2, row.prefix, row.read, result)
				ir, err := x86X87InitializedWordAPI(t, source, row.declaration, arch, triple, "text", X87Software)
				if row.good {
					if err != nil || ir == "" {
						t.Fatal("actual reaching-pointer control rejected", err)
					}
					return
				}
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("logical initialized bytes supplied an unproved native ENV backing: output=%t error=%v", ir != "", err)
				}
				// This is a source-role boundary, not a claim that the Go
				// assembler rejects the syntax or that a later guard ran.
				t.Logf("FIRST_CONTEXT %s: %v", row.name, err)
			})
		}
	}
}
