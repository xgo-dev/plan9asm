package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalUnalignedTransportCandidateRoles(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", "RET")
	for _, opcode := range []string{"MOVOU", "MOVUPS", "MOVUPD", "VMOVDQU", "VMOVUPS", "VMOVUPD",
		"VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
		for _, direction := range []string{"load", "store"} {
			for _, row := range []struct {
				address string
				want    bool
			}{
				{"16(SP)", true}, {"(SP)", true}, {"16(BP)", true},
				{"spill-16(SP)", false}, {"spill-(8+8)(SP)", false},
				{"input+0(FP)", false}, {"(AX)", false}, {"constant<>(SB)", false},
			} {
				name := fmt.Sprintf("%s/%s/%s", opcode, direction, row.address)
				t.Run(name, func(t *testing.T) {
					operands := row.address + ",X0"
					if direction == "store" {
						operands = "X0," + row.address
					}
					source := "TEXT ·Value(SB),4,$160-8\n" + opcode + " " + operands +
						"\nMOVQ X0,AX\nMOVQ AX,ret0+0(FP)\nRET\n"
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					if got := GoAMD64FixedLocalFrameBindingNeeded(file, "amd64"); got != row.want {
						t.Fatalf("physical scratch query = %v, want %v", got, row.want)
					}
					if GoAMD64FixedLocalFrameBindingNeeded(file, "386") {
						t.Fatal("AMD64 source observer claimed mode32 backing")
					}
					if row.want {
						_, err := Translate(file, Options{
							Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
							Sigs:       map[string]FuncSig{"Value": sig},
							ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
						})
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("candidate query supplied backing or initialized bytes: %v", err)
						}
					}
				})
			}
		}
	}
}
