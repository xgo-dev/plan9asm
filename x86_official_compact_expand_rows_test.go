package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialCompactExpandRowsThreeAPIsObjectsAndTerminalFaults(t *testing.T) {
	cases := x86OfficialPackedRowsObjectsInspect(t, goasmrules.X86CompactExpandRows, 72, 216, 0,
		x86OfficialMoveAssembly, x86OfficialMoveInspectFaults)
	terminal := 0
	for _, fixture := range cases {
		if fixture.witness.Zeroing && fixture.witness.Destination == "(AX)" {
			terminal++
		}
	}
	if terminal != 18 || len(cases)-terminal != 198 {
		t.Fatal("ordinary compact continuations and terminal memory zeroing were conflated", len(cases), terminal)
	}
}

// These independent nonzero addresses observe Go's actual compressed disp8.
// They supplement the canonical 216 witnesses without adding source authority.
func TestX86OfficialCompactExpandElementDisplacementActualGoBytes(t *testing.T) {
	var source strings.Builder
	var cases []x86OfficialPackedCase
	for _, direction := range []string{"COMPRESS", "EXPAND"} {
		for index, member := range []string{"B", "W", "D", "Q"} {
			name := fmt.Sprintf("CompactDisp%d", len(cases))
			op := "VP" + direction + member
			instruction := op + " X16,K1,16(AX)"
			p1, opcode, modrm := byte(0x7d), byte(0x63), byte(0x40)
			if index&1 != 0 {
				p1 |= 0x80
			}
			if index >= 2 {
				opcode = 0x8b
			}
			if direction == "EXPAND" {
				instruction, opcode, modrm = op+" 16(AX),K1,X18", 0x62, 0x50
				if index >= 2 {
					opcode = 0x89
				}
			}
			line := strings.Count(source.String(), "\n") + 2
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, instruction)
			cases = append(cases, x86OfficialPackedCase{
				row: "independent/element-disp8/" + op, symbol: name, line: line,
				witness: goasmrules.X86PackedBinaryWitness{
					Instruction: instruction,
					Encoding:    []byte{0x62, 0xe2, p1, 0x09, opcode, modrm, byte(16 >> index)},
				},
			})
		}
	}
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source.String())
	if err != nil {
		t.Fatal("actual Go element-disp8 anchor failed", err)
	}
	if len(cases) != 8 {
		t.Fatal("both directions need all four actual element scales", len(cases))
	}
	if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
		t.Fatal("compressed displacement used vector width or mask population instead of the element scale", err)
	}
}
