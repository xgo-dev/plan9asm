package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86NumericalScalarLaneOriginalPhysicalBoundaries(t *testing.T) {
	var rows []string
	for _, encoding := range []string{"legacy", "VEX", "EVEX"} {
		prefix, base, destination := "", "X1", "X2"
		if encoding != "legacy" {
			prefix = "V"
		}
		if encoding == "EVEX" {
			base, destination = "X20", "X21"
		}
		for _, suffix := range []string{"B", "W", "D", "Q"} {
			for _, transfer := range []string{"AX", "11(BX)(CX*2)", "table+7(SB)", "11(BX)(FS)"} {
				insert := fmt.Sprintf("%sPINSR%s $255,%s,%s", prefix, suffix, transfer, base)
				if prefix != "" {
					insert += "," + destination
				}
				rows = append(rows, insert, fmt.Sprintf("%sPEXTR%s $255,%s,%s", prefix, suffix, base, transfer))
			}
		}
		if prefix != "" {
			// This sibling shares the complete scalar-extract decoder.
			for _, transfer := range []string{"AX", "11(BX)(CX*2)", "table+7(SB)", "11(BX)(FS)"} {
				rows = append(rows, fmt.Sprintf("VEXTRACTPS $255,%s,%s", base, transfer))
			}
		}
	}
	if len(rows) != 104 {
		t.Fatal("complete scalar-lane physical source inventory changed", len(rows))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(rows, "\n")+"\nRET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("original Go instruction inventory changed", len(pcs), len(rows))
	}
	for index, row := range rows {
		t.Run(row, func(t *testing.T) {
			instruction := code[pcs[index]:pcs[index+1]]
			boundaries, scalar, err := x86NumericalNativeBoundaries(instruction, 64)
			vector := strings.HasPrefix(row, "V")
			if err != nil || len(boundaries) != 1 || boundaries[0].Length != len(instruction) ||
				vector && len(scalar) != 0 || !vector && len(scalar) != 1 {
				t.Fatalf("original scalar-lane boundary %x: %v %v %v", instruction, boundaries, scalar, err)
			}
			for cut := 1; cut < len(instruction); cut++ {
				if boundaries, scalar, err := x86NumericalNativeBoundaries(instruction[:cut], 64); err == nil || boundaries != nil || scalar != nil {
					t.Fatal("truncated scalar-lane instruction acquired a complete observation", cut, boundaries, scalar, err)
				}
			}
			if vector && strings.Contains(row, "(SB)") {
				decode := decodedX86PackedScalarExtractInstruction
				if strings.Contains(row, "PINSR") {
					decode = decodedX86VPINSRInstruction
					if instruction[0] == 0x62 {
						decode = decodedX86EVEXVPINSRInstruction
					}
				}
				if _, _, known, err := decode(instruction, 64); !known || err == nil {
					t.Fatal("physical RIP boundary granted raw source-layout permission", row, known, err)
				}
			}
		})
	}
}

func TestX86NumericalScalarLanePhysicalBoundaryGuards(t *testing.T) {
	for _, row := range []string{"VPINSRB $0,AX,X1,X2", "VPINSRW $0,AX,X1,X2", "VPINSRQ $0,AX,X20,X21", "VPEXTRB $0,X1,AX", "VPEXTRW $0,X20,AX"} {
		code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row+"\nRET")
		original := code[:pcs[1]]
		for _, mutation := range []string{"vector length", "address override", "mandatory prefix"} {
			t.Run(row+"/"+mutation, func(t *testing.T) {
				changed := append([]byte(nil), original...)
				prefix := 2
				if changed[0] == 0xc5 {
					prefix = 1
				}
				switch mutation {
				case "vector length":
					if changed[0] == 0x62 {
						changed[3] |= 0x20
					} else {
						changed[prefix] |= 4
					}
				case "address override":
					changed = append([]byte{0x67}, changed...)
				case "mandatory prefix":
					changed[prefix] &^= 3
				}
				if boundaries, scalar, err := x86NumericalNativeBoundaries(changed, 64); err == nil || boundaries != nil || scalar != nil {
					t.Fatal("invalid encoding acquired complete native boundaries", mutation, boundaries, scalar, err)
				}
			})
		}
	}
}
