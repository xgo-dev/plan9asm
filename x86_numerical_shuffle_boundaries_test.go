package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86NumericalPackedShuffleOriginalPhysicalBoundaries(t *testing.T) {
	// The independently audited Go table contains all ten encoding rows for
	// each of the three members. Expand operand roles, not decoder output.
	original := x86OfficialImmediateShuffleRows(t)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var rows []string
			for _, row := range original {
				parts := strings.SplitN(row, " ", 2)
				args := strings.Split(parts[1], ",")
				masked := len(args) == 4
				destination := args[len(args)-1]
				if arch == "386" && (masked || strings.HasSuffix(destination, "17")) {
					// Go's 386 frontend rejects four operands; high X/Y names
					// are source-only aliases, not physical extended registers.
					continue
				}
				evex := masked || strings.HasSuffix(destination, "17") || strings.HasPrefix(destination, "Z")
				suffixes := []string{""}
				if masked {
					suffixes = append(suffixes, ".Z")
				}
				inputs := []string{args[1], "-128(AX)(CX*4)", "table+17(SB)", "table-17(SB)"}
				for index, input := range inputs {
					args[1] = input
					for _, suffix := range suffixes {
						rows = append(rows, parts[0]+suffix+" "+strings.Join(args, ","))
						if index != 0 && evex && parts[0] == "VPSHUFD" {
							rows = append(rows, parts[0]+".BCST"+suffix+" "+strings.Join(args, ","))
						}
					}
				}
			}
			want, mode := 183, 64
			if arch == "386" {
				want, mode = 63, 32
			}
			if len(rows) != want {
				t.Fatal("complete physical shuffle row denominator changed", len(rows), want)
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nCMPL AX,$1\nRET")
			if len(pcs) != len(rows)+2 {
				t.Fatal("actual Go expanded or omitted an independent row", len(pcs), len(rows)+2)
			}
			x86CheckNumericalFloatingBoundaries(t, code, pcs, mode, len(rows))
			t.Logf("actual Go physical shuffle boundaries: mode=%d forms=%d; every byte cut rejected, not translation/runtime evidence", mode, len(rows))
		})
	}
}

func TestX86NumericalPackedShufflePhysicalMemoryDoesNotGrantRawSource(t *testing.T) {
	for _, op := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		rows := []string{
			op + " $255,table+17(SB),Y1",
			op + " $255,table-17(SB),X17",
			op + ".Z $255,table-17(SB),K7,Z1",
		}
		if op == "VPSHUFD" {
			rows = append(rows, op+".BCST.Z $255,table-17(SB),K1,Y1")
		}
		for _, row := range rows {
			t.Run(row, func(t *testing.T) {
				code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row+"\nRET")
				if _, _, known, err := decodedX86PackedShuffleInstruction(code, 64); !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
					t.Fatal("default raw source decoder gained RIP authority", known, err)
				}
				boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
				if err != nil || len(boundaries) != 2 || boundaries[0].Length != int(pcs[1]) || len(scalar) != 1 {
					t.Fatal("physical shuffle observation lost complete imm8 length or gained scalar inputs", boundaries, scalar, err)
				}
				for _, prefix := range []byte{0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x48} {
					changed := append([]byte{prefix}, code...)
					if partial, values, err := x86NumericalNativeBoundaries(changed, 64); !errors.Is(err, ErrProbeNeedsContext) || partial != nil || values != nil {
						t.Fatal("physical shuffle accepted forbidden prefix or partial observation", prefix, err)
					}
				}
			})
		}
	}
}
