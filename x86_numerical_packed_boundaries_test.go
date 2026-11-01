package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent operation directory; the production raw decoder does not define
// this test's members. Legal encoding, width and mask axes stay constrained.
func x86NumericalPackedBoundaryRows(arch string) []string {
	names := strings.Fields("VPADDB VPADDW VPADDD VPADDQ VPADDSB VPADDSW VPADDUSB VPADDUSW " +
		"VPSUBB VPSUBW VPSUBD VPSUBQ VPSUBSB VPSUBSW VPSUBUSB VPSUBUSW VPSHUFB " +
		"VPMULLD VPMULLQ VPMULLW VPMULHW VPMULHUW VPMULHRSW VPMULDQ VPMULUDQ " +
		"VPAVGB VPAVGW VPMADDWD VPMADDUBSW " +
		"VPMINSB VPMINUB VPMINSW VPMINUW VPMINSD VPMINUD VPMINSQ VPMINUQ " +
		"VPMAXSB VPMAXUB VPMAXSW VPMAXUW VPMAXSD VPMAXUD VPMAXSQ VPMAXUQ")
	if arch == "amd64" {
		names = append(names, "VPALIGNR") // Go's 386 frontend has no four-operand form.
	}
	var rows []string
	for _, name := range names {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, mask := range []string{"", "K1,", "K7,"} {
				if arch == "386" && mask != "" {
					continue
				}
				prefix, suffix := "", ""
				if name == "VPALIGNR" {
					prefix = "$255,"
				}
				if mask == "K7," {
					suffix = ".Z"
				}
				for _, first := range []string{bank + "0", "-128(AX)(CX*4)", "table+17(SB)"} {
					row := fmt.Sprintf("%s%s %s%s,%s1,%s%s2", name, suffix, prefix, first, bank, mask, bank)
					rows = append(rows, row)
					if arch == "amd64" && mask == "" && bank != "Z" {
						// Force the independent EVEX encoding, not a duplicate VEX spelling.
						rows = append(rows, strings.NewReplacer(bank+"0", bank+"16", bank+"1", bank+"17", bank+"2", bank+"18").Replace(row))
					}
				}
				minmax := strings.HasPrefix(name, "VPMIN") || strings.HasPrefix(name, "VPMAX")
				broadcast := name == "VPADDD" || name == "VPADDQ" || name == "VPSUBD" || name == "VPSUBQ" ||
					name == "VPMULLD" || name == "VPMULLQ" || name == "VPMULDQ" || name == "VPMULUDQ" ||
					minmax && (strings.HasSuffix(name, "D") || strings.HasSuffix(name, "Q"))
				if broadcast {
					rows = append(rows, fmt.Sprintf("%s.BCST%s table+17(SB),%s1,%s%s2", name, suffix, bank, mask, bank))
				}
			}
		}
	}
	for _, row := range x86PackedShiftRawCases() {
		if arch == "386" && row.mask != 0 {
			continue
		}
		instruction := row.instruction()
		if row.evex && arch == "amd64" {
			instruction = strings.NewReplacer("X0", "X16", "X1", "X17", "X2", "X18",
				"Y0", "Y16", "Y1", "Y17", "Y2", "Y18", "Z0", "Z16", "Z1", "Z17", "Z2", "Z18").Replace(instruction)
		}
		rows = append(rows, instruction)
		if row.input != "register" {
			rows = append(rows, strings.Replace(instruction, "(BX)", "table-17(SB)", 1),
				strings.Replace(instruction, "(BX)", "128(AX)(CX*4)", 1))
		}
	}
	if arch == "amd64" {
		for _, row := range x86ImmediateBlendCases() {
			if row.legacy {
				continue
			}
			instruction := row.instruction("255")
			rows = append(rows, instruction)
			if row.memory {
				rows = append(rows, strings.Replace(instruction, "(BX)", "table-17(SB)", 1),
					strings.Replace(instruction, "(BX)", "128(AX)(CX*4)", 1))
			}
		}
	}
	return rows
}

func TestX86NumericalPackedFamiliesOriginalPhysicalBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86NumericalPackedBoundaryRows(arch)
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nCMPL AX,$1\nRET")
			mode := 64
			if arch == "386" {
				mode = 32
			}
			x86CheckNumericalFloatingBoundaries(t, code, pcs, mode, len(rows))
			t.Logf("actual Go physical boundaries: mode=%d forms=%d bytes=%d; not translation/runtime evidence", mode, len(rows), len(code))
		})
	}
}

func TestX86NumericalPackedPhysicalMemoryDoesNotGrantRawSource(t *testing.T) {
	for _, row := range []struct {
		instruction string
		decode      func([]byte, int) (Instr, int, bool, error)
	}{
		{"VPADDQ table+17(SB),Y1,Y2", decodedX86PackedIntegerArithmeticInstruction},
		{"VPSUBD.BCST.Z table-17(SB),Z17,K1,Z18", decodedX86PackedIntegerArithmeticInstruction},
		{"VPSHUFB table+17(SB),Y1,Y2", decodedX86VPSHUFBInstruction},
		{"VPSHUFB.Z table-17(SB),Z17,K1,Z18", decodedX86VPSHUFBInstruction},
		{"VPALIGNR $255,table+17(SB),Y1,Y2", decodedX86PackedAlignRightInstruction},
		{"VPALIGNR.Z $255,table-17(SB),Z17,K1,Z18", decodedX86PackedAlignRightInstruction},
		{"VPSRLQ table+17(SB),Y1,Y2", decodedX86PackedUniformShiftInstruction},
		{"VPSRAQ.BCST.Z $255,table-17(SB),K1,Z18", decodedX86PackedUniformShiftInstruction},
		{"VPSLLVQ table+17(SB),Y1,Y2", decodedX86PerLaneVariableShiftInstruction},
		{"VPSRAVD.BCST.Z table-17(SB),Z17,K1,Z18", decodedX86PerLaneVariableShiftInstruction},
		{"VPSLLDQ $255,table+17(SB),X18", decodedX86RawVectorByteShiftInstruction},
		{"VPSRLDQ $255,table-17(SB),Z18", decodedX86RawVectorByteShiftInstruction},
		{"VPAVGB table+17(SB),Y1,Y2", decodedX86PackedAverageInstruction},
		{"VPAVGW.Z table-17(SB),Z17,K1,Z18", decodedX86PackedAverageInstruction},
		{"VPMINSD table+17(SB),Y1,Y2", decodedX86PackedIntegerMinMaxInstruction},
		{"VPMAXUQ.BCST.Z table-17(SB),Z17,K1,Z18", decodedX86PackedIntegerMinMaxInstruction},
		{"VPMULHW table+17(SB),Y1,Y2", decodedX86PackedMultiplyInstruction},
		{"VPMULLQ.BCST.Z table-17(SB),Z17,K1,Z18", decodedX86PackedMultiplyInstruction},
		{"VPMULDQ table+17(SB),Y1,Y2", decodedX86DwordToQwordMultiplyInstruction},
		{"VPMULUDQ.BCST.Z table-17(SB),Z17,K1,Z18", decodedX86DwordToQwordMultiplyInstruction},
		{"VPMADDWD table+17(SB),Y1,Y2", decodedX86VEXPackedMADDInstruction},
		{"VPMADDUBSW.Z table-17(SB),Z17,K1,Z18", decodedX86EVEXPackedMADDInstruction},
		{"VPBLENDD $255,table+17(SB),Y1,Y2", decodedX86ImmediatePackedBlendInstruction},
		{"VBLENDPD $255,table-17(SB),X1,X2", decodedX86ImmediatePackedBlendInstruction},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", row.instruction+"\nRET")
			if _, _, known, err := row.decode(code, 64); !known || err == nil || !strings.Contains(err.Error(), "RIP-relative") {
				t.Fatal("default raw source decoder gained RIP authority", known, err)
			}
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, 64)
			if err != nil || len(boundaries) != 2 || boundaries[0].Length != int(pcs[1]) || len(scalar) != 1 {
				t.Fatal("physical memory observation lost full instruction or gained scalar inputs", boundaries, scalar, err)
			}
			for _, prefix := range []byte{0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x48} {
				changed := append([]byte{prefix}, code...)
				if partial, values, err := x86NumericalNativeBoundaries(changed, 64); !errors.Is(err, ErrProbeNeedsContext) || partial != nil || values != nil {
					t.Fatal("physical memory adapter accepted forbidden prefix or partial observation", prefix, err)
				}
			}
		})
	}
}
