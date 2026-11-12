package goasmrules

import (
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedImmediateShuffleCompleteOfficialTransport(t *testing.T) {
	// PSHUFL and PSHUFD have distinct source optab entries. Preserve both;
	// neither is a frontend-only alias like PADDD.
	inventory := x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx,
				`PSHUFL PSHUFD PSHUFHW PSHUFLW VPSHUFD VPSHUFHW VPSHUFLW`)
		}, `^(PSHUF(L|D|HW|LW)|VPSHUF(D|HW|LW))$`, `^VPSHUFD$`, x86PackedRowCounts{
			names: 7, broadcast: 9,
			rows: [3]int{4, 12, 18}, formats: [3]int{8, 24, 63}, widths: [3]int{41, 33, 21},
		})
	masked, zeroing, memory := 0, 0, 0
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			operands := strings.Split(strings.Fields(witness.Instruction)[1], ",")
			if witness.First != operands[1] || witness.First == "" || witness.Second != "" ||
				witness.Memory != (witness.First == "(AX)") || witness.MaskResult {
				t.Fatal("unary immediate shuffle confused its literal, source and destination", row.ID, witness)
			}
			if witness.Masked {
				masked++
			}
			if witness.Zeroing {
				zeroing++
			}
			if witness.Memory {
				memory++
			}
		}
	}
	if masked != 42 || zeroing != 21 || memory != 52 {
		t.Fatal("shuffle mask/zero/complete memory controls changed", masked, zeroing, memory)
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PSHUFL $7,X0,X1", []byte{0x66, 0x0f, 0x70, 0xc8, 7}},
		{"PSHUFD $7,(AX),X1", []byte{0x66, 0x0f, 0x70, 0x08, 7}},
		{"PSHUFHW $7,X0,X1", []byte{0xf3, 0x0f, 0x70, 0xc8, 7}},
		{"PSHUFLW $7,(AX),X1", []byte{0xf2, 0x0f, 0x70, 0x08, 7}},
		{"VPSHUFD $7,X0,X2", []byte{0xc5, 0xf9, 0x70, 0xd0, 7}},
		{"VPSHUFHW $-1,(AX),Y2", []byte{0xc5, 0xfe, 0x70, 0x10, 255}},
		{"VPSHUFD.BCST.Z $7,(AX),K1,Z18", []byte{0x62, 0xe1, 0x7d, 0xd9, 0x70, 0x10, 7}},
		{"VPSHUFLW $7,Y16,Y18", []byte{0x62, 0xa1, 0x7f, 0x28, 0x70, 0xd0, 7}},
	})
}

func TestX86PackedImmediateShuffleAVXRegisterDestinationTransport(t *testing.T) {
	x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx, `VPSHUFD VPSHUFHW VPSHUFLW`)
		}, `^VPSHUF(D|HW|LW)$`, `^VPSHUFD$`, x86PackedRowCounts{
			names: 3, broadcast: 9,
			rows: [3]int{0, 12, 18}, formats: [3]int{0, 24, 63}, widths: [3]int{33, 33, 21},
		})
}

func TestX86PackedImmediateShuffleTransportRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"rotate extension role", "signed EVEX", "word broadcast", "tuple", "SAE", "binary F3"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VPSHUFD", 4
			if mutation == "word broadcast" {
				name = "VPSHUFHW"
			} else if mutation == "binary F3" {
				name, index = "VPMULLD", 2
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != index {
					continue
				}
				found++
				changed := original
				changed.OpBytes = append([]string(nil), original.OpBytes...)
				changed.Classes = append([]string(nil), original.Classes...)
				switch mutation {
				case "rotate extension role":
					changed.ZCase = "Zevex_i_rm_vo"
				case "signed EVEX":
					changed.Classes[0] = "Yi8"
				case "word broadcast":
					changed.OpBytes[changed.EncodingOffset+1] += " | evexBcstN4"
				case "tuple":
					changed.OpBytes[changed.EncodingOffset+1] = strings.Replace(changed.OpBytes[changed.EncodingOffset+1], "evexN16", "evexN8", 1)
				case "SAE":
					changed.OpBytes[changed.EncodingOffset+1] += " | evexSaeEnabled"
				case "binary F3":
					changed.OpBytes[changed.EncodingOffset] = strings.Replace(changed.OpBytes[changed.EncodingOffset], "evex66", "evexF3", 1)
				}
				if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
					t.Fatal("shuffle borrowed another role, memory shape or old prefix capability", mutation, changed)
				}
			}
			if found != 1 {
				t.Fatal("shuffle negative lost its exact source row", name, found)
			}
		})
	}
}
