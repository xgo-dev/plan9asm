package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedWideningCompleteOfficialTransport(t *testing.T) {
	// Existing helpers keep RED in format admission, rather than compilation
	// against a future family selector. Sign and zero retain distinct rows.
	inventory := x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx, `
				PMOVSXBW PMOVSXBD PMOVSXBQ PMOVSXWD PMOVSXWQ PMOVSXDQ
				PMOVZXBW PMOVZXBD PMOVZXBQ PMOVZXWD PMOVZXWQ PMOVZXDQ
				VPMOVSXBW VPMOVSXBD VPMOVSXBQ VPMOVSXWD VPMOVSXWQ VPMOVSXDQ
				VPMOVZXBW VPMOVZXBD VPMOVZXBQ VPMOVZXWD VPMOVZXWQ VPMOVZXDQ`)
		}, `^V?PMOV(SX|ZX)(BW|BD|BQ|WD|WQ|DQ)$`, `a^`, x86PackedRowCounts{
			names: 24, rows: [3]int{12, 24, 72}, formats: [3]int{24, 48, 216}, widths: [3]int{120, 96, 72},
		})
	masked, zeroing, memory := 0, 0, 0
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			operands := strings.Split(strings.Fields(witness.Instruction)[1], ",")
			if witness.First != operands[0] || witness.First == "" || witness.Broadcast || witness.MaskResult ||
				witness.Memory != (witness.First == "(AX)") ||
				witness.Generation == "legacy" && witness.Second != witness.Destination ||
				witness.Generation != "legacy" && witness.Second != "" {
				t.Fatal("widening syntax confused source, destination or numerical input roles", row.ID, witness)
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
	if masked != 144 || zeroing != 72 || memory != 144 {
		t.Fatal("complete widening mask/zero/memory controls changed", masked, zeroing, memory)
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"PMOVSXBW X0,X1", []byte{0x66, 0x0f, 0x38, 0x20, 0xc8}},
		{"PMOVZXBQ (AX),X1", []byte{0x66, 0x0f, 0x38, 0x32, 0x08}},
		{"VPMOVSXBW X0,Y2", []byte{0xc4, 0xe2, 0x7d, 0x20, 0xd0}},
		{"VPMOVZXDQ (AX),Y2", []byte{0xc4, 0xe2, 0x7d, 0x35, 0x10}},
		{"VPMOVSXBW Y16,Z18", []byte{0x62, 0xa2, 0x7d, 0x48, 0x20, 0xd0}},
		{"VPMOVSXBQ X16,Z18", []byte{0x62, 0xa2, 0x7d, 0x48, 0x22, 0xd0}},
		{"VPMOVZXDQ.Z (AX),K1,Z18", []byte{0x62, 0xe2, 0x7d, 0xc9, 0x35, 0x10}},
	})
}

func TestX86PackedWideningAVXIndependentCarriersAndTuples(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx, `
				VPMOVSXBW VPMOVSXBD VPMOVSXBQ VPMOVSXWD VPMOVSXWQ VPMOVSXDQ
				VPMOVZXBW VPMOVZXBD VPMOVZXBQ VPMOVZXWD VPMOVZXWQ VPMOVZXDQ`)
		}, `^VPMOV(SX|ZX)(BW|BD|BQ|WD|WQ|DQ)$`, `a^`, x86PackedRowCounts{
			names: 12, rows: [3]int{0, 24, 72}, formats: [3]int{0, 48, 216}, widths: [3]int{96, 96, 72},
		})
	bytes := map[byte]int{'B': 1, 'W': 2, 'D': 4, 'Q': 8}
	for _, row := range inventory.avx {
		if !inventory.names[row.Opcode] {
			continue
		}
		n := len(row.Opcode)
		ratio := bytes[row.Opcode[n-1]] / bytes[row.Opcode[n-2]]
		width := map[string]int{"Yxr": 128, "YxrEvex": 128, "Yyr": 256, "YyrEvex": 256, "Yzr": 512}[row.Classes[len(row.Classes)-1]]
		kind, source := "vex", "Yxm"
		if width/8/ratio > 16 {
			source = "Yym"
		}
		if strings.HasPrefix(row.ZCase, "Zevex_") {
			kind, source = "evex", source+"Evex"
			want := fmt.Sprintf("evexN%d|evexZeroingEnabled", width/8/ratio)
			if strings.Join(strings.Fields(row.OpBytes[row.EncodingOffset+1]), "") != want {
				t.Fatal("widening lost its shrinking tuple or gained foreign access controls", row)
			}
		}
		wantHeader := fmt.Sprintf("avxEscape|%s%d|%s66|%s0F38|%sW0", kind, width, kind, kind, kind)
		if row.Classes[0] != source || strings.Join(strings.Fields(row.OpBytes[row.EncodingOffset]), "") != wantHeader {
			t.Fatal("widening inferred destination width from its smaller source carrier", row)
		}
	}
	ySources, differentBanks := 0, 0
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			if witness.Memory {
				continue
			}
			n := len(row.Opcode)
			ratio := bytes[row.Opcode[n-1]] / bytes[row.Opcode[n-2]]
			source, index := "X", "0"
			if witness.Width/8/ratio > 16 {
				source = "Y"
				ySources++
			}
			if witness.Generation == "evex" {
				index = "16"
			}
			if witness.First != source+index {
				t.Fatal("widening changed its physical source bank", row.ID, witness)
			}
			if source != witness.Destination[:1] {
				differentBanks++
			}
		}
	}
	if ySources != 18 || differentBanks != 84 {
		t.Fatal("widening carrier-width controls changed", ySources, differentBanks)
	}
}

func TestX86PackedWideningTransportRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"ratio two X source", "ratio eight Y source", "ratio eight larger X tuple", "full tuple", "broadcast", "SAE", "rounding", "W1", "F2", "0F map", "binary role", "binary shrinking tuple", "ABS shrinking tuple"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VPMOVSXBW", 7
			if mutation == "ratio eight Y source" || mutation == "ratio eight larger X tuple" {
				name = "VPMOVSXBQ"
			} else if mutation == "binary shrinking tuple" {
				name, index = "VPMULLD", 2
			} else if mutation == "ABS shrinking tuple" {
				name, index = "VPABSD", 2
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
				header, feature := changed.EncodingOffset, changed.EncodingOffset+1
				switch mutation {
				case "ratio two X source":
					changed.Classes[0] = "YxmEvex"
				case "ratio eight Y source":
					changed.Classes[0] = "YymEvex"
				case "ratio eight larger X tuple":
					changed.OpBytes[feature] = strings.Replace(changed.OpBytes[feature], "evexN8", "evexN16", 1)
				case "full tuple":
					changed.OpBytes[feature] = strings.Replace(changed.OpBytes[feature], "evexN32", "evexN64", 1)
				case "binary shrinking tuple", "ABS shrinking tuple":
					changed.OpBytes[feature] = strings.Replace(changed.OpBytes[feature], "evexN16", "evexN8", 1)
				case "broadcast":
					changed.OpBytes[feature] += " | evexBcstN8"
				case "SAE":
					changed.OpBytes[feature] += " | evexSaeEnabled"
				case "rounding":
					changed.OpBytes[feature] += " | evexRoundingEnabled"
				case "W1":
					changed.OpBytes[header] = strings.Replace(changed.OpBytes[header], "evexW0", "evexW1", 1)
				case "F2":
					changed.OpBytes[header] = strings.Replace(changed.OpBytes[header], "evex66", "evexF2", 1)
				case "0F map":
					changed.OpBytes[header] = strings.Replace(changed.OpBytes[header], "evex0F38", "evex0F", 1)
				case "binary role":
					changed.ZCase = "Zevex_rm_v_k_r"
				}
				if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
					t.Fatal("widening borrowed a foreign carrier, prefix, tuple or numerical source role", mutation, changed)
				}
			}
			if found != 1 {
				t.Fatal("widening negative lost its exact original source row", name, index, found)
			}
		})
	}
}
