package goasmrules

import (
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedDuplicateCompleteOfficialTransport(t *testing.T) {
	// Existing helpers keep the initial failure in format admission, rather
	// than compilation against a future family selector.
	inventory := x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx,
				`MOVDDUP MOVSHDUP MOVSLDUP VMOVDDUP VMOVSHDUP VMOVSLDUP`)
		}, `^V?MOV(D|SH|SL)DUP$`, `a^`, x86PackedRowCounts{
			names: 6, rows: [3]int{3, 6, 18}, formats: [3]int{6, 12, 54}, widths: [3]int{30, 24, 18},
		})
	masked, zeroing, memory := 0, 0, 0
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			if witness.Generation == "legacy" && witness.Second != witness.Destination ||
				witness.Generation != "legacy" && witness.Second != "" ||
				witness.First == "" || witness.Memory != (witness.First == "(AX)") || witness.MaskResult {
				t.Fatal("duplicate unary syntax acquired a numerical second source or mask result", row.ID, witness)
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
	if masked != 36 || zeroing != 18 || memory != 36 {
		t.Fatal("duplicate mask/zero/source controls changed", masked, zeroing, memory)
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"MOVDDUP (AX),X1", []byte{0xf2, 0x0f, 0x12, 0x08}},
		{"MOVSHDUP X0,X1", []byte{0xf3, 0x0f, 0x16, 0xc8}},
		{"MOVSLDUP (AX),X1", []byte{0xf3, 0x0f, 0x12, 0x08}},
		{"VMOVDDUP X0,X2", []byte{0xc5, 0xfb, 0x12, 0xd0}},
		{"VMOVSLDUP (AX),Y2", []byte{0xc5, 0xfe, 0x12, 0x10}},
		{"VMOVDDUP X16,X18", []byte{0x62, 0xa1, 0xff, 0x08, 0x12, 0xd0}},
		{"VMOVSHDUP.Z (AX),K1,Z18", []byte{0x62, 0xe1, 0x7e, 0xc9, 0x16, 0x10}},
	})
}

func TestX86PackedDuplicateAVXPrefixesAndTupleTransport(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t,
		func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
			return x86PackedBinaryRows(legacy, avx, `VMOVDDUP VMOVSHDUP VMOVSLDUP`)
		}, `^VMOV(D|SH|SL)DUP$`, `a^`, x86PackedRowCounts{
			names: 3, rows: [3]int{0, 6, 18}, formats: [3]int{0, 12, 54}, widths: [3]int{24, 24, 18},
		})
	for _, row := range inventory.avx {
		if row.Opcode != "VMOVDDUP" && row.Opcode != "VMOVSHDUP" && row.Opcode != "VMOVSLDUP" {
			continue
		}
		stride, feature, prefix := 2, "", "vexF3"
		if strings.HasPrefix(row.ZCase, "Zevex_") {
			stride, prefix = 3, "evexF3"
			feature = []string{"evexN16", "evexN32", "evexN64"}[(row.RowIndex-2)/2]
		}
		if row.Opcode == "VMOVDDUP" {
			prefix = strings.Replace(prefix, "F3", "F2", 1)
			if row.RowIndex == 2 || row.RowIndex == 3 {
				feature = "evexN8"
			}
		}
		if !hasEncodingTerm(row.OpBytes[row.EncodingOffset], prefix) ||
			feature != "" && row.OpBytes[row.EncodingOffset+1] != feature+" | evexZeroingEnabled" ||
			row.ZOffset != stride && row.ZOffset != 0 {
			t.Fatal("duplicate prefixes or complete native source tuple changed", row)
		}
	}
}

func TestX86PackedDuplicateTransportRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"DDUP full tuple", "SHDUP narrow tuple", "broadcast", "SAE", "rounding", "binary F2", "ABS F3"} {
		t.Run(mutation, func(t *testing.T) {
			name := "VMOVDDUP"
			if mutation == "SHDUP narrow tuple" {
				name = "VMOVSHDUP"
			} else if mutation == "binary F2" {
				name = "VPMULLD"
			} else if mutation == "ABS F3" {
				name = "VPABSD"
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != 2 {
					continue
				}
				found++
				changed := original
				changed.OpBytes = append([]string(nil), original.OpBytes...)
				feature := changed.EncodingOffset + 1
				switch mutation {
				case "DDUP full tuple":
					changed.OpBytes[feature] = strings.Replace(changed.OpBytes[feature], "evexN8", "evexN16", 1)
				case "SHDUP narrow tuple":
					changed.OpBytes[feature] = strings.Replace(changed.OpBytes[feature], "evexN16", "evexN8", 1)
				case "broadcast":
					changed.OpBytes[feature] += " | evexBcstN8"
				case "SAE":
					changed.OpBytes[feature] += " | evexSaeEnabled"
				case "rounding":
					changed.OpBytes[feature] += " | evexRoundingEnabled"
				case "binary F2":
					changed.OpBytes[changed.EncodingOffset] = strings.Replace(changed.OpBytes[changed.EncodingOffset], "evex66", "evexF2", 1)
				case "ABS F3":
					changed.OpBytes[changed.EncodingOffset] = strings.Replace(changed.OpBytes[changed.EncodingOffset], "evex66", "evexF3", 1)
				}
				if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
					t.Fatal("duplicate format borrowed another tuple or broadened an old family", mutation, changed)
				}
			}
			if found != 1 {
				t.Fatal("foreign-axis control lost its exact original row", name, found)
			}
		})
	}
}
