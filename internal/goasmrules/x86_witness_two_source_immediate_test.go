package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86TwoSourceImmediateShuffleTestNames = "PALIGNR VPALIGNR SHUFPD VSHUFPD SHUFPS VSHUFPS"

func TestX86TwoSourceImmediateShuffleLegacyPrefixBoundaries(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range legacy.Optab {
		if entry.Opcode != "PALIGNR" && entry.Opcode != "SHUFPS" && entry.Opcode != "SHUFPD" {
			continue
		}
		for _, prefix := range []string{"Pq", "Pm", "Pf2", "Pf3"} {
			if prefix == entry.Prefix {
				continue
			}
			t.Run(entry.Opcode+"/"+prefix, func(t *testing.T) {
				if _, err := x86PackedLegacyRowWitnesses(entry, entry.Rows[0]); err != nil {
					t.Fatal("negative requires its valid original row", err)
				}
				bad := entry
				bad.Prefix = prefix
				if _, err := x86PackedLegacyRowWitnesses(bad, entry.Rows[0]); err == nil {
					t.Fatal("foreign legacy immediate prefix accepted", bad)
				}
			})
			checked++
		}
	}
	if checked != 9 {
		t.Fatal("legacy prefix negative denominator changed", checked)
	}
}

func TestX86TwoSourceImmediateShuffleCompleteOriginalRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, name := range strings.Fields(x86TwoSourceImmediateShuffleTestNames) {
		names[name] = true
	}
	type original struct {
		kind    string
		classes []string
		masked  bool
	}
	originals := map[string]original{}
	for _, entry := range legacy.Optab {
		if !names[entry.Opcode] {
			continue
		}
		for _, row := range entry.Rows {
			if strings.Join(row.Classes, ",") != "Yu8,Yxm,Yxr" || row.ZCase != "Zibm_r" || row.RowIndex != 0 {
				t.Fatal("legacy two-source immediate acquired a foreign/MMX row", entry, row)
			}
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			originals[id] = original{"legacy", row.Classes, false}
		}
	}
	for index, row := range avx {
		if !names[row.Opcode] {
			continue
		}
		kind := "vex"
		if strings.HasPrefix(row.ZCase, "Zevex_") {
			kind = "evex"
		}
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)
		originals[id] = original{kind, row.Classes, row.ZCase == "Zevex_i_rm_v_k_r"}
	}
	if len(originals) != 27 {
		t.Fatal("complete six-name original source denominator changed", len(originals))
	}
	// Existing helper only: do not manufacture missing-API compile RED.
	rows, err := x86PackedBinaryRows(legacy, avx, x86TwoSourceImmediateShuffleTestNames)
	if err != nil {
		t.Fatal(err)
	}
	seen, instructions := map[string]bool{}, map[string]bool{}
	rowKinds, formats, widths := map[string]int{}, map[string]int{}, map[int]int{}
	masked, zeroing, broadcast, memory := 0, 0, 0, 0
	for _, row := range rows {
		from, found := originals[row.ID]
		if !found || seen[row.ID] {
			t.Fatal("two-source immediate lost original row identity", row)
		}
		seen[row.ID] = true
		rowKinds[from.kind]++
		width := map[string]int{"Yxm": 128, "Yym": 256, "YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[from.classes[1]]
		bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[width]
		first, second, destination := bank+"0", bank+"1", bank+"2"
		if from.kind == "legacy" {
			destination = "X1"
		}
		if from.kind == "evex" {
			first, second, destination = bank+"16", bank+"17", bank+"18"
		}
		for _, w := range row.Witnesses {
			fields := strings.Fields(w.Instruction)
			if len(fields) != 2 {
				t.Fatal("lost source syntax", w)
			}
			args := strings.Split(fields[1], ",")
			count := 4
			if from.kind == "legacy" {
				count = 3
			}
			if w.Masked {
				count++
			}
			if len(args) != count {
				t.Fatal("lost source arity", row.ID, w)
			}
			if instructions[w.Instruction] || args[0] != "$7" || w.First != args[1] || w.First != first && w.First != "(AX)" || w.Second != second || w.Destination != destination || args[len(args)-1] != destination ||
				w.Width != width || w.Generation != from.kind || w.MaskResult || w.Masked != from.masked || w.Masked && args[len(args)-2] != "K1" ||
				w.Memory != (w.First == "(AX)") || w.Zeroing != strings.HasSuffix(fields[0], ".Z") || w.Zeroing && !w.Masked ||
				w.Broadcast != strings.Contains(fields[0], ".BCST") || w.Broadcast && (!w.Memory || from.kind != "evex" || row.Opcode == "VPALIGNR") ||
				len(w.Encoding) < 4 || w.Encoding[len(w.Encoding)-1] != 7 {
				t.Fatal("immediate/source/legacy-RMW/width/mask roles were conflated", row.ID, w)
			}
			// Legacy SHUF/PALIGNR reads the literal second operand as data;
			// unary PSHUFD/HW/LW still has its existing empty Second metadata.
			if from.kind == "legacy" && w.Second != w.Destination {
				t.Fatal("legacy old destination was erased", row.ID, w)
			}
			instructions[w.Instruction] = true
			formats[from.kind]++
			widths[width]++
			if w.Masked {
				masked++
			}
			if w.Zeroing {
				zeroing++
			}
			if w.Broadcast {
				broadcast++
			}
			if w.Memory {
				memory++
			}
		}
	}
	if len(rows) != 27 || len(seen) != len(originals) || len(instructions) != 90 || rowKinds["legacy"] != 3 || rowKinds["vex"] != 6 || rowKinds["evex"] != 18 ||
		formats["legacy"] != 6 || formats["vex"] != 12 || formats["evex"] != 72 || widths[128] != 36 || widths[256] != 30 || widths[512] != 24 || masked != 48 || zeroing != 24 || broadcast != 18 || memory != 54 {
		t.Fatal("complete two-source immediate denominator changed", len(rows), len(instructions), rowKinds, formats, widths, masked, zeroing, broadcast, memory)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"PALIGNR $7,X0,X1", []byte{0x66, 0x0f, 0x3a, 0x0f, 0xc8, 0x07}},
		{"SHUFPS $7,(AX),X1", []byte{0x0f, 0xc6, 0x08, 0x07}},
		{"SHUFPD $7,X0,X1", []byte{0x66, 0x0f, 0xc6, 0xc8, 0x07}},
		{"VPALIGNR $7,Y0,Y1,Y2", []byte{0xc4, 0xe3, 0x75, 0x0f, 0xd0, 0x07}},
		{"VPALIGNR.Z $7,X16,X17,K1,X18", []byte{0x62, 0xa3, 0x75, 0x81, 0x0f, 0xd0, 0x07}},
		{"VSHUFPS.BCST.Z $7,(AX),Z17,K1,Z18", []byte{0x62, 0xe1, 0x74, 0xd1, 0xc6, 0x10, 0x07}},
		{"VSHUFPD.BCST $7,(AX),Y17,Y18", []byte{0x62, 0xe1, 0xf5, 0x30, 0xc6, 0x10, 0x07}},
	})
}

func TestX86TwoSourceImmediateShuffleRejectsForeignFormatAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"PAL BCST", "PAL W1", "PAL map", "PAL no66", "PS BCST8", "PS prefix", "PS W1", "PD BCST4", "PD W0", "signed immediate", "source carrier", "data carrier", "K result", "K0 writemask", "tuple", "rounding", "SAE", "offset", "row index", "opcode extent"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VSHUFPS", 2
			if strings.HasPrefix(mutation, "PAL ") {
				name = "VPALIGNR"
			}
			if strings.HasPrefix(mutation, "PD ") {
				name = "VSHUFPD"
			}
			if mutation == "K0 writemask" {
				index = 3
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != index {
					continue
				}
				found++
				if _, err := x86PackedAVXRowWitnesses(original); err != nil {
					t.Fatal("negative requires its valid original row", original, err)
				}
				row := original
				row.Classes = append([]string(nil), row.Classes...)
				row.OpBytes = append([]string(nil), row.OpBytes...)
				header, feature := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "PAL BCST":
					row.OpBytes[feature] += "|evexBcstN8"
				case "PAL W1", "PS W1":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW0", "evexW1", 1)
				case "PAL map":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F3A", "evex0F38", 1)
				case "PAL no66":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex66", "", 1)
				case "PS BCST8":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexBcstN4", "evexBcstN8", 1)
				case "PS prefix":
					row.OpBytes[header] += "|evex66"
				case "PD BCST4":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexBcstN8", "evexBcstN4", 1)
				case "PD W0":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW1", "evexW0", 1)
				case "signed immediate":
					row.Classes[0] = "Yi8"
				case "source carrier":
					row.Classes[1] = "YymEvex"
				case "data carrier":
					row.Classes[2] = "YyrEvex"
				case "K result":
					row.Classes[len(row.Classes)-1] = "Yk"
				case "K0 writemask":
					row.Classes[3] = "Yk"
				case "tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN8", 1)
				case "rounding":
					row.OpBytes[feature] += "|evexRoundingEnabled"
				case "SAE":
					row.OpBytes[feature] += "|evexSaeEnabled"
				case "offset":
					row.EncodingOffset++
				case "row index":
					row.RowIndex++
				case "opcode extent":
					row.OpBytes[header+2] = "256"
				}
				if fmt.Sprint(row) == fmt.Sprint(original) {
					t.Fatal("negative did not change its original row", mutation)
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("two-source immediate borrowed a foreign format", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("negative lost its exact original row", name, index, found)
			}
		})
	}
}
