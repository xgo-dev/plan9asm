package goasmrules

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86PackedMoveTestRows(t *testing.T) ([]X86PackedBinaryRow, map[string]X86AVXRule) {
	t.Helper()
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := x86PackedBinaryRows(legacy, avx, `
		VMOVDQA VMOVDQU VMOVAPD VMOVAPS VMOVUPD VMOVUPS
		VMOVDQA32 VMOVDQA64 VMOVDQU8 VMOVDQU16 VMOVDQU32 VMOVDQU64`)
	if err != nil {
		t.Fatal(err)
	}
	original := make(map[string]X86AVXRule)
	for index, rule := range avx {
		if rule.Ytab == "_yvmovdqa" || rule.Ytab == "_yvmovapd" || rule.Ytab == "_yvmovdqa32" {
			original[fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)] = rule
		}
	}
	return rows, original
}

func TestX86PackedMoveRowsRetainDirectionAndTerminalControls(t *testing.T) {
	rows, original := x86PackedMoveTestRows(t)
	type counts struct {
		rows, formats                 [2]int // VEX, EVEX.
		widths                        [3]int
		copies, loads, stores, faults int
	}
	var got counts
	seen, names := make(map[string]bool), make(map[string]bool)
	for _, row := range rows {
		rule, exists := original[row.ID]
		if !exists || seen[row.ID] || len(row.Witnesses) == 0 || row.Opcode != rule.Opcode {
			t.Fatal("lost original move row identity", row)
		}
		seen[row.ID], names[row.Opcode] = true, true
		store := strings.HasPrefix(rule.ZCase, "Zvex_r_") || strings.HasPrefix(rule.ZCase, "Zevex_r_")
		generation := 0
		if strings.HasPrefix(rule.ZCase, "Zevex_") {
			generation = 1
		}
		got.rows[generation]++
		for _, witness := range row.Witnesses {
			if witness.Memory != (witness.First == "(AX)") || witness.Second != "" || witness.Broadcast || witness.MaskResult {
				t.Fatal("move direction changed source-only Memory or invented a second source", row.ID, witness)
			}
			if witness.Masked != (len(rule.Classes) == 3) || witness.Zeroing && !witness.Masked || len(witness.Encoding) < 4 {
				t.Fatal("move lost its mask, zeroing or physical bytes", row.ID, witness)
			}
			width, valid := map[int]int{128: 0, 256: 1, 512: 2}[witness.Width]
			if !valid || (witness.Generation == "evex") != (generation == 1) {
				t.Fatal("move width/generation changed", row.ID, witness)
			}
			got.formats[generation]++
			got.widths[width]++
			switch {
			case witness.Memory:
				if store {
					t.Fatal("store row acquired a load witness", row.ID, witness)
				}
				got.loads++
			case witness.Destination == "(AX)":
				if !store {
					t.Fatal("load row acquired a store witness", row.ID, witness)
				}
				if witness.Zeroing {
					got.faults++ // Go accepts these bytes; normal value execution is #UD.
				} else {
					got.stores++
				}
			default:
				if !store {
					t.Fatal("load-row register alternative falsely claims first-match ownership", row.ID, witness)
				}
				got.copies++
			}
		}
	}
	want := counts{rows: [2]int{24, 120}, formats: [2]int{36, 270}, widths: [3]int{108, 108, 90}, copies: 102, loads: 102, stores: 72, faults: 30}
	if len(rows) != 144 || len(seen) != len(original) || len(names) != 12 || got != want {
		t.Fatal("AVX-only move row/candidate denominator drift", len(rows), len(original), len(names), got, want)
	}
}

func TestX86PackedMoveLoadRegisterAlternativesRetainSelectedStoreRows(t *testing.T) {
	rows, original := x86PackedMoveTestRows(t)
	owners := make(map[string]string)
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			if !witness.Memory && witness.Destination != "(AX)" {
				if owners[witness.Instruction] != "" {
					t.Fatal("physical register witness has duplicate row owners", witness.Instruction)
				}
				owners[witness.Instruction] = row.ID
			}
		}
	}
	selections := 0
	for wantedID, rule := range original {
		if !strings.HasPrefix(rule.ZCase, "Zvex_rm_") && !strings.HasPrefix(rule.ZCase, "Zevex_rm_") {
			continue
		}
		bank := strings.ToUpper(rule.Classes[0][1:2])
		first, destination := bank+"0", bank+"2"
		if strings.HasPrefix(rule.ZCase, "Zevex_") {
			first, destination = bank+"16", bank+"18"
		}
		mask, suffixes := "", []string{""}
		if len(rule.Classes) == 3 {
			mask, suffixes = ",K1", []string{"", ".Z"}
		}
		for _, suffix := range suffixes {
			instruction := rule.Opcode + suffix + " " + first + mask + "," + destination
			selectedID := owners[instruction]
			selected, exists := original[selectedID]
			if !exists || selectedID == wantedID || selected.RowIndex >= rule.RowIndex || selected.Opcode != rule.Opcode || len(selected.Classes) != len(rule.Classes) ||
				selected.Classes[0] != rule.Classes[len(rule.Classes)-1] || selected.Classes[len(selected.Classes)-1] != rule.Classes[0] ||
				!strings.HasPrefix(selected.ZCase, strings.Split(rule.ZCase, "_")[0]+"_r_") {
				t.Fatal("load row lost its separately selected register alternative", wantedID, instruction, selectedID)
			}
			selections++
		}
	}
	if len(owners) != 102 || selections != 102 {
		t.Fatal("shadow selections were dropped or counted as additional physical witnesses", len(owners), selections)
	}
}

func x86PackedMoveStoreFixture() X86AVXRule {
	return X86AVXRule{Opcode: "VMOVDQU16", Ytab: "_yvmovdqa32", Prefix: "Pavx", RowIndex: 3,
		Classes: []string{"YyrEvex", "Yknot0", "YymEvex"}, ZCase: "Zevex_r_k_rm", ZOffset: 3,
		OpBytes: []string{"avxEscape | evex256 | evexF2 | evex0F | evexW1", "evexN32 | evexZeroingEnabled", "0x7F"}}
}

func TestX86PackedMoveRowBytesUseDirectionAndMoveOnlyPrefixes(t *testing.T) {
	rule := X86AVXRule{Opcode: "VMOVUPS", Ytab: "_yvmovapd", Prefix: "Pavx", Classes: []string{"Yxr", "Yxm"},
		ZCase: "Zvex_r_v_rm", ZOffset: 2, OpBytes: []string{"avxEscape | vex128 | vex0F | vexW0", "0x11"}}
	witnesses, err := x86PackedAVXRowWitnesses(rule)
	if err != nil || len(witnesses) != 2 || witnesses[0].Instruction != "VMOVUPS X0,X2" ||
		!bytes.Equal(witnesses[0].Encoding, []byte{0xc5, 0xf8, 0x11, 0xc2}) ||
		witnesses[1].Instruction != "VMOVUPS X0,(AX)" || !bytes.Equal(witnesses[1].Encoding, []byte{0xc5, 0xf8, 0x11, 0x00}) {
		t.Fatal("store direction reused load ModRM roles", witnesses, err)
	}
	witnesses, err = x86PackedAVXRowWitnesses(x86PackedMoveStoreFixture())
	if err != nil || len(witnesses) != 4 || witnesses[0].Instruction != "VMOVDQU16 Y16,K1,Y18" ||
		!bytes.Equal(witnesses[0].Encoding, []byte{0x62, 0xa1, 0xff, 0x29, 0x7f, 0xc2}) ||
		witnesses[3].Instruction != "VMOVDQU16.Z Y16,K1,(AX)" || witnesses[3].Memory ||
		!bytes.Equal(witnesses[3].Encoding, []byte{0x62, 0xe1, 0xff, 0xa9, 0x7f, 0x00}) {
		t.Fatal("F2/W1 store or terminal EVEX.z identity changed", witnesses, err)
	}
	for _, prefix := range []string{"vexF2", "vexF3"} {
		binary := X86AVXRule{Opcode: "VPMULLD", Ytab: "_yvandnpd", Prefix: "Pavx", Classes: []string{"Yxm", "Yxr", "Yxr"},
			ZCase: "Zvex_rm_v_r", ZOffset: 2, OpBytes: []string{"avxEscape | vex128 | " + prefix + " | vex0F38 | vexW0", "0x40"}}
		if _, err := x86PackedAVXRowWitnesses(binary); err == nil {
			t.Fatal("move-only pp widened the old binary grammar", prefix)
		}
	}
}

func TestX86PackedMoveRowRejectsUnauditedAxes(t *testing.T) {
	for _, edit := range []func(*X86AVXRule){
		func(r *X86AVXRule) { r.Ytab = "unknown" },
		func(r *X86AVXRule) { r.ZCase = "Zevex_rm_k_r" },
		func(r *X86AVXRule) { r.Classes[0] = "YymEvex" },
		func(r *X86AVXRule) { r.Classes[1] = "Yk" },
		func(r *X86AVXRule) { r.Classes[2] = "YxmEvex" },
		func(r *X86AVXRule) { r.ZOffset = 0 },
		func(r *X86AVXRule) { r.EncodingOffset = 1 },
		func(r *X86AVXRule) { r.OpBytes[0] += " | evexF3" },
		func(r *X86AVXRule) { r.OpBytes[0] += " | evex66" },
		func(r *X86AVXRule) { r.OpBytes[0] += " | futureFlag" },
		func(r *X86AVXRule) { r.OpBytes[1] += " | evexBcstN4" },
		func(r *X86AVXRule) { r.OpBytes[1] += " | evexRoundingEnabled" },
		func(r *X86AVXRule) { r.OpBytes[1] += " | evexSaeEnabled" },
		func(r *X86AVXRule) { r.OpBytes[1] = "evexN64 | evexZeroingEnabled" },
	} {
		rule := x86PackedMoveStoreFixture()
		before := rule
		before.OpBytes, before.Classes = append([]string(nil), rule.OpBytes...), append([]string(nil), rule.Classes...)
		edit(&rule)
		if witnesses, err := x86PackedAVXRowWitnesses(rule); err == nil || len(witnesses) != 0 {
			t.Fatal("unknown move direction or attribute silently accepted", witnesses, err)
		}
		if reflect.DeepEqual(rule, before) {
			t.Fatal("negative control did not mutate its row")
		}
	}
}
