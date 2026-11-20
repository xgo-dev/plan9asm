package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86LegacyLiteralSIMDSource(entry X86LegacyOpcode) bool {
	return entry.Ytab == "yxshuf" || entry.Ytab == "yaes"
}

// Independent source bytes follow Go's prefix switch plus PutOpBytesLit.
// The matched row's stride is not the zero-terminated literal's length.
func x86LegacyLiteralSIMDExpected(t *testing.T, entry X86LegacyOpcode) []X86PackedBinaryWitness {
	t.Helper()
	prefixes := map[string][]byte{"Pq": {0x66, 0x0f}, "Pf2": {0xf2, 0x0f}, "Pf3": {0xf3, 0x0f}, "Pm": {0x0f}, "Px": {}}
	prefix, found := prefixes[entry.Prefix]
	if !found {
		t.Fatal("unmodeled independent source prefix", entry)
	}
	encoding := append([]byte(nil), prefix...)
	for index, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil || value == 0 && index != len(entry.OpBytes)-1 {
			t.Fatal("independent source literal changed", entry, index, err)
		}
		if value != 0 {
			encoding = append(encoding, byte(value))
		}
	}
	var cases []X86PackedBinaryWitness
	for _, source := range []string{"X0", "(AX)"} {
		modrm := byte(0xc8)
		if source == "(AX)" {
			modrm = 0x08
		}
		instruction := entry.Opcode + " " + source + ",X1"
		code := append(append([]byte(nil), encoding...), modrm)
		if entry.Ytab == "yxshuf" {
			instruction = entry.Opcode + " $7," + source + ",X1"
			code = append(code, 7)
		}
		cases = append(cases, X86PackedBinaryWitness{Instruction: instruction, Destination: "X1", Encoding: code})
	}
	return cases
}

func TestX86LegacyLiteralSIMDCompleteOriginalInventory(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts, spans, ids := map[string]int{}, map[int]int{}, map[string]bool{}
	escaped := 0
	for _, entry := range catalog.Optab {
		if !x86LegacyLiteralSIMDSource(entry) {
			continue
		}
		if entry.Kind != "encoding" || len(entry.Rows) != 1 {
			t.Fatal("complete original literal SIMD entry changed", entry)
		}
		row := entry.Rows[0]
		classes, zcase := "Yxm,Yxr", "Zlitm_r"
		if entry.Ytab == "yxshuf" {
			classes, zcase = "Yu8,Yxm,Yxr", "Zibm_r"
		}
		if strings.Join(row.Classes, ",") != classes || len(row.Classes) != strings.Count(classes, ",")+1 ||
			row.RowIndex != 0 || row.ZCase != zcase || row.ZOffset != 2 || row.UnmatchedOffset != 0 {
			t.Fatal("original literal SIMD classes/stride/selection changed", entry)
		}
		id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
		if ids[id] || len(entry.OpBytes) < 2 || len(entry.OpBytes) > 4 {
			t.Fatal("original literal SIMD identity or span changed", id, entry)
		}
		ids[id] = true
		counts[entry.Ytab]++
		spans[len(entry.OpBytes)]++
		zero, err := strconv.ParseUint(entry.OpBytes[len(entry.OpBytes)-1], 0, 8)
		if err != nil || zero != 0 {
			t.Fatal("original literal SIMD terminator changed", id, err)
		}
		if entry.EscapeAdjustment != 0 {
			if entry.EscapeAdjustment != 1 || entry.Ytab != "yaes" || entry.Prefix != "Px" || entry.OpBytes[0] != "0x0f" {
				t.Fatal("original literal SIMD escape traversal changed", id, entry)
			}
			escaped++
		}
	}
	if len(ids) != 33 || counts["yxshuf"] != 23 || counts["yaes"] != 10 || spans[2] != 6 || spans[3] != 22 || spans[4] != 5 || escaped != 5 {
		t.Fatal("complete original literal SIMD union changed", len(ids), counts, spans, escaped)
	}
}

func TestX86LegacyLiteralSIMDExistingTransportCompleteBytes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Optab {
		if !x86LegacyLiteralSIMDSource(entry) {
			continue
		}
		row := entry.Rows[0]
		id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
		t.Run(id, func(t *testing.T) {
			expected := map[string]X86PackedBinaryWitness{}
			for _, witness := range x86LegacyLiteralSIMDExpected(t, entry) {
				expected[id+"/"+witness.Instruction] = witness
			}
			witnesses, err := x86PackedLegacyRowWitnesses(entry, row)
			if err != nil || len(witnesses) != 2 {
				t.Fatal("LEGACY_LITERAL_SIMD_SOURCE_TRANSPORT_FEATURE_GAP", err)
			}
			for _, witness := range witnesses {
				key := id + "/" + witness.Instruction
				want, found := expected[key]
				if !found || !bytes.Equal(want.Encoding, witness.Encoding) || want.Destination != witness.Destination {
					t.Fatal("literal SIMD transport differs from actual-Go source fixture", key, witness, want)
				}
				delete(expected, key)
			}
			if len(expected) != 0 {
				t.Fatal("literal SIMD transport omitted original source cases", id, expected)
			}
		})
	}
}

func TestX86LegacyLiteralSIMDRejectsMalformedSource(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		if !x86LegacyLiteralSIMDSource(original) {
			continue
		}
		selected := original.Rows[0]
		for _, control := range []string{"kind", "row-count", "prefix", "escape", "index", "zcase", "stride", "offset",
			"original-arity", "selected-arity", "original-index", "original-zcase", "original-stride", "original-offset",
			"original-immediate-role", "selected-immediate-role", "missing-zero", "early-zero", "tail", "nonbyte"} {
			if strings.HasSuffix(control, "immediate-role") && original.Ytab != "yxshuf" {
				continue
			}
			t.Run(original.Opcode+"/"+control, func(t *testing.T) {
				entry, row := original, selected
				entry.Rows = append([]X86LegacyOperand(nil), original.Rows...)
				entry.OpBytes = append([]string(nil), original.OpBytes...)
				switch control {
				case "kind":
					entry.Kind = "special"
				case "row-count":
					entry.Rows = append(entry.Rows, selected)
				case "prefix":
					entry.Prefix = "Pw"
				case "escape":
					entry.EscapeAdjustment++
				case "index":
					row.RowIndex++
				case "zcase":
					row.ZCase = "Zibr_m"
				case "stride":
					row.ZOffset++
				case "offset":
					row.UnmatchedOffset++
				case "original-arity":
					entry.Rows[0].Classes = []string{strings.Join(selected.Classes, ",")}
				case "selected-arity":
					row.Classes = []string{strings.Join(selected.Classes, ",")}
				case "original-index":
					entry.Rows[0].RowIndex++
				case "original-zcase":
					entry.Rows[0].ZCase = "Zibr_m"
				case "original-stride":
					entry.Rows[0].ZOffset++
				case "original-offset":
					entry.Rows[0].UnmatchedOffset++
				case "original-immediate-role":
					entry.Rows[0].Classes = append([]string(nil), selected.Classes...)
					entry.Rows[0].Classes[0] = "Yi32"
				case "selected-immediate-role":
					row.Classes = append([]string(nil), selected.Classes...)
					row.Classes[0] = "Yi32"
				case "missing-zero":
					entry.OpBytes = entry.OpBytes[:len(entry.OpBytes)-1]
				case "early-zero":
					entry.OpBytes[0] = "0"
				case "tail":
					entry.OpBytes = append(entry.OpBytes, "0")
				case "nonbyte":
					entry.OpBytes[0] = "256"
				}
				defer func() {
					if value := recover(); value != nil {
						t.Fatal("LEGACY_LITERAL_SIMD_MALFORMED_PANIC", control, value)
					}
				}()
				if witnesses, err := x86PackedLegacyRowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
					t.Fatal("LEGACY_LITERAL_SIMD_MALFORMED_ACCEPTED", control, witnesses, err)
				}
			})
		}
	}
}

func TestX86LegacyLiteralSIMDRejectsEveryLiteralAtom(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		if !x86LegacyLiteralSIMDSource(original) {
			continue
		}
		for index := 1; index < len(original.OpBytes); index++ {
			values := []string{"0", "256"}
			if index == len(original.OpBytes)-1 {
				values = []string{"1"} // Preserve the span while removing its final zero.
			}
			for _, value := range values {
				t.Run(fmt.Sprintf("%s/atom%d/%s", original.Opcode, index, value), func(t *testing.T) {
					entry := original
					entry.OpBytes = append([]string(nil), original.OpBytes...)
					entry.OpBytes[index] = value
					defer func() {
						if panicValue := recover(); panicValue != nil {
							t.Fatal("LEGACY_LITERAL_SIMD_MALFORMED_PANIC", index, value, panicValue)
						}
					}()
					if witnesses, err := x86PackedLegacyRowWitnesses(entry, entry.Rows[0]); err == nil || len(witnesses) != 0 {
						t.Fatal("LEGACY_LITERAL_SIMD_MALFORMED_ACCEPTED", index, value, witnesses, err)
					}
				})
			}
		}
	}
}

func TestX86LegacyLiteralSIMDViewKeepsCompleteIDsAndMode(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86LegacyLiteralSIMDRows(catalog, arch)
		if err != nil || len(rows) != 33 {
			t.Fatal("complete literal SIMD view changed", arch, len(rows), err)
		}
		seen, witnesses := map[string]bool{}, 0
		for _, row := range rows {
			if seen[row.ID] || len(row.Witnesses) != 2 {
				t.Fatal("literal SIMD original source identity repeated or lost a carrier", row)
			}
			seen[row.ID] = true
			witnesses += len(row.Witnesses)
		}
		if witnesses != 66 {
			t.Fatal("literal SIMD carrier witness union changed", witnesses)
		}
	}
	for _, arch := range []string{"", "arm", "arm64", "wasm"} {
		if rows, err := X86LegacyLiteralSIMDRows(catalog, arch); err == nil || len(rows) != 0 {
			t.Fatal("literal SIMD view inferred a missing or foreign x86 mode", arch, rows, err)
		}
	}
}

func TestX86LegacyLiteralSIMDLeadingEscapeRemainsClosed(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, original := range catalog.Optab {
		if original.Ytab != "yxshuf" || len(original.OpBytes) != 2 {
			continue
		}
		rows++
		for _, escape := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/escape%d", original.Opcode, escape), func(t *testing.T) {
				entry := original
				entry.OpBytes = []string{"0x0f", "0"}
				entry.EscapeAdjustment = escape
				if witnesses, err := x86PackedLegacyRowWitnesses(entry, entry.Rows[0]); err == nil || len(witnesses) != 0 {
					t.Fatal("closed old view admitted a one-atom leading escape", witnesses, err)
				}
				if encoding, err := x86LegacyLiteralSIMDEncoding(entry, entry.Rows[0]); err == nil || len(encoding) != 0 {
					t.Fatal("LEGACY_LITERAL_SIMD_PRIVATE_ESCAPE_ACCEPTED", escape, encoding, err)
				}
			})
		}
	}
	if rows != 6 {
		t.Fatal("closed placeholder source-row control inventory changed", rows)
	}
}

func TestX86PackedNarrowRowsShareBinaryWitnesses(t *testing.T) {
	x86CheckPackedRowInventory(t, X86PackedNarrowRows, `^V?PACK`, `DW$`, x86PackedRowCounts{
		names: 8, mmx: 3, broadcast: 18,
		rows: [3]int{4, 8, 24}, formats: [3]int{8, 16, 90}, widths: [3]int{46, 38, 30},
	})
}

func TestX86PackedAverageMultiplyRowsShareBinaryWitnesses(t *testing.T) {
	x86CheckPackedRowInventory(t, X86PackedAverageMultiplyRows,
		`^V?(PAVG[BW]|PMUL(LW|HW|HUW|HRSW|DQ|ULQ|UDQ)|PMADD(UBSW|WL|WD))$`,
		`^VPMUL(DQ|UDQ)$`, x86PackedRowCounts{
			names: 20, mmx: 7, broadcast: 18,
			rows: [3]int{10, 20, 60}, formats: [3]int{20, 40, 198}, widths: [3]int{106, 86, 66},
		})
}

func TestX86PackedBinaryPilotRows(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedBinaryPilotRows,
		`^V?(P(ADD|SUB)(B|W|L|D|Q|SB|SW|USB|USW)|PMULL[DQ])$`,
		`[DQ]$`, x86PackedRowCounts{
			names: 35, mmx: 7, broadcast: 54,
			rows: [3]int{17, 34, 108}, formats: [3]int{34, 68, 378}, widths: [3]int{194, 160, 126},
		})
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			if len(witness.Encoding) < 4 {
				t.Fatal("integer pilot lost its mandatory prefix or vector encoding", row.ID, witness)
			}
		}
	}
	for _, name := range []string{"PADDD", "PMULLW", "VPMULLW"} {
		if inventory.names[name] {
			t.Fatalf("alias or unmodified word multiply entered pilot: %s", name)
		}
	}
	wordMultiply := 0
	for _, entry := range inventory.legacy.Optab {
		if entry.Opcode == "PMULLW" {
			wordMultiply += len(entry.Rows)
		}
	}
	for _, row := range inventory.avx {
		if row.Opcode == "VPMULLW" {
			wordMultiply++
		}
	}
	if wordMultiply != 10 {
		t.Fatal("outside-pilot word multiply inventory changed", wordMultiply)
	}
}

func TestX86PackedBinaryRowEncodingAndFailClosed(t *testing.T) {
	rule := X86AVXRule{
		Opcode: "VPMULLD", Ytab: "_yvandnpd", Prefix: "Pavx", RowIndex: 3,
		Classes: []string{"YxmEvex", "YxrEvex", "Yknot0", "YxrEvex"},
		ZCase:   "Zevex_rm_v_k_r", ZOffset: 3,
		OpBytes: []string{"avxEscape | evex128 | evex66 | evex0F38 | evexW0", "evexN16 | evexBcstN4 | evexZeroingEnabled", "0x40"},
	}
	witnesses, err := x86PackedAVXRowWitnesses(rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(witnesses) != 6 || witnesses[0].Instruction != "VPMULLD X16,X17,K1,X18" ||
		!bytes.Equal(witnesses[0].Encoding, []byte{0x62, 0xa2, 0x75, 0x01, 0x40, 0xd0}) ||
		witnesses[5].Instruction != "VPMULLD.BCST.Z (AX),X17,K1,X18" ||
		!bytes.Equal(witnesses[5].Encoding, []byte{0x62, 0xe2, 0x75, 0x91, 0x40, 0x10}) {
		t.Fatalf("independent fixed-register EVEX expectation: %+v", witnesses)
	}
	for _, mutate := range []func(*X86AVXRule){
		func(r *X86AVXRule) { r.OpBytes[0] += " | futureFlag" },
		func(r *X86AVXRule) { r.OpBytes[0] += " | evexW1" },
		func(r *X86AVXRule) { r.OpBytes[1] += " | evexSaeEnabled" },
		func(r *X86AVXRule) { r.OpBytes[1] = strings.Replace(r.OpBytes[1], "evexN16", "evexN64", 1) },
		func(r *X86AVXRule) { r.OpBytes[2] = "opcodeConstant" },
		func(r *X86AVXRule) { r.EncodingOffset = 1 },
		func(r *X86AVXRule) { r.ZOffset = 2 },
		func(r *X86AVXRule) { r.Classes[0] = "Yxm" },
		func(r *X86AVXRule) { r.Ytab = "unknown" },
	} {
		local := rule
		local.OpBytes = append([]string(nil), rule.OpBytes...)
		local.Classes = append([]string(nil), rule.Classes...)
		mutate(&local)
		if _, err := x86PackedAVXRowWitnesses(local); err == nil {
			t.Fatalf("unmodeled official row silently accepted: %+v", local)
		}
	}
}

func TestX86PackedBinaryLegacyRowUsesSelectedPrefixOffset(t *testing.T) {
	entry := X86LegacyOpcode{Kind: "encoding", Opcode: "PADDL", Ytab: "ymm", Prefix: "Py1", OpBytes: []string{"0xfe", "Pe", "0xfe"}}
	row := X86LegacyOperand{RowIndex: 1, Classes: []string{"Yxm", "Yxr"}, ZCase: "Zm_r_xm", ZOffset: 2, UnmatchedOffset: 1}
	witnesses, err := x86PackedLegacyRowWitnesses(entry, row)
	if err != nil || len(witnesses) != 2 || !bytes.Equal(witnesses[0].Encoding, []byte{0x66, 0x0f, 0xfe, 0xc8}) ||
		!bytes.Equal(witnesses[1].Encoding, []byte{0x66, 0x0f, 0xfe, 0x08}) {
		t.Fatalf("Py1 selected XMM prefix/opcode: %+v/%v", witnesses, err)
	}
	for _, offset := range []int{0, 2, 3} {
		local := row
		local.UnmatchedOffset = offset
		if _, err := x86PackedLegacyRowWitnesses(entry, local); err == nil {
			t.Fatal("unmatched traversal offset was mistaken for a selected opcode offset", offset)
		}
	}
	entry.OpBytes[1] = "Pf2"
	if _, err := x86PackedLegacyRowWitnesses(entry, row); err == nil {
		t.Fatal("changed legacy mandatory prefix was ignored")
	}
}

func TestX86PackedIntegerMinMaxRowsShareBinaryWitnesses(t *testing.T) {
	inventory := x86CheckPackedRowInventory(t, X86PackedIntegerMinMaxRows,
		`^V?P(MIN|MAX)`, `[DQ]$`, x86PackedRowCounts{
			names: 28, broadcast: 72,
			rows: [3]int{12, 24, 96}, formats: [3]int{24, 48, 360}, widths: [3]int{168, 144, 120},
		})
	narrowEVEX := 0
	for _, row := range inventory.rows {
		for _, witness := range row.Witnesses {
			if witness.Generation == "evex" && witness.Width < 512 && !witness.Masked &&
				!witness.Broadcast && !strings.HasSuffix(row.Opcode, "Q") {
				narrowEVEX++
			}
		}
	}
	if narrowEVEX != 48 {
		t.Fatal("unmasked narrow non-Q EVEX inventory drift", narrowEVEX)
	}
}
