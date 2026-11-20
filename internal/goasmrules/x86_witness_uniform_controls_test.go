package goasmrules

import (
	"runtime"
	"strings"
	"testing"
)

func TestX86UniformByteShiftRejectsUnknownAVXFormatAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	seed := func(op string, row int) X86AVXRule {
		for _, rule := range rules {
			if rule.Opcode == op && rule.RowIndex == row {
				rule.Classes = append([]string(nil), rule.Classes...)
				rule.OpBytes = append([]string(nil), rule.OpBytes...)
				return rule
			}
		}
		t.Fatalf("original official row absent: %s/%d", op, row)
		return X86AVXRule{}
	}
	for _, row := range []struct {
		name, op string
		index    int
		change   func(*X86AVXRule)
	}{
		{"extension-is-not-register", "VPSLLD", 9, func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+3] = "8" }},
		{"unmasked-row-stride", "VPSLLD", 8, func(r *X86AVXRule) { r.ZOffset = 4 }},
		{"uniform-m128-not-data-width", "VPSLLD", 14, func(r *X86AVXRule) {
			r.OpBytes[r.EncodingOffset+1] = strings.ReplaceAll(r.OpBytes[r.EncodingOffset+1], "evexN16", "evexN32")
		}},
		{"uniform-count-not-Y", "VPSLLD", 14, func(r *X86AVXRule) { r.Classes[0] = "YymEvex" }},
		{"uniform-count-no-BCST", "VPSLLD", 14, func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+1] += " | evexBcstN4" }},
		{"VPSRAQ-count-independent-data-width", "VPSRAQ", 8, func(r *X86AVXRule) { r.Classes[1] = "YxrEvex" }},
		{"VEX-immediate-register-only", "VPSLLD", 0, func(r *X86AVXRule) { r.Classes[1] = "Yxm" }},
		{"EVEX-immediate-unsigned-only", "VPSLLD", 6, func(r *X86AVXRule) { r.Classes[0] = "Yi8" }},
		{"nonzero-mask-class", "VPSLLD", 7, func(r *X86AVXRule) { r.Classes[2] = "Yk" }},
		{"byte-no-mask", "VPSLLDQ", 4, func(r *X86AVXRule) {
			r.ZCase = "Zevex_i_rm_k_vo"
			r.Classes = []string{"Yu8", "YxmEvex", "Yknot0", "YxrEvex"}
		}},
		{"byte-immediate-only", "VPSLLDQ", 4, func(r *X86AVXRule) {
			r.ZCase, r.ZOffset = "Zevex_rm_v_r", 3
			r.Classes = []string{"YxmEvex", "YxrEvex", "YxrEvex"}
		}},
		{"byte-no-BCST", "VPSLLDQ", 4, func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+1] += " | evexBcstN4" }},
		{"byte-no-zeroing", "VPSLLDQ", 4, func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+1] += " | evexZeroingEnabled" }},
		{"byte-W0", "VPSLLDQ", 4, func(r *X86AVXRule) {
			r.OpBytes[r.EncodingOffset] = strings.ReplaceAll(r.OpBytes[r.EncodingOffset], "evexW0", "evexW1")
		}},
		{"VEX-W0", "VPSLLD", 0, func(r *X86AVXRule) {
			r.OpBytes[r.EncodingOffset] = strings.ReplaceAll(r.OpBytes[r.EncodingOffset], "vexW0", "vexW1")
		}},
		{"unknown-header-atom", "VPSLLD", 6, func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset] += " | evexUnaudited" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			rule := seed(row.op, row.index)
			row.change(&rule)
			if witnesses, err := x86PackedAVXRowWitnesses(rule); err == nil || len(witnesses) != 0 {
				t.Fatal("unmodeled official format returned partial or accepted witnesses", witnesses, err)
			}
		})
	}
}

func TestX86UniformByteShiftRejectsUnknownLegacyFormatAxes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range []string{"extension", "prefix", "payload", "offset", "class", "byte-extension"} {
		t.Run(control, func(t *testing.T) {
			op, index := "PSLLL", 3
			if control == "byte-extension" {
				op, index = "PSLLO", 0
			}
			found := 0
			for _, entry := range catalog.Optab {
				if entry.Opcode != op {
					continue
				}
				for _, row := range entry.Rows {
					if row.RowIndex != index {
						continue
					}
					found++
					entry.OpBytes = append([]string(nil), entry.OpBytes...)
					row.Classes = append([]string(nil), row.Classes...)
					switch control {
					case "extension":
						entry.OpBytes[2], entry.OpBytes[7] = "8", "8"
					case "prefix":
						entry.OpBytes[5] = "Pm"
					case "payload":
						entry.OpBytes = append(entry.OpBytes, "0")
					case "offset":
						row.UnmatchedOffset++
					case "class":
						row.Classes[1] = "Yxm"
					case "byte-extension":
						entry.OpBytes[1] = "8"
					}
					if witnesses, err := x86PackedLegacyRowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
						t.Fatal("unmodeled complete legacy row returned witnesses", witnesses, err)
					}
				}
			}
			if found != 1 {
				t.Fatal("missing or repeated original official row", found)
			}
		})
	}
}
