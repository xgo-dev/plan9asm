package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86SpecialVectorStateCompleteOriginalRows(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := X86SpecialVectorStateRows(X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	originals := map[string]X86AVXRule{}
	for index, rule := range avx {
		if x86SpecialVectorStateName(rule.Opcode) {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)] = rule
		}
	}
	if len(rows) != 237 || len(originals) != 237 {
		t.Fatal("complete237 original source closure", len(rows), len(originals))
	}
	for _, row := range rows {
		names[row.Opcode] = true
		t.Run(row.ID, func(t *testing.T) {
			original, found := originals[row.ID]
			if !found || len(row.Witnesses) == 0 {
				t.Fatal("original row lost source/witnesses", row.ID)
			}
			valid, err := x86PackedAVXRowWitnesses(original)
			if err != nil || len(valid) == 0 {
				t.Fatal("valid source must precede negative metadata", err)
			}
			// The complete opcode payload contains other generations and widths.
			// Only this row's current encoding block supplies suffix controls.
			inputForms := 2
			if len(original.Classes) <= 1 {
				inputForms = 1
			}
			masked, maskResult := false, false
			for _, class := range original.Classes {
				masked = masked || class == "Yknot0"
				if strings.HasSuffix(class, "Multi4") {
					inputForms = 1
				}
			}
			if len(original.Classes) > 0 {
				maskResult = original.Classes[len(original.Classes)-1] == "Yk"
			}
			controls := ""
			if strings.HasPrefix(original.ZCase, "Zevex_") {
				controls = original.OpBytes[original.EncodingOffset+1]
			}
			want := inputForms
			if strings.Contains(controls, "evexBcstN") {
				want++
			}
			if strings.Contains(controls, "evexSaeEnabled") {
				want++
			}
			if strings.Contains(controls, "evexRoundingEnabled") {
				want += 4
			}
			if masked && !maskResult {
				want *= 2
			}
			if maskResult {
				want *= 2
			}
			if len(valid) != want {
				t.Fatal("current source block shape count", row.ID, len(valid), want)
			}
			for _, axis := range []string{"prefix", "classes", "header", "payload-bound"} {
				t.Run(axis, func(t *testing.T) {
					bad := original
					bad.Classes = append([]string(nil), original.Classes...)
					bad.OpBytes = append([]string(nil), original.OpBytes...)
					switch axis {
					case "prefix":
						bad.Prefix = "Pm"
					case "classes":
						if len(bad.Classes) == 0 {
							bad.Classes = []string{"Yxxx"}
						} else {
							bad.Classes[0] = "Yxxx"
						}
					case "header":
						bad.OpBytes[bad.EncodingOffset] += " | inventedEncodingPermission"
					case "payload-bound":
						bad.EncodingOffset += len(bad.OpBytes)
					}
					if _, err := x86PackedAVXRowWitnesses(bad); err == nil {
						t.Fatal("mutated source metadata granted a physical grammar", axis, row.ID)
					}
				})
			}
		})
	}
	if len(names) != 89 {
		t.Fatal("complete89 source names", len(names))
	}
}
