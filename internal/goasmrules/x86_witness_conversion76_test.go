package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// An independent source namespace, separate from ordinary packed numeric
// conversion. Every literal record is passed to the existing witness helper.
func TestX86PrecisionHalfScalarConversionOfficialSourceWitnesses(t *testing.T) {
	names := strings.Fields(`
		VCVTPD2PS VCVTPD2PSX VCVTPD2PSY VCVTPS2PD
		VCVTPH2PS VCVTPS2PH VCVTSD2SS VCVTSS2SD
		VCVTSD2SI VCVTSD2SIQ VCVTSS2SI VCVTSS2SIQ
		VCVTTSD2SI VCVTTSD2SIQ VCVTTSS2SI VCVTTSS2SIQ
		VCVTSD2USIL VCVTSD2USIQ VCVTSS2USIL VCVTSS2USIQ
		VCVTTSD2USIL VCVTTSD2USIQ VCVTTSS2USIL VCVTTSS2USIQ
		VCVTSI2SDL VCVTSI2SDQ VCVTSI2SSL VCVTSI2SSQ
		VCVTUSI2SDL VCVTUSI2SDQ VCVTUSI2SSL VCVTUSI2SSQ
	`)
	selected := make(map[string]bool)
	for _, name := range names {
		if selected[name] {
			t.Fatal("duplicate independent source member", name)
		}
		selected[name] = true
	}
	if len(selected) != 32 {
		t.Fatal("complete precision/half/scalar source namespace changed", len(selected))
	}
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	seen, rows := make(map[string]bool), 0
	for index, rule := range rules {
		if !selected[rule.Opcode] {
			continue
		}
		seen[rule.Opcode] = true
		rows++
		t.Run(fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex), func(t *testing.T) {
			witnesses, err := x86PackedAVXRowWitnesses(rule)
			if err != nil || len(witnesses) == 0 {
				t.Fatal("complete original conversion row has no current physical witness", err)
			}
			for _, witness := range witnesses {
				if len(witness.Encoding) == 0 || witness.Instruction == "" {
					t.Fatal("physical witness lost its source or expected encoding", rule, witness)
				}
			}
		})
	}
	if rows != 76 || len(seen) != 32 {
		t.Fatal("source closure must retain every original row and member", rows, len(seen))
	}
}

func TestX86PrecisionHalfScalarConversionRejectsMutatedSourceMetadata(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := X86PrecisionHalfScalarConversionRows(X86LegacyCatalog{}, avx)
	if err != nil || len(rows) != 76 {
		t.Fatal("complete source positive", len(rows), err)
	}
	selected := make(map[string]bool)
	for _, row := range rows {
		selected[row.ID] = true
	}
	checked := 0
	for index, original := range avx {
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, original.Opcode, original.Ytab, original.RowIndex)
		if !selected[id] {
			continue
		}
		checked++
		t.Run(id, func(t *testing.T) {
			valid, err := x86PackedAVXRowWitnesses(original)
			if err != nil || len(valid) == 0 {
				t.Fatal("valid original must precede rejection controls", err)
			}
			for _, axis := range []string{"prefix", "row", "zoffset", "encoding-offset", "roles", "header", "zcase", "opcode-byte"} {
				t.Run(axis, func(t *testing.T) {
					changed := original
					changed.Classes = append([]string(nil), original.Classes...)
					changed.OpBytes = append([]string(nil), original.OpBytes...)
					switch axis {
					case "prefix":
						changed.Prefix = "Pm"
					case "row":
						changed.RowIndex += 100
					case "zoffset":
						changed.ZOffset += 100
					case "encoding-offset":
						changed.EncodingOffset += len(changed.OpBytes)
					case "roles":
						changed.Classes[0] = "Yxxx"
					case "header":
						changed.OpBytes[changed.EncodingOffset] += " | evexInventedPermission"
					case "zcase":
						changed.ZCase = "Zinvalid"
					case "opcode-byte":
						stride := 2
						if strings.HasPrefix(changed.ZCase, "Zevex_") {
							stride = 3
						}
						changed.OpBytes[changed.EncodingOffset+stride-1] = "0x100"
					}
					if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
						t.Fatal("corrupted source metadata granted a legal physical format", axis, original, changed)
					}
				})
			}
		})
	}
	if checked != 76 {
		t.Fatal("complete source controls changed", checked)
	}
}
