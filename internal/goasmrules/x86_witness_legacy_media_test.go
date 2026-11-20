package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This independent scope names semantic families, not opcode bytes. The
// original table still supplies every row, class, prefix and payload.
func x86LegacyMediaTestMember(entry X86LegacyOpcode, row X86LegacyOperand) bool {
	switch entry.Ytab {
	case "ymm":
		return row.RowIndex == 0
	case "yps":
		return row.RowIndex < 2
	case "yxmov":
		return true
	case "yxm":
		return strings.Contains(" ADDSUBPD ADDSUBPS COMISD COMISS CVTPD2PS CVTPS2PD CVTSD2SS CVTSS2SD HADDPD HADDPS HSUBPD HSUBPS PSADBW RCPPS RCPSS RSQRTPS RSQRTSS SQRTPD SQRTPS SQRTSD SQRTSS UCOMISD UCOMISS ", " "+entry.Opcode+" ")
	}
	return false
}

// The recorded RED used the old default helper. The final explicit carrier
// projection keeps that helper's MMX refusal and all previous views intact.
func TestX86LegacyMediaRemainderExplicitCarrierTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range catalog.Optab {
		for _, row := range entry.Rows {
			if !x86LegacyMediaTestMember(entry, row) {
				continue
			}
			counts[entry.Ytab]++
			t.Run(fmt.Sprintf("%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex), func(t *testing.T) {
				witnesses, mmx, err := x86LegacyMediaRowWitnesses(entry, row)
				if err != nil || len(witnesses) == 0 {
					t.Fatal("complete explicit carrier projection has no transport", err)
				}
				if mmx {
					if old, err := x86PackedLegacyRowWitnesses(entry, row); err == nil || len(old) != 0 {
						t.Fatal("default packed consumer acquired physical MMX rows", old, err)
					}
				}
				for _, w := range witnesses {
					if w.Width != 128 && !mmx || w.Width != 64 && mmx || w.Generation != "legacy" ||
						w.Masked || w.Zeroing || w.Broadcast || w.MaskResult {
						t.Fatal("carrier or unrelated control changed", w)
					}
				}
			})
		}
	}
	if fmt.Sprint(counts) != "map[ymm:33 yps:16 yxm:23 yxmov:24]" {
		t.Fatal("complete original media denominator changed", counts)
	}
}

func TestX86LegacyMediaRemainderModesAndPayload(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86LegacyMediaRemainderRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		ids, formats, filtered := map[string]bool{}, 0, 0
		for _, row := range rows {
			if row.ID == "" || ids[row.ID] {
				t.Fatal("original row identity missing/repeated", row)
			}
			ids[row.ID] = true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("refused mode acquired witnesses", row)
				}
			}
			formats += len(row.Witnesses)
		}
		wantFormats, wantFiltered := 160, 0
		if arch == "386" {
			wantFormats, wantFiltered = 70, 49
		}
		if len(ids) != 96 || formats != wantFormats || filtered != wantFiltered {
			t.Fatal("original source/carrier/mode union changed", arch, len(ids), formats, filtered)
		}
	}
	for _, original := range catalog.Optab {
		if original.Opcode != "PADDB" {
			continue
		}
		entry := original
		entry.OpBytes = append([]string(nil), original.OpBytes...)
		entry.OpBytes[0], entry.OpBytes[2] = "0xfd", "0xfd"
		w, _, err := x86LegacyMediaRowWitnesses(entry, entry.Rows[0])
		if err != nil || len(w) != 2 || !bytes.Equal(w[0].Encoding, []byte{0x0f, 0xfd, 0xc8}) {
			t.Fatal("transport replaced original selected bytes by a mnemonic table", w, err)
		}
	}
}

func TestX86LegacyMediaCompleteMMXAtomsRemainTyped(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		if original.Ytab != "ymm" && original.Ytab != "yps" {
			continue
		}
		for _, control := range []string{"opcode-is-prefix", "unused-extension"} {
			if control == "unused-extension" && original.Ytab != "yps" {
				continue
			}
			t.Run(original.Opcode+"/"+control, func(t *testing.T) {
				entry := original
				entry.OpBytes = append([]string(nil), original.OpBytes...)
				if control == "unused-extension" {
					entry.OpBytes[2], entry.OpBytes[7] = "8", "8"
				} else if entry.Ytab == "ymm" {
					entry.OpBytes[0], entry.OpBytes[2] = "Pe", "Pe"
				} else {
					entry.OpBytes[0], entry.OpBytes[4] = "Pe", "Pe"
				}
				if w, _, err := x86LegacyMediaRowWitnesses(entry, entry.Rows[0]); err == nil || len(w) != 0 {
					t.Fatal("complete MMX schema confused a prefix/opcode or ignored an invalid /digit", w, err)
				}
			})
		}
	}
}

func TestX86LegacyMediaRemainderRejectsForeignAxes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		for _, operand := range original.Rows {
			if !x86LegacyMediaTestMember(original, operand) {
				continue
			}
			for _, control := range []string{"kind", "table", "prefix", "escape", "index", "classes", "zcase", "stride", "offset", "extent", "selected-byte", "unselected-byte"} {
				t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, operand.RowIndex, control), func(t *testing.T) {
					entry, row := original, operand
					entry.OpBytes = append([]string(nil), original.OpBytes...)
					switch control {
					case "kind":
						entry.Kind = "special"
					case "table":
						entry.Ytab = "unknown"
					case "prefix":
						entry.Prefix = "unknown"
					case "escape":
						entry.EscapeAdjustment++
					case "index":
						row.RowIndex = len(entry.Rows)
					case "classes":
						row.Classes = []string{"Yunknown", "Yxr"}
					case "zcase":
						row.ZCase = "Zunknown"
					case "stride":
						row.ZOffset++
					case "offset":
						row.UnmatchedOffset++
					case "extent":
						entry.OpBytes = append(entry.OpBytes, "0")
					case "selected-byte":
						entry.OpBytes[row.UnmatchedOffset] = "not-a-byte"
					case "unselected-byte":
						index := len(entry.OpBytes) - 1
						if index == row.UnmatchedOffset {
							index = 0
						}
						entry.OpBytes[index] = "not-a-byte"
					}
					if w, _, err := x86LegacyMediaRowWitnesses(entry, row); err == nil || len(w) != 0 {
						t.Fatal("foreign source axes silently acquired media transport", control, w, err)
					}
				})
			}
		}
	}
}
