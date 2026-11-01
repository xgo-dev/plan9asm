package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"testing"
)

func zeroOperandOriginalEntries(t *testing.T) []X86LegacyOpcode {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var entries []X86LegacyOpcode
	prefixes := map[string]int{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "ynone" {
			continue
		}
		if entry.Kind != "encoding" || len(entry.Rows) != 1 {
			t.Fatal("complete zero-operand source entry changed", entry)
		}
		row := entry.Rows[0]
		if row.RowIndex != 0 || row.ZCase != "Zlit" || row.ZOffset != 1 ||
			row.UnmatchedOffset != 0 || len(row.Classes) != 0 {
			t.Fatal("complete zero-operand original schema changed", entry)
		}
		prefixes[entry.Prefix]++
		entries = append(entries, entry)
	}
	for prefix, want := range map[string]int{
		"Px": 68, "Pm": 24, "Pe": 15, "P32": 12, "Pw": 10, "Pb": 7, "Py": 3,
	} {
		if prefixes[prefix] != want {
			t.Fatal("complete source prefix inventory changed", prefix, prefixes)
		}
	}
	if prefixes["Pf3"] > 1 || len(entries) != 139+prefixes["Pf3"] || len(prefixes) != 7+prefixes["Pf3"] {
		t.Fatal("complete zero-operand SDK inventory changed", len(entries), prefixes)
	}
	return entries
}

// This independent model follows Go's prefix switch and PutOpBytesLit.
// It is checked against actual Go objects in the package-level owner. The
// first zero terminates emission, but every original array atom is retained.
func zeroOperandExpected(t *testing.T, entry X86LegacyOpcode, arch string) ([]byte, bool) {
	t.Helper()
	if arch != "amd64" && arch != "386" {
		t.Fatal("foreign test mode", arch)
	}
	if arch == "amd64" && entry.Prefix == "P32" ||
		arch == "386" && (entry.Prefix == "Pw" || entry.Prefix == "Py") {
		return nil, false
	}
	prefixes := map[string][]byte{
		"Px": {}, "Pb": {}, "P32": {}, "Py": {},
		"Pm": {0x0f}, "Pe": {0x66}, "Pw": {0x48}, "Pf3": {0xf3, 0x0f},
	}
	prefix, found := prefixes[entry.Prefix]
	if !found {
		t.Fatal("independent original prefix changed", entry)
	}
	code := append([]byte(nil), prefix...)
	terminated := false
	for i, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			t.Fatal("independent original literal atom changed", entry.Opcode, i, atom, err)
		}
		if value == 0 {
			terminated = true
		}
		if !terminated {
			code = append(code, byte(value))
		}
	}
	return code, true
}

func TestX86ZeroOperandCompleteOriginalInventory(t *testing.T) {
	entries := zeroOperandOriginalEntries(t)
	accepted, refused := 0, 0
	for _, arch := range []string{"amd64", "386"} {
		for _, entry := range entries {
			code, valid := zeroOperandExpected(t, entry, arch)
			if !valid {
				refused++
				continue
			}
			if len(code) == 0 {
				t.Fatal("empty original source literal", arch, entry)
			}
			accepted++
		}
	}
	if refused != 25 || accepted != 2*len(entries)-25 {
		t.Fatal("complete mode inventory changed", accepted, refused)
	}
}

func TestX86ZeroOperandExistingSourceTransportCompleteBytes(t *testing.T) {
	for _, entry := range zeroOperandOriginalEntries(t) {
		for _, arch := range []string{"amd64", "386"} {
			code, valid := zeroOperandExpected(t, entry, arch)
			if !valid {
				continue
			}
			id := fmt.Sprintf("optab/%d/%s/ynone/0/%s", entry.TableIndex, entry.Opcode, arch)
			t.Run(id, func(t *testing.T) {
				before := fmt.Sprintf("%#v", entry)
				// Both original REDs called the existing scalar-only helper.
				// The explicit source view closes that feature gap without
				// changing the older numerical consumer's accepted domain.
				row, err := x86ZeroOperandSourceRow(entry, entry.Rows[0], arch, 31)
				if err != nil || row.ModeFiltered != "" || len(row.Witnesses) != 1 {
					t.Fatal("ZERO_OPERAND_SOURCE_TRANSPORT_FEATURE_GAP", err, row)
				}
				witness := row.Witnesses[0]
				if witness.Instruction != entry.Opcode || witness.Destination != "" || !bytes.Equal(witness.Encoding, code) {
					t.Fatal("original source identity/literal bytes differ", witness, code)
				}
				if before != fmt.Sprintf("%#v", entry) {
					t.Fatal("source formatter mutated the original entry")
				}
			})
		}
	}
}

func TestX86ZeroOperandCompleteMetadataBoundaries(t *testing.T) {
	entries := zeroOperandOriginalEntries(t)
	checks := 0
	for _, entry := range entries {
		t.Run(entry.Opcode, func(t *testing.T) {
			arch := "amd64"
			if entry.Prefix == "P32" {
				arch = "386"
			}
			for _, field := range []string{
				"kind", "ytab", "row-count", "original-arity", "selected-arity",
				"original-index", "selected-index", "original-zcase", "selected-zcase",
				"original-stride-negative", "original-stride-overflow", "selected-stride",
				"original-offset-negative", "selected-offset-overflow", "prefix",
				"escape-negative", "escape-overflow", "escape-identity", "empty-payload",
				"empty-literal", "payload-full-without-terminator", "payload-overflow",
			} {
				changed, row := entry, entry.Rows[0]
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				changed.OpBytes = append([]string(nil), entry.OpBytes...)
				maxInt := int(^uint(0) >> 1)
				switch field {
				case "kind":
					changed.Kind = "reserved"
				case "ytab":
					changed.Ytab = "yin"
				case "row-count":
					changed.Rows = append(changed.Rows, row)
				case "original-arity":
					changed.Rows[0].Classes = []string{"Ynone"}
				case "selected-arity":
					row.Classes = []string{"Ynone"}
				case "original-index":
					changed.Rows[0].RowIndex = 1
				case "selected-index":
					row.RowIndex = -1
				case "original-zcase":
					changed.Rows[0].ZCase = "Zpseudo"
				case "selected-zcase":
					row.ZCase = "Zlitm_r"
				case "original-stride-negative":
					changed.Rows[0].ZOffset = -maxInt - 1
				case "original-stride-overflow":
					changed.Rows[0].ZOffset = maxInt
				case "selected-stride":
					row.ZOffset = 0
				case "original-offset-negative":
					changed.Rows[0].UnmatchedOffset = -maxInt - 1
				case "selected-offset-overflow":
					row.UnmatchedOffset = maxInt
				case "prefix":
					changed.Prefix = "Pq"
				case "escape-negative":
					changed.EscapeAdjustment = -1
				case "escape-overflow":
					changed.EscapeAdjustment = maxInt
				case "escape-identity":
					changed.EscapeAdjustment = 1 - entry.EscapeAdjustment
				case "empty-payload":
					changed.OpBytes = nil
				case "empty-literal":
					changed.OpBytes[0] = "0"
				case "payload-full-without-terminator", "payload-overflow":
					// The observed Go source uses a 31-byte fixed array.
					// Filling it removes the implicit zero terminator.
					count := 31
					if field == "payload-overflow" {
						count++
					}
					changed.OpBytes = make([]string, count)
					for i := range changed.OpBytes {
						changed.OpBytes[i] = "1"
					}
					// Preserve source escape identity so the missing implicit
					// terminator is the independent rejection reason.
					changed.OpBytes[0] = entry.OpBytes[0]
				}
				checks++
				if _, err := x86ZeroOperandSourceRow(changed, row, arch, 31); err == nil {
					t.Errorf("malformed original source accepted: op=%s mode=%s mutation=%s", entry.Opcode, arch, field)
				}
			}
			for i := range entry.OpBytes {
				for _, atom := range []string{"-1", "0x100", "Pm"} {
					changed := entry
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					changed.OpBytes[i] = atom
					checks++
					if _, err := x86ZeroOperandSourceRow(changed, entry.Rows[0], arch, 31); err == nil {
						t.Errorf("malformed literal atom accepted: op=%s index=%d atom=%q", entry.Opcode, i, atom)
					}
				}
			}
		})
	}
	want := 3703
	if len(entries) == 140 {
		want = 3731
	}
	if checks != want {
		t.Fatal("complete metadata control count changed", checks, want)
	}
	t.Logf("ZERO_OPERAND_METADATA_CHECKS=%d", checks)
}

func TestX86ZeroOperandSourceViewKeepsScalarConsumerBoundary(t *testing.T) {
	for _, entry := range zeroOperandOriginalEntries(t) {
		for _, arch := range []string{"amd64", "386"} {
			if _, err := x86ScalarRMWRowWitnesses(entry, entry.Rows[0], arch); err == nil {
				t.Fatal("source literal widened the older scalar numerical consumer", entry.Opcode, arch)
			}
		}
	}
}
