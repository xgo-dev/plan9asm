package plan9asm

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86ZeroOperandCompleteSourceView(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86ZeroOperandRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, position, filtered := map[string]bool{}, 0, 0
		for _, entry := range catalog.Optab {
			if entry.Ytab != "ynone" {
				continue
			}
			fixture, valid := zeroOperandOriginalCase(t, entry, arch)
			if position >= len(rows) {
				t.Fatal("source view omitted original rows", arch, fixture.row)
			}
			row := rows[position]
			position++
			if row.ID != fixture.row || row.Opcode != entry.Opcode || seen[row.ID] {
				t.Fatal("source ID/order/name mismatch", arch, row, fixture.row)
			}
			seen[row.ID] = true
			if !valid {
				if row.ModeFiltered == "" || len(row.Witnesses) != 0 {
					t.Fatal("mode-refused original row gained a source witness", arch, row)
				}
				filtered++
				continue
			}
			if row.ModeFiltered != "" || len(row.Witnesses) != 1 {
				t.Fatal("legal original row has no exact source witness", arch, row)
			}
			witness := row.Witnesses[0]
			if witness.Instruction != fixture.witness.Instruction || witness.Destination != "" ||
				!bytes.Equal(witness.Encoding, fixture.witness.Encoding) {
				t.Fatal("source ID/instruction/literal/destination mismatch", arch, row, fixture)
			}
		}
		wantFiltered := 12
		if arch == "386" {
			wantFiltered = 13
		}
		if position != len(rows) || position != 139 && position != 140 || filtered != wantFiltered {
			t.Fatal("complete original source view changed", arch, position, len(rows), filtered)
		}
		modes[arch] = rows
	}
	for _, arch := range []string{"", "arm64", "amd64x"} {
		if _, err := goasmrules.X86ZeroOperandRows(catalog, arch); err == nil {
			t.Fatal("foreign source mode accepted", arch)
		}
	}
	for _, field := range []string{"empty", "duplicate", "capacity"} {
		changed := catalog
		changed.Optab = append([]goasmrules.X86LegacyOpcode(nil), catalog.Optab...)
		switch field {
		case "empty":
			changed.Optab = nil
		case "duplicate":
			for _, entry := range catalog.Optab {
				if entry.Ytab == "ynone" {
					changed.Optab = append(changed.Optab, entry)
					break
				}
			}
		case "capacity":
			changed.OpBytesSize = 0
		}
		if _, err := goasmrules.X86ZeroOperandRows(changed, "amd64"); err == nil {
			t.Fatal("invalid complete source catalog accepted", field)
		}
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_ZERO_OPERAND_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
}

// This test-only reference follows the original Go prefix switch and complete
// zero-terminated opBytes array, independently of the production formatter.
func zeroOperandOriginalCase(t *testing.T, entry goasmrules.X86LegacyOpcode, arch string) (x86OfficialPackedCase, bool) {
	t.Helper()
	fixture := x86OfficialPackedCase{
		row:     fmt.Sprintf("optab/%d/%s/ynone/0", entry.TableIndex, entry.Opcode),
		witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode},
	}
	if arch == "amd64" && entry.Prefix == "P32" ||
		arch == "386" && (entry.Prefix == "Pw" || entry.Prefix == "Py") {
		return fixture, false
	}
	prefixes := map[string][]byte{
		"Px": {}, "Pb": {}, "P32": {}, "Py": {},
		"Pm": {0x0f}, "Pe": {0x66}, "Pw": {0x48}, "Pf3": {0xf3, 0x0f},
	}
	prefix, found := prefixes[entry.Prefix]
	if !found {
		t.Fatal("unobserved original zero-operand prefix", entry)
	}
	fixture.witness.Encoding = append([]byte(nil), prefix...)
	terminated := false
	for i, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			t.Fatal("original zero-operand atom changed", entry.Opcode, i, atom, err)
		}
		if value == 0 {
			terminated = true
		}
		if !terminated {
			fixture.witness.Encoding = append(fixture.witness.Encoding, byte(value))
		}
	}
	return fixture, true
}

// Prefix source rows retain a compatible successor. These functions are
// assembled as data-producing oracles, never executed. Their existence grants
// no initialized input, hardware, native-entry or machine-state permission.
func zeroOperandOriginalContext(opcode string) (before, after string) {
	// Keep Go's preprocessing delta balanced before the final RET. For a
	// POP, the matching PUSH precedes the measured original instruction;
	// for a PUSH, the matching POP follows it. PUSHA/POPA use the same
	// physical-width pairing even though obj6 tracks only individual pushes.
	if strings.HasPrefix(opcode, "PUSH") {
		return "", "POP" + strings.TrimPrefix(opcode, "PUSH") + "\n"
	}
	if strings.HasPrefix(opcode, "POP") {
		return "PUSH" + strings.TrimPrefix(opcode, "POP") + "\n", ""
	}
	switch opcode {
	case "LOCK":
		return "", "ADDL AX,(BX)\n"
	case "REP":
		return "", "MOVSB\n"
	case "REPN":
		return "", "CMPSB\n"
	case "XACQUIRE", "XRELEASE":
		return "", "LOCK\nADDL AX,(BX)\n"
	}
	return "", ""
}

func TestX86ZeroOperandOriginalGoCompleteBytesAndModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var entries []goasmrules.X86LegacyOpcode
	for _, entry := range catalog.Optab {
		if entry.Ytab == "ynone" {
			if len(entry.Rows) != 1 || entry.Rows[0].ZCase != "Zlit" || len(entry.Rows[0].Classes) != 0 {
				t.Fatal("complete original zero-operand row changed", entry)
			}
			entries = append(entries, entry)
		}
	}
	if len(entries) != 139 && len(entries) != 140 {
		t.Fatal("complete SDK zero-operand inventory changed", len(entries))
	}
	observed, accepted, refused := 0, 0, 0
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var positives []x86OfficialPackedCase
			for _, entry := range entries {
				fixture, valid := zeroOperandOriginalCase(t, entry, arch)
				observed++
				if valid {
					positives = append(positives, fixture)
					accepted++
					continue
				}
				refused++
				t.Run("mode-refusal/"+fixture.row, func(t *testing.T) {
					before, after := zeroOperandOriginalContext(entry.Opcode)
					source := "TEXT ·NoMode(SB),4,$0-0\n" + before + entry.Opcode + "\n" + after + "RET\n"
					listing, err := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
					marker := "asmins: illegal 64:"
					if entry.Prefix == "P32" {
						marker = "asmins: illegal in 64-bit mode:"
					} else if entry.Prefix == "Py" {
						marker = "asmins: illegal in 32-bit mode:"
					}
					matched := false
					for _, line := range strings.Split(listing, "\n") {
						if strings.Contains(line, marker) && strings.Contains(line, entry.Opcode) {
							matched = true
						}
					}
					if !matched || strings.Contains(listing, "unbalanced PUSH/POP") {
						t.Fatal("source refusal lacks the original opcode/mode diagnostic", fixture.row, arch, marker, listing)
					}
					t.Logf("ZERO_OPERAND_ACTUAL_GO_MODE_REFUSAL id=%s mode=%s exit=%v diagnostic=%q", fixture.row, arch, err, listing)
				})
			}
			for start := 0; start < len(positives); start += 32 {
				end := start + 32
				if end > len(positives) {
					end = len(positives)
				}
				batch := append([]x86OfficialPackedCase(nil), positives[start:end]...)
				var source strings.Builder
				for i := range batch {
					batch[i].symbol = fmt.Sprintf("ZeroOperand%d", start+i)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[i].symbol)
					before, after := zeroOperandOriginalContext(batch[i].witness.Instruction)
					source.WriteString(before)
					batch[i].line = strings.Count(source.String(), "\n") + 1
					fmt.Fprintln(&source, batch[i].witness.Instruction)
					source.WriteString(after)
					source.WriteString("RET\n")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal("actual Go zero-operand source batch rejected", arch, start, err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("original zero-operand literal bytes changed", arch, start, err)
				}
			}
		})
	}
	if observed != 2*len(entries) || refused != 25 || accepted != 2*len(entries)-25 {
		t.Fatal("complete original source/mode observation matrix changed", observed, accepted, refused)
	}
	t.Logf("ZERO_OPERAND_ACTUAL_GO observations=%d accepted=%d refused=%d", observed, accepted, refused)
}
