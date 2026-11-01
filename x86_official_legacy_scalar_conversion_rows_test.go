package plan9asm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func scalarConversion12OriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	type sample struct {
		name, table, prefix string
		fromFloat           bool
	}
	samples := []sample{
		{"CVTSD2SL", "yxcvfl", "f20f2d", true},
		{"CVTSD2SQ", "yxcvfq", "f2480f2d", true},
		{"CVTSS2SL", "yxcvfl", "f30f2d", true},
		{"CVTSS2SQ", "yxcvfq", "f3480f2d", true},
		{"CVTTSD2SL", "yxcvfl", "f20f2c", true},
		{"CVTTSD2SQ", "yxcvfq", "f2480f2c", true},
		{"CVTTSS2SL", "yxcvfl", "f30f2c", true},
		{"CVTTSS2SQ", "yxcvfq", "f3480f2c", true},
		{"CVTSL2SD", "yxcvlf", "f20f2a", false},
		{"CVTSQ2SD", "yxcvqf", "f2480f2a", false},
		{"CVTSL2SS", "yxcvlf", "f30f2a", false},
		{"CVTSQ2SS", "yxcvqf", "f3480f2a", false},
	}
	entries := map[string]goasmrules.X86LegacyOpcode{}
	for _, entry := range catalog.Optab {
		for _, sample := range samples {
			if entry.Opcode == sample.name {
				if _, dup := entries[entry.Opcode]; dup {
					t.Fatal("duplicate original table")
				}
				entries[entry.Opcode] = entry
			}
		}
	}
	if len(entries) != 12 {
		t.Fatal("missing complete original conversion family")
	}
	var cases []x86OfficialPackedCase
	for _, sample := range samples {
		entry := entries[sample.name]
		if entry.Ytab != sample.table || len(entry.Rows) != 1 {
			t.Fatal("original row ownership changed", entry)
		}
		operands := []string{"CX,X1", "0(SI),X1"}
		modrm := []string{"c9", "0e"}
		if sample.fromFloat {
			operands = []string{"X0,BX", "0(SI),BX"}
			modrm = []string{"d8", "1e"}
		}
		for index, args := range operands {
			instruction := sample.name + " " + args
			encoding, err := hex.DecodeString(sample.prefix + modrm[index])
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, x86OfficialPackedCase{row: fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab), witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: encoding, Destination: strings.Split(args, ",")[1]}})
		}
	}
	return cases
}

func TestX86LegacyScalarConversionOriginalGoBytesAndModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := scalarConversion12OriginalCases(t, catalog)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			var cases []x86OfficialPackedCase
			for _, original := range originals {
				instruction := original.witness.Instruction
				wide := strings.Contains(strings.Fields(instruction)[0], "SQ")
				if arch == "386" && wide {
					t.Run("Q-refusal/"+instruction, func(t *testing.T) {
						listing, err := x86ScalarLiteralExpectedGoListing(t, arch, "TEXT ·NoQ(SB),4,$0-0\n"+instruction+"\nRET\n", false)
						t.Logf("ORIGINAL_SCALAR_CONVERSION_Q_REFUSAL arch=%s source=%q exit=%v diagnostic=%q", arch, instruction, err, listing)
					})
					continue
				}
				fixture := original
				fixture.symbol = fmt.Sprintf("ScalarConversion%d", len(cases))
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", fixture.symbol)
				fixture.line = strings.Count(source.String(), "\n") + 1
				fmt.Fprintln(&source, instruction)
				source.WriteString("RET\n")
				cases = append(cases, fixture)
			}
			want := 24
			if arch == "386" {
				want = 12
			}
			if len(cases) != want || len(cases) > 32 {
				t.Fatal("whole-mode byte witness inventory changed", len(cases))
			}
			listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
				t.Fatal("independent original conversion bytes", err)
			}
		})
	}
}

func TestX86LegacyScalarConversionCompleteSourceJoin(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := scalarConversion12OriginalCases(t, catalog)
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86LegacyScalarConversionRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		expected := map[string]x86OfficialPackedCase{}
		for _, fixture := range originals {
			if arch == "386" && strings.Contains(strings.Fields(fixture.witness.Instruction)[0], "SQ") {
				continue
			}
			key := fixture.row + "/" + fixture.witness.Instruction
			if _, duplicate := expected[key]; duplicate {
				t.Fatal("duplicate independent source fixture", key)
			}
			expected[key] = fixture
		}
		filtered := 0
		for _, row := range rows {
			if row.ModeFiltered != "" {
				if arch != "386" || !strings.Contains(row.Opcode, "SQ") || len(row.Witnesses) != 0 {
					t.Fatal("original mode restriction changed", row)
				}
				filtered++
				continue
			}
			if len(row.Witnesses) != 2 {
				t.Fatal("source row lost register/memory alternatives", row)
			}
			for _, w := range row.Witnesses {
				key := row.ID + "/" + w.Instruction
				original, found := expected[key]
				if !found || !bytes.Equal(original.witness.Encoding, w.Encoding) || original.witness.Destination != w.Destination {
					t.Fatal("source ID/bytes/direction differ from independent Go fixture", key, w, original)
				}
				delete(expected, key)
			}
		}
		wantFiltered := 0
		if arch == "386" {
			wantFiltered = 6
		}
		if len(rows) != 12 || filtered != wantFiltered || len(expected) != 0 {
			t.Fatal("incomplete original scalar conversion mode join", arch, len(rows), filtered, len(expected))
		}
		modes[arch] = rows
	}
	if _, err := goasmrules.X86LegacyScalarConversionRows(catalog, "arm64"); err == nil {
		t.Fatal("foreign mode accepted")
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_LEGACY_SCALAR_CONVERSION_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
}
