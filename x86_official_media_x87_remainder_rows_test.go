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

// The reference follows original source prefix, mediaop, literal and asmando
// emission. It does not invoke a production witness formatter. In particular,
// non-temporal GP-register destinations are Go-byte observations, not valid
// CPU instructions or initialized numerical/native positives.
func mediaX87OriginalSourceCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	rows := 0
	for _, entry := range catalog.Optab {
		switch entry.Ytab {
		case "yxcvm1", "yxcvm2", "ylddqu", "yxr", "ymr", "yxr_ml", "ymr_ml", "ymrxr", "ymmxmm0f38", "ymshuf", "yfxch", "ystsw":
		default:
			continue
		}
		atoms := make([]byte, len(entry.OpBytes))
		for index, token := range entry.OpBytes {
			value, err := strconv.ParseUint(token, 0, 8)
			if err != nil {
				var found bool
				atoms[index], found = map[string]byte{"Pe": 0x66, "Pm": 0x0f, "Pf2": 0xf2, "Pf3": 0xf3}[token]
				if !found {
					t.Fatal("independent original media atom changed", entry, token)
				}
			} else {
				atoms[index] = byte(value)
			}
		}
		for _, row := range entry.Rows {
			rows++
			prefix, found := map[string][]byte{
				"Px": {}, "Pm": {0x0f}, "Pe": {0x66}, "Pf2": {0xf2, 0x0f},
				"Pf3": {0xf3, 0x0f}, "Pq4": {0x66, 0x0f, 0x38},
			}[entry.Prefix]
			cursor := row.UnmatchedOffset
			if !found || cursor < 0 || cursor >= len(atoms) {
				t.Fatal("independent original prefix/row offset changed", entry, row)
			}
			code := append([]byte(nil), prefix...)
			if atoms[cursor] == 0x0f {
				code = append(code, 0x0f)
				cursor++
			}
			if cursor >= len(atoms) {
				t.Fatal("independent original selected opcode missing", entry, row)
			}
			switch row.ZCase {
			case "Zlit", "Zlitm_r", "Zibm_r":
				// FSTSW's final literal uses the implicit zero cells of
				// Go's fixed opBytes array; other rows have an explicit zero.
				for cursor < len(atoms) && atoms[cursor] != 0 {
					code = append(code, atoms[cursor])
					cursor++
				}
			case "Zm_r_xm", "Zr_m_xm":
				mediaPrefix := atoms[cursor]
				if row.ZOffset != 1 && (mediaPrefix == 0x66 || mediaPrefix == 0x0f || mediaPrefix == 0xf2 || mediaPrefix == 0xf3) {
					if mediaPrefix != 0x0f {
						code = append(code, mediaPrefix)
					}
					code = append(code, 0x0f)
					cursor++
				} else if len(code) == 0 || code[len(code)-1] != 0x0f {
					code = append(code, 0x0f)
				}
				if cursor >= len(atoms) {
					t.Fatal("independent mediaop missing its selected opcode", entry, row)
				}
				code = append(code, atoms[cursor])
			case "Zm_r", "Zm_o", "Zo_m":
				code = append(code, atoms[cursor])
			default:
				t.Fatal("independent original media Z-case changed", entry, row)
			}
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			add := func(source, destination string, modrm byte, tail ...byte) {
				encoding := append([]byte(nil), code...)
				if row.ZCase != "Zlit" {
					encoding = append(encoding, modrm)
				}
				encoding = append(encoding, tail...)
				instruction := entry.Opcode + " " + destination
				if source != "" {
					instruction = entry.Opcode + " " + source + "," + destination
				}
				if entry.Ytab == "ymshuf" {
					instruction = entry.Opcode + " $7," + source + "," + destination
					encoding = append(encoding, 7)
				}
				cases = append(cases, x86OfficialPackedCase{row: id, witness: goasmrules.X86PackedBinaryWitness{
					Instruction: instruction, Destination: destination, Encoding: encoding,
				}})
			}
			switch strings.Join(row.Classes, ",") {
			case "Yxm,Yxr":
				add("X0", "X1", 0xc8)
				add("(AX)", "X1", 0x08)
			case "Yxm,Ymr":
				add("X0", "M1", 0xc8)
				add("(AX)", "M1", 0x08)
			case "Ymm,Yxr":
				// Memory matches the preceding Yxm,Yxr row. It is
				// already observed there, never attributed to this row.
				add("M0", "X1", 0xc8)
			case "Yxr,Yxr", "Ymr,Yxr":
				bank := "X0"
				if row.Classes[0] == "Ymr" {
					bank = "M0"
				}
				add(bank, "X1", 0xc8)
			case "Ymr,Ymr":
				add("M0", "M1", 0xc8)
			case "Ym,Yxr":
				add("(AX)", "X1", 0x08)
			case "Yxr,Yml", "Ymr,Yml":
				bank := "X0"
				if row.Classes[0] == "Ymr" {
					bank = "M0"
				}
				add(bank, "CX", 0xc1) // Go accepts this CPU-invalid store form.
				add(bank, "(AX)", 0)
			case "Ymm,Ymr", "Yi8,Ymm,Ymr":
				add("M0", "M1", 0xc8)
				add("(AX)", "M1", 0x08)
			case "Yf0,Yrf", "Yrf,Yf0":
				fragment := atoms[row.UnmatchedOffset+1]
				for _, lane := range []byte{1, 7} {
					first, last := "F0", fmt.Sprint("F", lane)
					if row.Classes[0] == "Yrf" {
						first, last = last, first
					}
					add(first, last, 0xc0|lane|fragment<<3)
				}
			case "Ym":
				fragment := atoms[row.UnmatchedOffset+1]
				add("", "(AX)", fragment<<3)
				add("", "7(AX)", 0x40|fragment<<3, 7)
			case "Yax":
				add("", "AX", 0)
			default:
				t.Fatal("independent original media operand classes changed", entry, row)
			}
		}
		if entry.Ytab == "yfxch" {
			// F0,F0 selects the first direction even though both match.
			cases = append(cases, x86OfficialPackedCase{
				row: fmt.Sprintf("optab/%d/%s/yfxch/0/first-match", entry.TableIndex, entry.Opcode),
				witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " F0,F0", Destination: "F0",
					Encoding: []byte{atoms[0], 0xc0 | atoms[1]<<3}},
			})
		}
	}
	if rows != 31 || len(cases) != 53 {
		t.Fatal("complete media/x87 independent source row/case count changed", rows, len(cases))
	}
	return cases
}

func TestX86OfficialMediaX87OriginalGoRowsAndFirstMatch(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		x86LegacyLiteralSIMDCheckGoBatches(t, arch, mediaX87OriginalSourceCases(t, catalog))
	}
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86LegacyMediaX87Rows(catalog, arch)
		if err != nil {
			t.Fatal("complete explicit source view failed after independent original-Go observations", arch, err)
		}
		expected := map[string]goasmrules.X86PackedBinaryWitness{}
		for _, original := range mediaX87OriginalSourceCases(t, catalog) {
			if strings.HasSuffix(original.row, "/first-match") {
				continue // Independently assembled selection control, not another original row.
			}
			expected[original.row+"/"+original.witness.Instruction] = original.witness
		}
		witnesses := 0
		for _, row := range rows {
			if row.ModeFiltered != "" {
				t.Fatal("source view filtered an actually assembled canonical mode", arch, row)
			}
			for _, witness := range row.Witnesses {
				key := row.ID + "/" + witness.Instruction
				original, found := expected[key]
				if !found || !bytes.Equal(original.Encoding, witness.Encoding) || original.Destination != witness.Destination {
					t.Fatal("complete media/x87 source transport differs from independent actual Go", arch, key, witness, original)
				}
				delete(expected, key)
				witnesses++
			}
		}
		if len(rows) != 31 || witnesses != 52 || len(expected) != 0 {
			t.Fatal("complete media/x87 original ID/witness join omitted or repeated source cases", arch, len(rows), witnesses, expected)
		}
		modes[arch] = rows
	}
	if !t.Failed() {
		t.Log("MEDIA_X87_ACTUAL_GO original_rows=31 original_cases=52 first_match_controls=1 modes=2 exact_bytes=106")
		x86Legacy127SaveIdentity(t, "PLAN9ASM_MEDIA_X87_REMAINDER_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86ScalarRMWRow
		}{catalog, modes})
	}
}

func TestX86OfficialMediaX87OriginalGoSignedImmediateBoundaries(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var originals []x86OfficialPackedCase
	for _, fixture := range mediaX87OriginalSourceCases(t, catalog) {
		if strings.HasPrefix(fixture.witness.Instruction, "PSHUFW ") {
			originals = append(originals, fixture)
		}
	}
	if len(originals) != 2 {
		t.Fatal("complete original PSHUFW carrier set changed", originals)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var accepted []x86OfficialPackedCase
			for _, value := range []int{-128, -1, 0, 127} {
				for _, original := range originals {
					changed := original
					changed.witness.Instruction = strings.Replace(original.witness.Instruction, "$7,", fmt.Sprintf("$%d,", value), 1)
					changed.witness.Encoding = append([]byte(nil), original.witness.Encoding...)
					changed.witness.Encoding[len(changed.witness.Encoding)-1] = byte(value)
					accepted = append(accepted, changed)
				}
			}
			x86LegacyLiteralSIMDCheckGoBatches(t, arch, accepted)
			for _, value := range []int{-129, 128, 255, 256} {
				for _, original := range originals {
					instruction := strings.Replace(original.witness.Instruction, "$7,", fmt.Sprintf("$%d,", value), 1)
					t.Run(instruction, func(t *testing.T) {
						source := "TEXT ·Refused(SB),4,$0-0\n" + instruction + "\nRET\n"
						listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
						if !strings.Contains(listing, "invalid instruction") || !strings.Contains(listing, "PSHUFW") {
							t.Fatal("PSHUFW Yi8 refusal did not identify its actual original source grammar", listing)
						}
					})
				}
			}
		})
	}
	if !t.Failed() {
		t.Log("MEDIA_X87_SIGNED_IMMEDIATES observations=32 exact_bytes=16 actual_Yi8_refusals=16")
	}
}
