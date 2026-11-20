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

// These source-shape witnesses prove Go row selection only. They are not
// initialized public functions or executable x87 values. In particular Go's
// botch rows can assemble without identifying a valid numerical operation.
func x86X87OriginalSourceCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	rows, shadows := 0, 0
	for _, entry := range catalog.Optab {
		switch entry.Ytab {
		case "yfmvx", "yfadd", "yfcmv", "ycompp":
		default:
			continue
		}
		for _, row := range entry.Rows {
			rows++
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			if row.UnmatchedOffset < 0 || row.UnmatchedOffset+2 > len(entry.OpBytes) {
				t.Fatal("original x87 source payload is incomplete", id)
			}
			opcode, err := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset], 0, 8)
			if err != nil {
				t.Fatal(id, err)
			}
			fragment, err := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset+1], 0, 8)
			if err != nil {
				t.Fatal(id, err)
			}
			appendCase := func(instruction string, modrm byte, displacement ...byte) {
				code := append([]byte{byte(opcode), modrm}, displacement...)
				cases = append(cases, x86OfficialPackedCase{row: id,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: code}})
			}
			switch row.ZCase + "/" + strings.Join(row.Classes, ",") {
			case "Zm_o/Ym,Yf0":
				appendCase(entry.Opcode+" (AX),F0", byte(fragment<<3))
				appendCase(entry.Opcode+" 7(AX),F0", byte(0x40|fragment<<3), 7)
			case "Zm_o/Yrf,Yf0":
				for _, lane := range []byte{1, 7} {
					appendCase(fmt.Sprintf("%s F%d,F0", entry.Opcode, lane), byte(0xc0|lane|byte(fragment<<3)))
				}
			case "Zo_m/Yf0,Yrf":
				for _, lane := range []byte{1, 7} {
					// asmando ORs the full source field fragment. FUCOMPP's
					// decimal 13 is not a three-bit /digit or a REX extension.
					appendCase(fmt.Sprintf("%s F0,F%d", entry.Opcode, lane), byte(0xc0|lane|byte(fragment<<3)))
				}
			default:
				t.Fatal("unmodeled original x87 operand shape", id, row)
			}
		}
		if entry.Ytab == "yfadd" {
			// F0,F0 selects the earlier Yrf,F0 row, never the overlapping
			// F0,Yrf row. Retain its true source ID as a separate control.
			row := entry.Rows[1]
			opcode, firstErr := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset], 0, 8)
			fragment, lastErr := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset+1], 0, 8)
			if firstErr != nil || lastErr != nil {
				t.Fatal("alias source payload", firstErr, lastErr)
			}
			cases = append(cases, x86OfficialPackedCase{
				row:     fmt.Sprintf("optab/%d/%s/%s/%d/shadows-row2", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex),
				witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " F0,F0", Encoding: []byte{byte(opcode), byte(0xc0 | fragment<<3)}},
			})
			shadows++
		}
	}
	if rows != 79 || shadows != 8 || len(cases) != 166 {
		t.Fatal("complete x87 source row/alias union changed", rows, shadows, len(cases))
	}
	return cases
}

func TestX86OfficialLegacyX87OriginalGoRowsAndFirstMatch(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := make(map[string][]goasmrules.X86X87Row)
	for _, arch := range []string{"amd64", "386"} {
		cases := x86X87OriginalSourceCases(t, catalog)
		rows, err := goasmrules.X86X87Rows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		expected := make(map[string]x86OfficialPackedCase, len(cases))
		for _, fixture := range cases {
			expected[fixture.row+"/"+fixture.witness.Instruction] = fixture
		}
		witnesses := 0
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				original, found := expected[row.ID+"/"+witness.Instruction]
				if !found || !bytes.Equal(original.witness.Encoding, witness.Encoding) {
					t.Fatal("new x87 transport changed its independent original source witness", row.ID, witness)
				}
				witnesses++
			}
		}
		if len(rows) != 79 || witnesses != 158 {
			t.Fatal("explicit x87 source transport union changed", arch, len(rows), witnesses)
		}
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				batch := cases[start:end]
				var source strings.Builder
				line := 1
				for index := range batch {
					fixture := &batch[index]
					fixture.symbol = fmt.Sprintf("X87Original%d", start+index)
					fixture.line = line + 1
					body := fmt.Sprintf("TEXT ·%s(SB),4,$0-0\n%s\nRET\n", fixture.symbol, fixture.witness.Instruction)
					source.WriteString(body)
					line += strings.Count(body, "\n")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal("actual Go did not accept the complete original source-format batch", err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("actual Go x87 source row, full ModRM fragment or first-match bytes differ", err)
				}
			})
		}
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_X87_ROW_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86X87Row
		}{catalog, modes})
	}
}

// These objects exercise the existing instruction emitter, including the botch
// encodings. They provide neither numerical witnesses nor public input facts.
// Batch the original operations so compiler count follows format groups rather
// than the number of source rows, lanes and object targets multiplied together.
func TestX86OfficialLegacyX87OriginalEmitterObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		cases := x86X87OriginalSourceCases(t, catalog)
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				var source strings.Builder
				source.WriteString("TEXT ·X87OriginalEmitter(SB),4,$0-0\n")
				for _, fixture := range cases[start:end] {
					source.WriteString("FINIT\n")
					source.WriteString(fixture.witness.Instruction)
					source.WriteByte('\n')
				}
				source.WriteString("RET\n")
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal("complete original emitter source did not parse", err)
				}
				for _, triple := range x86Legacy127Targets(arch) {
					ir := x86X87LowererObjectUnit(t, file, arch, triple)
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
					}
				}
				t.Logf("private emitter only: retained %d exact original row/alias operations; no execution claim", end-start)
			})
		}
	}
}

func x86X87MoveOriginalSourceCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	rows, controls := 0, 0
	for _, entry := range catalog.Optab {
		switch entry.Ytab {
		case "yfmvd", "yfmvdp", "yfmvf", "yfmvp":
		default:
			continue
		}
		for _, row := range entry.Rows {
			rows++
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			if len(row.Classes) != 2 || row.UnmatchedOffset < 0 || row.UnmatchedOffset+2 > len(entry.OpBytes) {
				t.Fatal("incomplete original MOVE source row", id)
			}
			opcode, firstErr := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset], 0, 8)
			fragment, lastErr := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset+1], 0, 8)
			if firstErr != nil || lastErr != nil {
				t.Fatal("original MOVE source payload", id, firstErr, lastErr)
			}
			memory := row.Classes[0] == "Ym" || row.Classes[1] == "Ym"
			for _, lane := range []byte{1, 7} {
				first, last := fmt.Sprint("F", lane), "F0"
				code := []byte{byte(opcode), 0xc0 | lane | byte(fragment<<3)}
				if memory {
					first, code = "(AX)", []byte{byte(opcode), byte(fragment << 3)}
					if lane == 7 {
						first, code = "7(AX)", []byte{byte(opcode), 0x40 | byte(fragment<<3), 7}
					}
				}
				if row.ZCase == "Zo_m" {
					first, last = last, first
				}
				cases = append(cases, x86OfficialPackedCase{row: id,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " " + first + "," + last, Destination: last, Encoding: code}})
			}
			// The non-pop F0,F0 alias selects yfmvd row2 before row3.
			// The pop alias selects yfmvdp's actual register row1.
			if entry.Ytab == "yfmvd" && row.RowIndex == 2 || entry.Ytab == "yfmvdp" && row.RowIndex == 1 {
				cases = append(cases, x86OfficialPackedCase{row: id + "/F0-control",
					witness: goasmrules.X86PackedBinaryWitness{Instruction: entry.Opcode + " F0,F0", Encoding: []byte{byte(opcode), 0xc0 | byte(fragment<<3)}}})
				controls++
			}
		}
	}
	if rows != 18 || controls != 2 || len(cases) != 38 {
		t.Fatal("complete remaining MOVE source union changed", rows, controls, len(cases))
	}
	return cases
}

func TestX86OfficialLegacyX87MoveOriginalGoRowsAndFirstMatch(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := make(map[string][]goasmrules.X86X87Row)
	for _, arch := range []string{"amd64", "386"} {
		cases := x86X87MoveOriginalSourceCases(t, catalog)
		rows, err := goasmrules.X86X87MoveRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		expected := make(map[string]goasmrules.X86PackedBinaryWitness, len(cases))
		for _, fixture := range cases {
			expected[fixture.row+"/"+fixture.witness.Instruction] = fixture.witness
		}
		witnesses := 0
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				key := row.ID + "/" + witness.Instruction
				original, found := expected[key]
				if !found || !bytes.Equal(original.Encoding, witness.Encoding) || original.Destination != witness.Destination {
					t.Fatal("MOVE transport differs from the independent actual-Go fixture", key, original, witness)
				}
				delete(expected, key)
				witnesses++
			}
		}
		if len(rows) != 18 || witnesses != 36 || len(expected) != 2 {
			t.Fatal("complete MOVE row/witness/first-match union changed", arch, len(rows), witnesses, len(expected))
		}
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				batch := cases[start:end]
				var source strings.Builder
				line := 1
				for index := range batch {
					fixture := &batch[index]
					fixture.symbol = fmt.Sprintf("X87MoveOriginal%d", start+index)
					fixture.line = line + 1
					body := fmt.Sprintf("TEXT ·%s(SB),4,$0-0\n%s\nRET\n", fixture.symbol, fixture.witness.Instruction)
					source.WriteString(body)
					line += strings.Count(body, "\n")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal("actual Go refused the original MOVE row/alias batch", err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("actual Go MOVE direction, pop or first-match bytes differ", err)
				}
			})
		}
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_X87_MOVE_ROW_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86X87Row
		}{catalog, modes})
	}
}

func TestX86OfficialLegacyX87MoveOriginalEmitterObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	objects := 0
	for _, arch := range []string{"amd64", "386"} {
		cases := x86X87MoveOriginalSourceCases(t, catalog)
		for start := 0; start < len(cases); start += 32 {
			end := start + 32
			if end > len(cases) {
				end = len(cases)
			}
			t.Run(fmt.Sprintf("%s/batch%d", arch, start/32), func(t *testing.T) {
				var source strings.Builder
				source.WriteString("TEXT ·X87MoveEmitter(SB),4,$0-0\n")
				for _, fixture := range cases[start:end] {
					source.WriteString("FINIT\n")
					source.WriteString(fixture.witness.Instruction)
					source.WriteByte('\n')
				}
				source.WriteString("RET\n")
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				for _, triple := range x86Legacy127Targets(arch) {
					ir := x86X87LowererObjectUnit(t, file, arch, triple)
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, triple, ir, level)
						objects++
					}
				}
				t.Logf("private emitter only: retained %d original MOVE row/alias operations; no numerical or execution claim", end-start)
			})
		}
	}
	if objects != 20 {
		t.Fatal("complete five-target O0/O2 MOVE object matrix changed", objects)
	}
}
