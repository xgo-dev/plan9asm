// This observes Go source bytes; privileged/obsolete forms are never executed.
package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Separate source producers share an ID union, never numerical permissions
// or membership in the other producer's grammar.
func movtabCompleteSourceJoin(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) map[string]goasmrules.X86ScalarRMWRow {
	t.Helper()
	rows, err := goasmrules.X86ScalarShiftRotateRows(catalog, arch)
	if err != nil {
		t.Fatal(err)
	}
	joined := map[string]goasmrules.X86ScalarRMWRow{}
	for _, row := range rows {
		if strings.HasPrefix(row.ID, "ymovtab/") {
			joined[row.ID] = row
		}
	}
	if len(joined) != 18 {
		t.Fatal("original double-shift join changed", len(joined))
	}
	remainder, err := goasmrules.X86MovtabRemainderRows(catalog, arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range remainder {
		if _, duplicate := joined[row.ID]; duplicate {
			t.Fatal("separate source producers duplicated an original ID", row.ID)
		}
		joined[row.ID] = row
	}
	if len(remainder) != 92 || len(joined) != 110 {
		t.Fatal("non-TLS source join changed", len(remainder), len(joined))
	}
	return joined
}

func TestX86MovtabRemainderCompleteSourceJoin(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := movtabRemainderOriginalCases(t, catalog)
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			joined := movtabCompleteSourceJoin(t, catalog, arch)
			count := 0
			for _, original := range catalog.Movtab {
				if original.Kind != "encoding" || original.Code == "movDoubleShift" {
					continue
				}
				count++
				id := fmt.Sprintf("ymovtab/%d/%s/%s", original.TableIndex, original.Opcode, original.Code)
				t.Run(id, func(t *testing.T) {
					actual, found := joined[id]
					if original.Code == "movTLSReg" {
						// These two remain source-byte gaps. Actual OS/shared
						// profiles and relocation owners are separate evidence.
						if found {
							t.Fatal("TLS metadata was counted as a successful source encoding", actual)
						}
						instruction := x86PureGPUnknownInstruction(t, original.Opcode+" TLS,AX")
						if err := x86SourceTLSMoveError(instruction, arch); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unbound TLS source lost its actual-context boundary", err)
						}
						return
					}
					if !found {
						t.Fatal("MOVTAB_REMAINDER_SOURCE_ID_FEATURE_GAP", id)
					}
					if actual.ID != id || actual.Opcode != original.Opcode {
						t.Fatal("source join changed the original row identity", original, actual)
					}
					var expected []x86OfficialPackedCase
					for _, fixture := range originals {
						if fixture.row == id {
							expected = append(expected, fixture)
						}
					}
					if len(expected) == 0 {
						t.Fatal("source join lost its independent original byte reference", id)
					}
					if arch == "386" && strings.Contains(expected[0].witness.Instruction, "CR8") {
						if actual.ModeFiltered == "" || len(actual.Witnesses) != 0 {
							t.Fatal("386 CR8 original refusal became a successful source encoding", actual)
						}
						return
					}
					if actual.ModeFiltered != "" || len(actual.Witnesses) != len(expected) {
						t.Fatal("source witness count, mode or context changed", actual, len(expected))
					}
					for index, witness := range actual.Witnesses {
						fixture := expected[index].witness
						if witness.Instruction != fixture.Instruction || witness.Destination != fixture.Destination || string(witness.Encoding) != string(fixture.Encoding) {
							t.Fatal("source join changed original Go syntax, first-match or bytes", witness, fixture)
						}
					}
				})
			}
			if count != 94 {
				t.Fatal("complete remainder source denominator changed", count)
			}
			t.Log("MOVTAB_SOURCE_JOIN proven_rows=92 pending_TLS_source_rows=2 original_double_shift_rows=18")
			for _, original := range catalog.Movtab {
				if original.Kind != "encoding" || original.Code == "movDoubleShift" || original.Code == "movTLSReg" {
					continue
				}
				id := fmt.Sprintf("ymovtab/%d/%s/%s", original.TableIndex, original.Opcode, original.Code)
				modes[arch] = append(modes[arch], joined[id])
			}
		})
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_MOVTAB_REMAINDER_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86ScalarRMWRow
		}{catalog, modes})
	}
}

func TestX86MovtabRemainderCompleteOriginalSchema(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Movtab) != 113 {
		t.Fatal("complete ymovtab, including sentinel, changed", len(catalog.Movtab))
	}
	want := map[string]int{
		"movLit": 26, "movRegMem": 6, "movMemReg": 6,
		"movRegMem2op": 27, "movMemReg2op": 27,
		"movDoubleShift": 18, "movTLSReg": 2,
	}
	counts := map[string]int{}
	for index, row := range catalog.Movtab {
		if row.TableIndex != index {
			t.Fatal("original table order changed", row)
		}
		if index == 112 {
			if row.Kind != "sentinel" || row.Opcode != "" || row.OpcodeExpression != "0" ||
				row.From != "0" || row.From3 != "0" || row.To != "0" || row.Code != "0" || len(row.OpBytes) != 0 {
				t.Fatal("explicit movtab sentinel changed", row)
			}
			continue
		}
		if row.Kind != "encoding" || len(row.OpBytes) > 4 ||
			strings.TrimPrefix(row.OpcodeExpression, "obj.") != "A"+row.Opcode {
			t.Fatal("original move schema/source identity changed", row)
		}
		if _, found := want[row.Code]; !found {
			t.Fatal("unowned original move code", row)
		}
		if row.Code != "movDoubleShift" && row.From3 != "Ynone" {
			t.Fatal("ordinary fallback move acquired a third source operand", row)
		}
		counts[row.Code]++
	}
	for code, expected := range want {
		if counts[code] != expected {
			t.Fatal("complete move-code source count changed", code, counts[code], expected)
		}
	}
	// The eighteen existing fallback shifts are not eighteen new identities.
	rows, err := goasmrules.X86ScalarShiftRotateRows(catalog, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	shiftIDs := map[string]bool{}
	for _, row := range rows {
		if strings.HasPrefix(row.ID, "ymovtab/") {
			shiftIDs[row.ID] = true
		}
	}
	for _, original := range catalog.Movtab {
		if original.Code == "movDoubleShift" {
			id := fmt.Sprintf("ymovtab/%d/%s/movDoubleShift", original.TableIndex, original.Opcode)
			if !shiftIDs[id] {
				t.Fatal("existing double-shift source owner was lost", id)
			}
		}
	}
	if len(shiftIDs) != 18 {
		t.Fatal("existing double-shift source union changed", len(shiftIDs))
	}
}

// Independent reference for Go's five non-TLS fallback emission branches.
// No separate per-mnemonic opcode table: original payloads supply the bytes.
func movtabRemainderOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	rows := 0
	for _, row := range catalog.Movtab {
		if row.Kind != "encoding" || row.Code == "movDoubleShift" || row.Code == "movTLSReg" {
			continue
		}
		rows++
		var payload [4]byte
		for index, atom := range row.OpBytes {
			if row.Code == "movLit" && index == 0 && atom == "Pe" {
				payload[index] = 0x66
				continue
			}
			value, err := strconv.ParseUint(atom, 0, 8)
			if err != nil {
				t.Fatal("invalid original source byte atom", row, index, atom, err)
			}
			payload[index] = byte(value)
		}
		add := func(arguments string, code []byte) {
			cases = append(cases, x86OfficialPackedCase{
				row: fmt.Sprintf("ymovtab/%d/%s/%s", row.TableIndex, row.Opcode, row.Code),
				witness: goasmrules.X86PackedBinaryWitness{
					Instruction: row.Opcode + " " + arguments,
					Destination: arguments[strings.LastIndex(arguments, ",")+1:],
					Encoding:    append([]byte(nil), code...),
				},
			})
		}
		if row.Code == "movLit" {
			end := 0
			for end < len(payload) && payload[end] != 0 {
				end++
			}
			if end == 0 || end == len(payload) {
				t.Fatal("unterminated or empty segment-stack literal", row)
			}
			class := row.From
			if class == "Ynone" {
				class = row.To
			}
			add(strings.ToUpper(strings.TrimPrefix(class, "Y")), payload[:end])
			continue
		}
		special, ordinary := row.From, row.To
		toSpecial := row.Code == "movMemReg" || row.Code == "movMemReg2op"
		if toSpecial {
			special, ordinary = row.To, row.From
		}
		var operands []string
		switch ordinary {
		case "Yrl":
			operands = []string{"BX"}
		case "Yml":
			operands = []string{"BX", "0(SI)"}
		case "Ym":
			operands = []string{"0(SI)"}
		default:
			t.Fatal("unknown ordinary side of original move fallback", row)
		}
		special = strings.ToUpper(strings.TrimPrefix(special, "Y"))
		span := 1
		if strings.HasSuffix(row.Code, "2op") {
			span = 2
		}
		for _, operand := range operands {
			modrm := byte(0xc3) // BX
			if operand == "0(SI)" {
				modrm = 6
			}
			code := append([]byte(nil), payload[:span]...)
			extension := payload[span]
			if extension > 7 {
				// CR8 is carried in REX.R, not REX.W or a Q suffix.
				if special != "CR8" || extension != 8 {
					t.Fatal("unknown special-register extension", row)
				}
				code = append([]byte{0x44}, code...)
			}
			code = append(code, modrm|(extension&7)<<3)
			arguments := special + "," + operand
			if toSpecial {
				arguments = operand + "," + special
			}
			add(arguments, code)
		}
	}
	if rows != 92 || len(cases) != 114 {
		t.Fatal("complete non-TLS move source inventory changed", rows, len(cases))
	}
	return cases
}

func TestX86MovtabRemainderOriginalGoBytesAndModeRefusals(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := movtabRemainderOriginalCases(t, catalog)
	accepted, refused := 0, 0
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var positives []x86OfficialPackedCase
			for _, original := range originals {
				if arch == "386" && strings.Contains(original.witness.Instruction, "CR8") {
					refused++
					t.Run(original.witness.Instruction, func(t *testing.T) {
						listing, _ := x86ScalarLiteralExpectedGoListing(t, arch,
							"TEXT ·NoCR8(SB),4,$0-0\n"+original.witness.Instruction+"\nRET\n", false)
						if !strings.Contains(listing, "asmins: illegal in mode 32:") || !strings.Contains(listing, "CR8") {
							t.Fatal("missing original 386 REX source refusal", original, listing)
						}
					})
					continue
				}
				accepted++
				positives = append(positives, original)
			}
			for start := 0; start < len(positives); start += 32 {
				end := start + 32
				if end > len(positives) {
					end = len(positives)
				}
				batch := append([]x86OfficialPackedCase(nil), positives[start:end]...)
				var source strings.Builder
				for index := range batch {
					batch[index].symbol = fmt.Sprintf("MoveRemainder%d", start+index)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[index].symbol)
					operation := strings.Fields(batch[index].witness.Instruction)[0]
					width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[operation[len(operation)-1]]
					if strings.HasPrefix(operation, "POP") {
						fmt.Fprintf(&source, "ADJSP $%d\n", width)
					}
					batch[index].line = strings.Count(source.String(), "\n") + 1
					fmt.Fprintln(&source, batch[index].witness.Instruction)
					if strings.HasPrefix(operation, "PUSH") {
						fmt.Fprintf(&source, "ADJSP $-%d\n", width)
					}
					source.WriteString("RET\n")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal("original fallback source batch rejected", arch, start, err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("independent fallback source byte mismatch", arch, start, err)
				}
			}
		})
	}
	if accepted != 224 || refused != 4 {
		t.Fatal("original fallback source/mode matrix changed", accepted, refused)
	}
}
