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

// Source ownership is narrower than shared operand tables. In particular,
// ARPL, INVPCID and FS/GS-base operations retain independent contracts.
func gpDataFlagsCPU100Member(entry goasmrules.X86LegacyOpcode) bool {
	switch entry.Ytab {
	case "yxorb", "ytestl", "ybtl", "ybswap":
		return true
	case "ym_rl":
		return strings.HasPrefix(entry.Opcode, "LEA")
	case "yrb_mb", "yrl_ml":
		return strings.HasPrefix(entry.Opcode, "XADD") || strings.HasPrefix(entry.Opcode, "CMPXCHG") ||
			strings.HasPrefix(entry.Opcode, "MOVNTI") || entry.Opcode == "MOVQL"
	case "yscond":
		return entry.Opcode == "CMPXCHG8B" || entry.Opcode == "CMPXCHG16B"
	case "ycrc32b", "ycrc32l":
		return strings.HasPrefix(entry.Opcode, "CRC32") || strings.HasPrefix(entry.Opcode, "TZCNT")
	case "yrdrand":
		return strings.HasPrefix(entry.Opcode, "RDRAND") || strings.HasPrefix(entry.Opcode, "RDSEED") || entry.Opcode == "RDPID"
	}
	return false
}

// This independent reference models Go's source prefix and Z-case emission.
// Actual Go objects below validate the model before any production-view join.
// Strides select a later row; they are not the selected encoding's byte count.
func gpDataFlagsCPU100OriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog) []x86OfficialPackedCase {
	t.Helper()
	var cases []x86OfficialPackedCase
	rows := 0
	for _, entry := range catalog.Optab {
		if !gpDataFlagsCPU100Member(entry) {
			continue
		}
		var atoms []byte
		for _, token := range entry.OpBytes {
			value, err := strconv.ParseUint(token, 0, 8)
			if err != nil {
				t.Fatal("independent GP original byte changed", entry, token, err)
			}
			atoms = append(atoms, byte(value))
		}
		width := entry.Opcode[len(entry.Opcode)-1]
		source, destination, accumulator := "CX", "BX", "AX"
		if width == 'B' {
			source, destination, accumulator = "CL", "BL", "AL"
		}
		for _, row := range entry.Rows {
			rows++
			prefixes := map[string][]byte{
				"Px": {}, "Pb": {}, "Pe": {0x66}, "Pm": {0x0f},
				"Pq": {0x66, 0x0f}, "Pw": {0x48}, "Pf3": {0xf3, 0x0f},
			}
			prefix, found := prefixes[entry.Prefix]
			if !found || row.UnmatchedOffset < 0 || row.UnmatchedOffset >= len(atoms) {
				t.Fatal("independent GP original prefix/row changed", entry, row)
			}
			code := append([]byte(nil), prefix...)
			cursor := row.UnmatchedOffset
			if atoms[cursor] == 0x0f {
				code = append(code, 0x0f)
				cursor++
			}
			if cursor >= len(atoms) {
				t.Fatal("missing independent GP opcode", entry, row)
			}
			var operands [][2]string
			switch row.ZCase {
			case "Zib_", "Zil_":
				operands = append(operands, [2]string{"$128", accumulator})
			case "Zibo_m", "Zilo_m":
				immediate := "$128"
				if row.Classes[0] == "Yi8" {
					immediate = "$1"
				}
				operands = append(operands, [2]string{immediate, destination}, [2]string{immediate, "0(SI)"})
			case "Zr_m":
				// The Go table also admits a MOVNTI register destination.
				// Like pair CAS below, that CPU-invalid encoding is retained
				// only as a source observation, never a numerical positive.
				operands = append(operands, [2]string{source, destination})
				operands = append(operands, [2]string{source, "0(SI)"})
			case "Zm_r":
				// Register/register matches the earlier direction for the
				// TEST/byte tables. LEA's Ym source is memory syntax only.
				operands = append(operands, [2]string{"0(SI)", destination})
			case "Zlitm_r":
				operands = append(operands, [2]string{source, "BX"}, [2]string{"0(SI)", "BX"})
			case "Zo_m":
				if entry.Ytab == "yrdrand" {
					operands = append(operands, [2]string{"", "BX"})
				} else {
					// Go's Ymb also admits register encodings for pair CAS.
					// These are source observations only; hardware requires
					// memory and they must not become numerical positives.
					operands = append(operands, [2]string{"", destination}, [2]string{"", "0(SI)"})
				}
			case "Z_rp":
				operands = append(operands, [2]string{"", "BX"})
			default:
				t.Fatal("unmodeled independent GP source Z-case", entry, row)
			}
			for _, args := range operands {
				encoding := append([]byte(nil), code...)
				memory := args[0] == "0(SI)" || args[1] == "0(SI)"
				rm := byte(0xc3)
				if memory {
					rm = 6
				}
				encoding = append(encoding, atoms[cursor])
				switch row.ZCase {
				case "Zib_", "Zil_":
				case "Zibo_m", "Zilo_m", "Zo_m":
					if cursor+1 >= len(atoms) || atoms[cursor+1] > 7 {
						t.Fatal("independent opcode extension changed", entry, row)
					}
					encoding = append(encoding, rm|atoms[cursor+1]<<3)
				case "Zr_m":
					encoding = append(encoding, rm|1<<3)
				case "Zm_r":
					encoding = append(encoding, byte(6|3<<3))
				case "Z_rp":
					encoding[len(encoding)-1] += 3
				case "Zlitm_r":
					literal := atoms[row.UnmatchedOffset:]
					end := 0
					for end < len(literal) && literal[end] != 0 {
						end++
					}
					if end == len(literal) || end == 0 {
						t.Fatal("independent complete literal span changed", entry)
					}
					literal = literal[:end]
					encoding = append(append([]byte(nil), prefix...), literal...)
					if entry.Prefix == "Pw" {
						// Mandatory F2/F3 precedes REX, as in Go's final pass.
						encoding = append([]byte{literal[0], 0x48}, literal[1:]...)
					}
					if !memory {
						rm = 0xc1
					}
					encoding = append(encoding, rm|3<<3)
				}
				if strings.HasPrefix(args[0], "$") {
					immediate, err := strconv.ParseInt(args[0][1:], 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					bytes := 1
					if width != 'B' && row.Classes[0] != "Yi8" {
						bytes = 4
						if width == 'W' {
							bytes = 2
						}
					}
					for i := 0; i < bytes; i++ {
						encoding = append(encoding, byte(uint64(immediate)>>uint(8*i)))
					}
				}
				instruction := entry.Opcode + " " + args[1]
				if args[0] != "" {
					instruction = entry.Opcode + " " + args[0] + "," + args[1]
				}
				cases = append(cases, x86OfficialPackedCase{
					row:     fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex),
					witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Destination: args[1], Encoding: encoding},
				})
			}
		}
	}
	if rows != 99 && rows != 100 || len(cases) != rows+66 {
		t.Fatal("independent complete GP source formats changed", rows, len(cases))
	}
	return cases
}

func TestX86GPDataFlagsCPUOriginalGoCompleteBytesAndModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := gpDataFlagsCPU100OriginalCases(t, catalog)
	prefixes := map[string]string{}
	for _, entry := range catalog.Optab {
		prefixes[entry.Opcode] = entry.Prefix
	}
	observations, accepted, refused := 0, 0, 0
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var positives []x86OfficialPackedCase
			for _, original := range originals {
				observations++
				name := strings.Fields(original.witness.Instruction)[0]
				if arch != "386" || prefixes[name] != "Pw" {
					accepted++
					positives = append(positives, original)
					continue
				}
				refused++
				t.Run("mode-refusal/"+original.row+"/"+original.witness.Instruction, func(t *testing.T) {
					source := "TEXT ·NoMode(SB),4,$0-0\n" + original.witness.Instruction + "\nRET\n"
					listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
					if !strings.Contains(listing, "asmins: illegal 64:") || !strings.Contains(listing, name) {
						t.Fatal("missing original source mode diagnostic", original, listing)
					}
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
					batch[i].symbol = fmt.Sprintf("GPData%d", start+i)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[i].symbol)
					batch[i].line = strings.Count(source.String(), "\n") + 1
					fmt.Fprintln(&source, batch[i].witness.Instruction)
					source.WriteString("RET\n")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal("original complete GP source batch rejected", arch, start, err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("independent original GP row/encoding mismatch", arch, start, err)
				}
			}
		})
	}
	if observations != 2*len(originals) || refused != 38 || accepted != observations-38 {
		t.Fatal("complete GP source mode observation matrix changed", observations, accepted, refused)
	}
	t.Logf("GP_DATA_FLAGS_CPU_ACTUAL_GO observations=%d accepted=%d exact_mode_refusals=%d", observations, accepted, refused)
	// Every production witness is joined to the independently assembled
	// original ID, instruction, byte encoding and destination. Retain mode
	// refusals as rows without promoting them to source-encoding witnesses.
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86GPDataFlagsCPURows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		expected := map[string]x86OfficialPackedCase{}
		for _, original := range originals {
			name := strings.Fields(original.witness.Instruction)[0]
			if arch == "386" && prefixes[name] == "Pw" {
				continue
			}
			key := original.row + "/" + original.witness.Instruction
			if _, duplicate := expected[key]; duplicate {
				t.Fatal("duplicate independent original source witness", key)
			}
			expected[key] = original
		}
		seen, filtered := map[string]bool{}, 0
		for _, row := range rows {
			if seen[row.ID] {
				t.Fatal("duplicate original source row", row.ID)
			}
			seen[row.ID] = true
			if row.ModeFiltered != "" {
				if arch != "386" || prefixes[row.Opcode] != "Pw" || len(row.Witnesses) != 0 {
					t.Fatal("source mode refusal was widened", arch, row)
				}
				filtered++
				continue
			}
			for _, witness := range row.Witnesses {
				key := row.ID + "/" + witness.Instruction
				original, found := expected[key]
				if !found || witness.Destination != original.witness.Destination ||
					!bytes.Equal(witness.Encoding, original.witness.Encoding) {
					t.Fatal("production source view differs from actual-Go ID/bytes/direction", arch, key, witness, original)
				}
				delete(expected, key)
			}
		}
		wantFiltered := 0
		if arch == "386" {
			wantFiltered = 22
		}
		if len(rows) != 99 && len(rows) != 100 || filtered != wantFiltered || len(expected) != 0 {
			t.Fatal("incomplete whole GP source join", arch, len(rows), filtered, len(expected))
		}
		modes[arch] = rows
	}
	if _, err := goasmrules.X86GPDataFlagsCPURows(catalog, "arm64"); err == nil {
		t.Fatal("foreign source mode accepted")
	}
	x86Legacy127SaveIdentity(t, "PLAN9ASM_GP_DATA_FLAGS_CPU_IDENTITY_OUTPUT", struct {
		Source goasmrules.X86LegacyCatalog
		Modes  map[string][]goasmrules.X86ScalarRMWRow
	}{catalog, modes})
}

func TestX86GPDataFlagsCPUOriginalGoImmediateClassBoundaries(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := gpDataFlagsCPU100OriginalCases(t, catalog)
	entries := map[string]goasmrules.X86LegacyOpcode{}
	for _, entry := range catalog.Optab {
		entries[entry.Opcode] = entry
	}
	observations, accepted, rejected := 0, 0, 0
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var positives []x86OfficialPackedCase
			for _, original := range originals {
				name := strings.Fields(original.witness.Instruction)[0]
				entry := entries[name]
				if !strings.HasSuffix(original.row, "/0") || !strings.Contains(original.witness.Instruction, "$") ||
					strings.Contains(original.witness.Instruction, "(") || arch == "386" && entry.Prefix == "Pw" {
					continue
				}
				if entry.Ytab != "yxorb" && entry.Ytab != "ytestl" && entry.Ytab != "ybtl" {
					continue
				}
				for _, value := range []int64{-129, -128, -1, 0, 1, 127, 128, 255, 256} {
					observations++
					fixture := original
					comma := strings.IndexByte(original.witness.Instruction, ',')
					fixture.witness.Instruction = fmt.Sprintf("%s $%d%s", name, value, original.witness.Instruction[comma:])
					valid := entry.Ytab != "ybtl" || value >= -128 && value <= 127
					if !valid {
						rejected++
						t.Run(fixture.witness.Instruction, func(t *testing.T) {
							listing, _ := x86ScalarLiteralExpectedGoListing(t, arch,
								"TEXT ·NoImmediate(SB),4,$0-0\n"+fixture.witness.Instruction+"\nRET\n", false)
							if !strings.Contains(listing, name) {
								t.Fatal("missing original immediate-class refusal", fixture.row, listing)
							}
						})
						continue
					}
					accepted++
					bytes := 1
					if entry.Ytab == "ytestl" {
						bytes = 4
						if strings.HasSuffix(name, "W") {
							bytes = 2
						}
					}
					fixture.witness.Encoding = append([]byte(nil), original.witness.Encoding...)
					for i := 0; i < bytes; i++ {
						fixture.witness.Encoding[len(fixture.witness.Encoding)-bytes+i] = byte(uint64(value) >> uint(8*i))
					}
					positives = append(positives, fixture)
				}
			}
			for start := 0; start < len(positives); start += 32 {
				end := start + 32
				if end > len(positives) {
					end = len(positives)
				}
				batch := append([]x86OfficialPackedCase(nil), positives[start:end]...)
				var source strings.Builder
				for i := range batch {
					batch[i].symbol = fmt.Sprintf("GPImmediate%d", start+i)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", batch[i].symbol)
					batch[i].line = strings.Count(source.String(), "\n") + 1
					fmt.Fprintln(&source, batch[i].witness.Instruction)
					source.WriteString("RET\n")
				}
				listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
				if err != nil {
					t.Fatal(err)
				}
				if err := x86OfficialPackedVerifyListing(listing, batch); err != nil {
					t.Fatal("original Yi8/Yi32 source-byte boundary mismatch", arch, start, err)
				}
			}
		})
	}
	if observations != 369 || accepted != 289 || rejected != 80 {
		t.Fatal("complete Yi8/Yi32 boundary inventory changed", observations, accepted, rejected)
	}
	t.Logf("GP_DATA_FLAGS_CPU_IMMEDIATES observations=%d exact_bytes=%d source_refusals=%d", observations, accepted, rejected)
}

// MOVQL is Go's 32-bit 0x89 alias. Its source encoding being representable
// does not prove that the existing named translator dispatch implements it.
func TestX86GPDataFlagsCPUMOVQLInitializedThreeAPIObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var cases []x86OfficialPackedCase
	for _, original := range gpDataFlagsCPU100OriginalCases(t, catalog) {
		if strings.HasPrefix(original.witness.Instruction, "MOVQL ") {
			cases = append(cases, original)
		}
	}
	if len(cases) != 2 {
		t.Fatal("complete MOVQL original source directions changed", len(cases))
	}
	for _, arch := range []string{"amd64", "386"} {
		x86Legacy127Objects(t, arch, cases, x86ScalarRMRegisterInitializedFunction)
	}
}
