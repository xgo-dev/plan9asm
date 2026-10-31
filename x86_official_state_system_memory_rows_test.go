package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func stateSystemSourceTable(table string) bool {
	switch table {
	case "yclflush", "ysvrs_mo", "ysvrs_om", "yin", "yint", "ydivl", "ydivb",
		"ywrfsbase", "ycrc32l", "yprefetch", "yincq", "yrdrand", "ym_rl",
		"yrl_m", "yrl_ml", "yxbegin", "yxabort":
		return true
	}
	return false
}

// This source-only reference follows Go's prefix switch, selected Z-case and
// final REX insertion. It never calls a production witness formatter and none
// of these assembled instructions is executed. Privileged and CPU-invalid
// encodings remain source observations, not numerical/native positives.
func stateSystemOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) ([]x86OfficialPackedCase, []x86OfficialPackedCase) {
	t.Helper()
	var accepted, refused []x86OfficialPackedCase
	for _, entry := range catalog.Optab {
		if !stateSystemSourceTable(entry.Ytab) {
			continue
		}
		var atoms []byte
		for _, token := range entry.OpBytes {
			value, err := strconv.ParseUint(token, 0, 8)
			if err != nil {
				t.Fatal("independent original system byte changed", entry, token, err)
			}
			atoms = append(atoms, byte(value))
		}
		for _, row := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			prefix, found := map[string][]byte{
				"Px": {}, "Pb": {}, "P32": {}, "Pe": {0x66}, "Pm": {0x0f},
				"Pq": {0x66, 0x0f}, "Pf2": {0xf2, 0x0f}, "Pf3": {0xf3, 0x0f},
				"Pw": {}, "Pfw": {0xf3, 0x0f},
			}[entry.Prefix]
			cursor := row.UnmatchedOffset
			if !found || cursor < 0 || cursor >= len(atoms) {
				t.Fatal("independent system prefix/row offset changed", entry, row)
			}
			code := append([]byte(nil), prefix...)
			if atoms[cursor] == 0x0f {
				code = append(code, 0x0f)
				cursor++
			}
			if cursor >= len(atoms) {
				t.Fatal("independent system selected opcode missing", entry, row)
			}
			if row.ZCase == "Zlit" || row.ZCase == "Zlitm_r" {
				// A missing explicit terminator is valid when Go's fixed
				// opcode array supplies implicit zero padding, e.g. yin.
				for end := cursor; end < len(atoms) && atoms[end] != 0; end++ {
					code = append(code, atoms[end])
				}
			} else {
				code = append(code, atoms[cursor])
			}
			if entry.Prefix == "Pw" || entry.Prefix == "Pfw" {
				position := 0
				for position < len(code) && (code[position] == 0x66 || code[position] == 0xf2 || code[position] == 0xf3) {
					position++
				}
				code = append(code[:position], append([]byte{0x48}, code[position:]...)...)
			}
			var operands [][2]string
			switch row.ZCase {
			case "Zm_o", "Zo_m":
				if len(row.Classes) != 1 {
					t.Fatal("independent unary system operand arity changed", entry, row)
				}
				switch row.Classes[0] {
				case "Ymb":
					operands = [][2]string{{"", "BL"}, {"", "0(SI)"}}
				case "Yml":
					operands = [][2]string{{"", "BX"}, {"", "0(SI)"}}
				case "Yrl":
					operands = [][2]string{{"", "BX"}}
				case "Ym":
					operands = [][2]string{{"", "0(SI)"}}
				default:
					t.Fatal("independent system register/memory class changed", entry, row)
				}
			case "Zr_m":
				operands = [][2]string{{"CX", "0(SI)"}}
				if row.Classes[1] == "Yml" {
					operands = append([][2]string{{"CX", "BX"}}, operands...)
				}
			case "Zm_r":
				operands = [][2]string{{"0(SI)", "BX"}}
			case "Zlitm_r":
				operands = [][2]string{{"CX", "BX"}, {"0(SI)", "BX"}}
			case "Zib_":
				operands = [][2]string{{"", "$7"}}
			case "Zlit":
				operands = [][2]string{{"", ""}}
			case "Zjmp":
				// A next-instruction target has an independently known zero
				// rel32. It is not a numeric target or a new raw permission.
				operands = [][2]string{{"", "1(PC)"}}
			default:
				t.Fatal("independent complete system Z-case changed", entry, row)
			}
			for _, args := range operands {
				encoding := append([]byte(nil), code...)
				memory := args[0] == "0(SI)" || args[1] == "0(SI)"
				rm := byte(0xc3)
				if memory {
					rm = 6
				}
				switch row.ZCase {
				case "Zm_o", "Zo_m":
					if cursor+1 >= len(atoms) || atoms[cursor+1] > 7 {
						t.Fatal("independent system /digit changed", entry, row)
					}
					encoding = append(encoding, rm|atoms[cursor+1]<<3)
				case "Zr_m":
					encoding = append(encoding, rm|1<<3)
				case "Zm_r":
					encoding = append(encoding, byte(6|3<<3))
				case "Zlitm_r":
					if !memory {
						rm = 0xc1
					}
					encoding = append(encoding, rm|3<<3)
				case "Zib_":
					if entry.Ytab == "yxabort" {
						encoding = append(encoding, atoms[cursor+1])
					}
					encoding = append(encoding, 7)
				case "Zjmp":
					encoding = append(encoding, atoms[cursor+1], 0, 0, 0, 0)
				}
				instruction := entry.Opcode
				if args[0] != "" {
					instruction += " " + args[0] + "," + args[1]
				} else if args[1] != "" {
					instruction += " " + args[1]
				}
				fixture := x86OfficialPackedCase{row: id, witness: goasmrules.X86PackedBinaryWitness{
					Instruction: instruction, Encoding: encoding,
				}}
				filtered := arch == "amd64" && entry.Prefix == "P32" ||
					arch == "386" && (entry.Prefix == "Pw" || entry.Prefix == "Pfw")
				if filtered {
					// One original source statement suffices for each refused
					// row; accepted modes retain all register/memory cases.
					refused = append(refused, fixture)
					break
				}
				accepted = append(accepted, fixture)
			}
		}
	}
	want, filtered := 188, 2
	if arch == "386" {
		want, filtered = 145, 31
	}
	hasRDPID := false
	for _, entry := range catalog.Optab {
		hasRDPID = hasRDPID || entry.Opcode == "RDPID"
	}
	if !hasRDPID {
		want--
	}
	if len(accepted) != want || len(refused) != filtered {
		t.Fatal("complete independent system source denominator changed", arch, len(accepted), len(refused), want, filtered)
	}
	return accepted, refused
}

func stateSystemOriginalXBEGINRelocation(t *testing.T, arch string) {
	t.Helper()
	const symbol = "SystemExternalBranch"
	const instruction = "XBEGIN ·ExternalTarget(SB)"
	source := "TEXT ·" + symbol + "(SB),4,$0-0\n" + instruction + "\nRET\n"
	listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, true)
	fixture := x86OfficialPackedCase{
		symbol: symbol, line: 2, row: "original-XBEGIN-external-rel32",
		witness: goasmrules.X86PackedBinaryWitness{
			Instruction: instruction, Encoding: []byte{0xc7, 0xf8, 0, 0, 0, 0},
		},
	}
	if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{fixture}); err != nil {
		t.Fatal("actual Go XBEGIN external opcode/rel32 bytes differ", err)
	}
	// Bind the older numeric spelling to this SDK's own generated assertion.
	// The source-only relocation is not a callable/native-entry permission.
	enum, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "objabi", "reloctype_string.go"))
	if err != nil {
		t.Fatal(err)
	}
	kinds := regexp.MustCompile(`x\[R_CALL-([0-9]+)\]`).FindAllStringSubmatch(string(enum), -1)
	if len(kinds) != 1 {
		t.Fatal("actual SDK must declare one exact R_CALL relocation value")
	}
	prefix := ""
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "STEXT" {
			for _, candidate := range []string{"literal.", `"".`} {
				if fields[0] == candidate+symbol {
					prefix = candidate
				}
			}
		}
	}
	if prefix == "" {
		t.Fatal("original Go XBEGIN lacks its exact local package owner")
	}
	pattern := regexp.MustCompile(`(?m)^\s*rel 2\+4 t=(?:R_CALL|` + kinds[0][1] + `) ` +
		regexp.QuoteMeta(prefix+"ExternalTarget") + `\+0\s*$`)
	complete := func(text string) bool {
		count := 0
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == "rel" {
				count++
			}
		}
		return count == 1 && len(pattern.FindAllString(text, -1)) == 1
	}
	if !complete(listing) {
		t.Fatal("original Go XBEGIN lacks its unique offset2/width4/R_CALL/target/addend relocation", listing)
	}
	valid := "rel 2+4 t=" + kinds[0][1] + " " + prefix + "ExternalTarget+0\n"
	for _, damaged := range []string{
		"", valid + valid,
		strings.Replace(valid, "2+4", "3+4", 1),
		strings.Replace(valid, "2+4", "2+8", 1),
		strings.Replace(valid, "t="+kinds[0][1], "t=R_ADDR", 1),
		strings.Replace(valid, "ExternalTarget", "ForeignTarget", 1),
		strings.Replace(valid, "+0", "+1", 1),
	} {
		if complete(damaged) {
			t.Fatal("damaged XBEGIN relocation satisfied the independent oracle", damaged)
		}
	}
	t.Logf("STATE_SYSTEM_ORIGINAL_XBEGIN_RELOCATION arch=%s offset=2 width=4 SDK_R_CALL=%s target=%sExternalTarget addend=0; source-only", arch, kinds[0][1], prefix)
}

func TestX86OfficialStateSystemMemoryOriginalGoBytesAndModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch+"/external-XBEGIN-relocation", func(t *testing.T) {
			stateSystemOriginalXBEGINRelocation(t, arch)
		})
		accepted, refused := stateSystemOriginalCases(t, catalog, arch)
		x86LegacyLiteralSIMDCheckGoBatches(t, arch, accepted)
		for _, fixture := range refused {
			t.Run(arch+"/mode-refused/"+fixture.row, func(t *testing.T) {
				source := "TEXT ·Refused(SB),4,$0-0\n" + fixture.witness.Instruction + "\nRET\n"
				listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
				opcode := strings.Fields(fixture.witness.Instruction)[0]
				if !strings.Contains(listing, opcode) ||
					!strings.Contains(listing, "illegal 64") && !strings.Contains(listing, "illegal in") {
					t.Fatal("Go mode refusal did not identify the original instruction and source mode", fixture.row, listing)
				}
			})
		}
	}
}

func TestX86OfficialStateSystemMemoryOriginalImmediateBoundaries(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		originals, _ := stateSystemOriginalCases(t, catalog, arch)
		var accepted []x86OfficialPackedCase
		observed := 0
		for _, original := range originals {
			if !strings.Contains(original.witness.Instruction, " $7") {
				continue
			}
			observed++
			values := []int64{-2147483648, -1, 0, 127, 128, 255, 256, 2147483647, 4294967295}
			if strings.HasPrefix(original.witness.Instruction, "XABORT ") {
				values = []int64{0, 1, 127, 128, 255}
			}
			for _, value := range values {
				fixture := original
				fixture.witness.Instruction = strings.Replace(original.witness.Instruction, "$7", fmt.Sprintf("$%d", value), 1)
				fixture.witness.Encoding = append([]byte(nil), original.witness.Encoding...)
				fixture.witness.Encoding[len(fixture.witness.Encoding)-1] = byte(value)
				accepted = append(accepted, fixture)
			}
		}
		if observed != 8 || len(accepted) != 68 {
			t.Fatal("complete Yi32/Yu8 system immediate inventory changed", arch, observed, len(accepted))
		}
		x86LegacyLiteralSIMDCheckGoBatches(t, arch, accepted)
		for _, instruction := range []string{"XABORT $-1", "XABORT $256"} {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT ·Refused(SB),4,$0-0\n" + instruction + "\nRET\n"
				listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
				if !strings.Contains(listing, "XABORT") || !strings.Contains(listing, "invalid instruction") {
					t.Fatal("Go Yu8 refusal did not identify the original instruction", listing)
				}
			})
		}
	}
}
