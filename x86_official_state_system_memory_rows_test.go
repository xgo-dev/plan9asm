package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The stock assembler's refusal and this original backend observation are
// independent. Only this actual observer can turn a candidate backend byte
// sequence into evidence; it grants no numerical or native-entry permission.
func TestX86StateSystemMemoryOriginalBackend(t *testing.T) {
	const root = "TestPlan9asmOriginalStateSystemBackend"
	output := x86OriginalGoBackendOutput(t, "testdata/goasm/state_system_backend_test.go", root)
	type record struct {
		Arch, Opcode, Origin string
		PC                   int64
		Encoding             []byte
		Offset, Size, Kind   int
		KindName, Symbol     string
		Add                  int64
	}
	runs, passes := map[string]int{}, map[string]int{}
	records := map[string]record{}
	packagePasses := 0
	for _, line := range bytes.Split(bytes.TrimSpace(output), []byte{'\n'}) {
		var event struct{ Action, Test, Output string }
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal("original backend emitted non-JSON output", err, string(line))
		}
		switch event.Action {
		case "run":
			runs[event.Test]++
		case "pass":
			if event.Test == "" {
				packagePasses++
			} else {
				passes[event.Test]++
			}
		case "fail", "skip", "build-fail":
			t.Fatal("original backend did not complete every owned case", event)
		}
		const marker = "PLAN9ASM_STATE_SYSTEM_BACKEND "
		if position := strings.Index(event.Output, marker); position >= 0 {
			var actual record
			if err := json.Unmarshal([]byte(strings.TrimSpace(event.Output[position+len(marker):])), &actual); err != nil {
				t.Fatal("invalid actual backend record", err)
			}
			name := actual.Arch + "/" + actual.Opcode
			if _, duplicate := records[name]; duplicate || event.Test != root+"/"+name {
				t.Fatal("backend record lost its unique actual test owner", name, event.Test)
			}
			records[name] = actual
		}
	}
	if len(runs) != 5 || len(passes) != 5 || packagePasses != 1 || len(records) != 4 || runs[root] != 1 || passes[root] != 1 {
		t.Fatal("incomplete actual backend execution", runs, passes, packagePasses, records)
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := goasmrules.LoadX86UnaryDestinations(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86StateSystemMemoryRows(catalog, frontend, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, opcode := range []string{"FLDENV", "XBEGIN"} {
			name := arch + "/" + opcode
			t.Run(name, func(t *testing.T) {
				actual, found := records[name]
				if !found || runs[root+"/"+name] != 1 || passes[root+"/"+name] != 1 || actual.Origin != "stock-backend" || actual.PC != 13 {
					t.Fatal("backend identity or execution differs", name, actual)
				}
				if opcode == "XBEGIN" {
					// The fixture compares Type to the actual SDK objabi.R_CALL;
					// never share a hard-coded relocation enum across SDKs.
					if !bytes.Equal(actual.Encoding, []byte{0xc7, 0xf8, 0, 0, 0, 0}) || actual.Offset != 15 || actual.Size != 4 || actual.Kind <= 0 || actual.KindName != "R_CALL" || actual.Symbol != "plan9asm.backend.target" || actual.Add != 0 {
						t.Fatal("actual external branch encoding or relocation differs", actual)
					}
				} else {
					if !bytes.Equal(actual.Encoding, []byte{0xd9, 0x26}) || actual.Offset != 0 || actual.Size != 0 || actual.Kind != 0 || actual.KindName != "" || actual.Symbol != "" || actual.Add != 0 {
						t.Fatal("actual FLDENV encoding or absent relocation differs", actual)
					}
					joined := 0
					for _, row := range rows {
						if row.Opcode == opcode {
							if row.FrontendRejected == "" || row.ModeFiltered != "" || len(row.Witnesses) != 0 || len(row.BackendWitnesses) != 1 || !bytes.Equal(row.BackendWitnesses[0].Encoding, actual.Encoding) {
								t.Fatal("backend bytes lost the original frontend boundary", row)
							}
							joined++
						}
					}
					if joined != 1 {
						t.Fatal("actual backend record did not join exactly one original source row", joined)
					}
				}
				t.Logf("ACTUAL_STATE_SYSTEM_BACKEND arch=%s opcode=%s bytes=%x relocation=%s/%d pc=%d", arch, opcode, actual.Encoding, actual.KindName, actual.Kind, actual.PC)
			})
		}
	}
}

func stateSystemOriginalUnaryDestinations(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/obj6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]bool{}
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "unaryDst" || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("original unaryDst is not a complete source literal")
			}
			for _, element := range literal.Elts {
				pair := element.(*ast.KeyValueExpr)
				key, setting := pair.Key.(*ast.Ident), pair.Value.(*ast.Ident)
				if !strings.HasPrefix(key.Name, "A") || setting.Name != "true" && setting.Name != "false" {
					t.Fatal("original unaryDst key/value changed", element)
				}
				result[strings.TrimPrefix(key.Name, "A")] = setting.Name == "true"
			}
		}
	}
	if len(result) == 0 {
		t.Fatal("actual SDK has no captured unaryDst source roles")
	}
	return result
}

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
func stateSystemOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) ([]x86OfficialPackedCase, []x86OfficialPackedCase, []x86OfficialPackedCase) {
	t.Helper()
	var accepted, refused, frontend []x86OfficialPackedCase
	unary := stateSystemOriginalUnaryDestinations(t)
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
				destination := args[1]
				if row.ZCase == "Zm_o" || row.ZCase == "Zib_" {
					destination = ""
				}
				fixture := x86OfficialPackedCase{row: id, witness: goasmrules.X86PackedBinaryWitness{
					Instruction: instruction, Encoding: encoding, Destination: destination,
				}}
				if (row.ZCase == "Zm_o" || row.ZCase == "Zo_m") && unary[entry.Opcode] != (row.ZCase == "Zo_m") {
					frontend = append(frontend, fixture)
					break // Retained separately: stock frontend and backend slots disagree.
				}
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
	want, filtered := 187, 2
	if arch == "386" {
		want, filtered = 144, 31
	}
	hasRDPID := false
	for _, entry := range catalog.Optab {
		hasRDPID = hasRDPID || entry.Opcode == "RDPID"
	}
	if !hasRDPID {
		want--
	}
	if len(accepted) != want || len(refused) != filtered || len(frontend) != 1 {
		t.Fatal("complete independent system source denominator changed", arch, len(accepted), len(refused), len(frontend), want, filtered)
	}
	return accepted, refused, frontend
}

func stateSystemOriginalXBEGINBoundary(t *testing.T, arch string) {
	t.Helper()
	const external = "XBEGIN ·ExternalTarget(SB)"
	source := "TEXT ·SystemExternalBranch(SB),4,$0-0\n" + external + "\nRET\n"
	listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
	if !strings.Contains(listing, "XBEGIN") || !strings.Contains(listing, "invalid instruction") {
		t.Fatal("original external XBEGIN lacks its concrete frontend rejection", listing)
	}
	// Stock asm preserves an SB target as TYPE_MEM, which does not match Ybr.
	// Local branches are distinct source positives, including relative fixups.
	for _, row := range []struct {
		name, instruction, tail string
		encoding                []byte
	}{
		{"self", "XBEGIN 0(PC)", "", []byte{0xc7, 0xf8, 0xfa, 0xff, 0xff, 0xff}},
		{"forward", "XBEGIN 2(PC)", "BYTE $0x90\n", []byte{0xc7, 0xf8, 1, 0, 0, 0}},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := "TEXT ·LocalBranch(SB),4,$0-0\n" + row.instruction + "\n" + row.tail + "RET\n"
			actual, _ := x86ScalarLiteralExpectedGoListing(t, arch, body, true)
			fixture := x86OfficialPackedCase{symbol: "LocalBranch", line: 2, row: "original-XBEGIN-local-rel32",
				witness: goasmrules.X86PackedBinaryWitness{Instruction: row.instruction, Encoding: row.encoding}}
			if err := x86OfficialPackedVerifyListing(actual, []x86OfficialPackedCase{fixture}); err != nil {
				t.Fatal("original local XBEGIN rel32 fixup differs", err)
			}
			for _, line := range strings.Split(actual, "\n") {
				fields := strings.Fields(line)
				if len(fields) > 0 && fields[0] == "rel" {
					t.Fatal("local XBEGIN unexpectedly requires an external relocation", line)
				}
			}
		})
	}
}

func stateSystemOriginalFrontendFailure(t *testing.T, arch string, fixture x86OfficialPackedCase) {
	t.Helper()
	// This known SDK slot mismatch is not an ordinary syntax rejection.
	dir := t.TempDir()
	input, object := filepath.Join(dir, "frontend.s"), filepath.Join(dir, "frontend.o")
	body := "TEXT ·SystemFrontend(SB),4,$0-0\n" + fixture.witness.Instruction + "\nRET\n"
	if err := os.WriteFile(input, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	stage, stop := runtimeOracleStageContext(t)
	defer stop()
	ctx, cancel := context.WithTimeout(stage, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "tool", "asm", "-S", "-p", "literal", "-o", object, input)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || ctx.Err() != nil || !strings.Contains(string(output), "asm: asmand: bad address") {
		t.Fatalf("actual original From/To mismatch has no exact SDK failure: %v / %v\n%s", err, ctx.Err(), output)
	}
	t.Logf("ORIGINAL_FRONTEND_FAILURE_OUTPUT:\n%s", output)
	strict := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), false, arch)
	if strict == nil || !strings.Contains(strict.Error(), "infrastructure failure") {
		t.Fatal("positionless SDK diagnostic became a bound syntax rejection", strict)
	}
	// A single failed function need not produce a listing or complete object.
	// Its source rejection supplies no successful byte witness. The original
	// backend, when given From directly, has a separate encoding observation.
	unchanged, readErr := os.ReadFile(input)
	if readErr != nil || string(unchanged) != body {
		t.Fatal("owned original frontend source changed", readErr)
	}
	t.Logf("STATE_SYSTEM_STOCK_FRONTEND_FAILURE arch=%s id=%s sourceSHA=%x outputSHA=%x; unaryDst and Z-case slots disagree; not assembled or translated", arch, fixture.row, sha256.Sum256([]byte(body)), sha256.Sum256(output))
}

func TestX86OfficialStateSystemMemoryOriginalGoBytesAndModes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	roles, err := goasmrules.LoadX86UnaryDestinations(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86StateSystemMemoryRow{}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch+"/XBEGIN-source-boundaries", func(t *testing.T) {
			stateSystemOriginalXBEGINBoundary(t, arch)
		})
		accepted, refused, frontend := stateSystemOriginalCases(t, catalog, arch)
		for _, fixture := range frontend {
			t.Run(arch+"/frontend-failure/"+fixture.row, func(t *testing.T) {
				stateSystemOriginalFrontendFailure(t, arch, fixture)
			})
		}
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
		actual, err := goasmrules.X86StateSystemMemoryRows(catalog, roles, arch)
		if err != nil {
			t.Fatal(err)
		}
		stateSystemJoinOriginalCases(t, arch, actual, accepted, refused, frontend)
		modes[arch] = actual
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_STATE_SYSTEM_MEMORY_IDENTITY_OUTPUT", struct {
			Source   goasmrules.X86LegacyCatalog
			Frontend map[string]bool
			Modes    map[string][]goasmrules.X86StateSystemMemoryRow
		}{catalog, stateSystemOriginalUnaryDestinations(t), modes})
	}
}

func stateSystemJoinOriginalCases(t *testing.T, arch string, rows []goasmrules.X86StateSystemMemoryRow, accepted, modeRefused, frontend []x86OfficialPackedCase) {
	t.Helper()
	expected := map[string]goasmrules.X86PackedBinaryWitness{}
	for _, fixture := range accepted {
		expected[fixture.row+"/"+fixture.witness.Instruction] = fixture.witness
	}
	filtered, rejected := map[string]bool{}, map[string]x86OfficialPackedCase{}
	for _, fixture := range modeRefused {
		filtered[fixture.row] = true
	}
	for _, fixture := range frontend {
		rejected[fixture.row] = fixture
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.ID] {
			t.Fatal("duplicate original state source ID", arch, row.ID)
		}
		seen[row.ID] = true
		if original, found := rejected[row.ID]; found {
			if row.FrontendRejected == "" || row.ModeFiltered != "" || len(row.Witnesses) != 0 || len(row.BackendWitnesses) != 1 {
				t.Fatal("frontend failure became a mode/target filter or a successful named-source witness", row)
			}
			candidate := row.BackendWitnesses[0]
			if candidate.Instruction != original.witness.Instruction || candidate.Destination != original.witness.Destination || string(candidate.Encoding) != string(original.witness.Encoding) {
				t.Fatal("backend candidate differs from the complete original encoding table", row, original)
			}
			delete(rejected, row.ID)
			continue
		}
		if filtered[row.ID] {
			if row.ModeFiltered == "" || row.FrontendRejected != "" || len(row.Witnesses) != 0 || len(row.BackendWitnesses) != 0 {
				t.Fatal("original mode rejection became a successful source encoding", row)
			}
			delete(filtered, row.ID)
			continue
		}
		if row.ModeFiltered != "" || row.FrontendRejected != "" || len(row.BackendWitnesses) != 0 || len(row.Witnesses) == 0 {
			t.Fatal("valid original source disappeared or changed its origin", row)
		}
		for _, witness := range row.Witnesses {
			key := row.ID + "/" + witness.Instruction
			original, found := expected[key]
			if !found || witness.Destination != original.Destination || string(witness.Encoding) != string(original.Encoding) {
				t.Fatal("state source ID/instruction/encoding/destination differs from actual original Go", arch, row.ID, witness, original)
			}
			delete(expected, key)
		}
	}
	if len(expected) != 0 || len(filtered) != 0 || len(rejected) != 0 {
		t.Fatal("state source projection omitted original cases", arch, len(expected), len(filtered), len(rejected))
	}
}

func TestX86OfficialStateSystemMemoryOriginalImmediateBoundaries(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		originals, _, _ := stateSystemOriginalCases(t, catalog, arch)
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
