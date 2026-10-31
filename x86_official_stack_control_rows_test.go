package plan9asm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type x86StackControlRelocation struct {
	Offset, Size int
	Kind, Symbol string
	Add          int64
}

type x86StackControlSourceWitness struct {
	goasmrules.X86ScalarRMWWitness
	Origin      string
	Relocations []x86StackControlRelocation
}

type x86StackControlSourceRow struct {
	Opcode, ModeFiltered string
	Witnesses            []x86StackControlSourceWitness
}

type x86StackControlOriginalCase struct {
	x86OfficialPackedCase
	origin      string
	relocations []x86StackControlRelocation
	padding     int
	refused     bool
}

// Older original backends surround AMD64 DUFF calls with their own BP
// transport. Capture both the byte declarations and their actual use; their
// presence is a source fact, not a hard-coded Go-version choice.
func x86StackControlOriginalDuffFrame(t *testing.T) ([]byte, []byte) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	values, uses := map[string][]byte{}, map[string]int{}
	for _, declaration := range file.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.VAR {
			for _, specification := range group.Specs {
				specification, ok := specification.(*ast.ValueSpec)
				if !ok || len(specification.Names) != 1 || len(specification.Values) != 1 {
					continue
				}
				name := specification.Names[0].Name
				if name != "bpduff1" && name != "bpduff2" {
					continue
				}
				literal, ok := specification.Values[0].(*ast.CompositeLit)
				if !ok || values[name] != nil {
					t.Fatal("ambiguous original DUFF BP declaration", name)
				}
				for _, element := range literal.Elts {
					atom, ok := element.(*ast.BasicLit)
					if !ok || atom.Kind != token.INT {
						t.Fatal("nonliteral original DUFF BP byte", name)
					}
					value, err := strconv.ParseUint(atom.Value, 0, 8)
					if err != nil {
						t.Fatal(err)
					}
					values[name] = append(values[name], byte(value))
				}
			}
		}
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "doasm" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Put" {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			argument, named := call.Args[0].(*ast.Ident)
			if ok && named && receiver.Name == "ab" && (argument.Name == "bpduff1" || argument.Name == "bpduff2") {
				uses[argument.Name]++
			}
			return true
		})
	}
	if len(values) == 0 && len(uses) == 0 {
		return nil, nil
	}
	if len(values) != 2 || len(uses) != 2 || uses["bpduff1"] != 1 || uses["bpduff2"] != 1 {
		t.Fatal("incomplete original DUFF BP source transport", values, uses)
	}
	return values["bpduff1"], values["bpduff2"]
}

func x86StackControlOriginalCases(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) []x86StackControlOriginalCase {
	t.Helper()
	var result []x86StackControlOriginalCase
	duffBefore, duffAfter := x86StackControlOriginalDuffFrame(t)
	rows := 0
	for _, entry := range catalog.Optab {
		switch entry.Ytab {
		case "ycall", "yloop", "yjmp", "ypopl", "ypushl", "yret", "yduff":
		default:
			continue
		}
		var payload []byte
		for _, atom := range entry.OpBytes {
			value, err := strconv.ParseUint(atom, 0, 8)
			if err != nil {
				t.Fatal("original stack/control byte atom", entry.Opcode, atom, err)
			}
			payload = append(payload, byte(value))
		}
		var prefix []byte
		if entry.Prefix == "Pe" {
			prefix = []byte{0x66}
		} else if entry.Prefix == "Pw" {
			prefix = []byte{0x48}
		}
		for _, operand := range entry.Rows {
			rows++
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, operand.RowIndex)
			offset := operand.UnmatchedOffset
			add := func(arguments string, code []byte, padding int, relocations ...x86StackControlRelocation) {
				instruction := strings.TrimSpace(entry.Opcode + " " + arguments)
				origin := "stock-asm"
				if operand.ZCase == "Zcallduff" {
					origin = "stock-backend"
				}
				result = append(result, x86StackControlOriginalCase{
					x86OfficialPackedCase: x86OfficialPackedCase{row: id, witness: goasmrules.X86PackedBinaryWitness{
						Instruction: instruction, Destination: arguments[strings.LastIndex(arguments, ",")+1:],
						Encoding: append(append([]byte(nil), prefix...), code...),
					}}, origin: origin, relocations: relocations, padding: padding,
					refused: entry.Prefix == "P32" && arch == "amd64" || (entry.Prefix == "Py" || entry.Prefix == "Pw") && arch == "386",
				})
			}
			rel := func(kind, symbol string, addend int64, displacement, size int) x86StackControlRelocation {
				return x86StackControlRelocation{len(prefix) + displacement, size, kind, symbol, addend}
			}
			switch operand.ZCase {
			case "Z_rp", "Zrp_":
				add("BX", []byte{payload[offset] + 3}, 0)
			case "Zo_m", "Zm_o", "Zo_m64", "Zcallindreg":
				operands := []string{"0(SI)"}
				if operand.ZCase == "Zo_m64" || operand.ZCase == "Zcallindreg" {
					operands = []string{"BX", "0(SI)"}
				}
				if len(operand.Classes) == 2 {
					operands = []string{"CX,BX"}
				}
				for _, arguments := range operands {
					modrm := byte(6)
					if strings.HasSuffix(arguments, "BX") {
						modrm = 0xc3
					}
					var relocations []x86StackControlRelocation
					if operand.ZCase == "Zcallindreg" {
						relocations = []x86StackControlRelocation{rel("R_CALLIND", "", 0, 0, 0)}
					}
					add(arguments, []byte{payload[offset], modrm | payload[offset+1]<<3}, 0, relocations...)
				}
			case "Zib_", "Zil_":
				immediate, width := 7, 1
				if operand.ZCase == "Zil_" {
					immediate, width = 300, 4
					if entry.Prefix == "Pe" {
						width = 2
					}
				}
				code := []byte{payload[offset]}
				for index := 0; index < width; index++ {
					code = append(code, byte(immediate>>uint(index*8)))
				}
				add(fmt.Sprintf("$%d", immediate), code, 0)
			case "Zo_iw":
				code, arguments := []byte{payload[offset]}, ""
				if len(operand.Classes) != 0 {
					code, arguments = append(code, 37, 0), "$37"
				}
				add(arguments, code, 0)
			case "Zcallind":
				kind := "R_PCREL"
				if arch == "386" {
					kind = "R_ADDR"
				}
				// checkaddr permits *name(SB), not *name+offset(SB).
				add("*·Target(SB)", []byte{payload[offset], payload[offset+1], 0, 0, 0, 0}, 0,
					rel(kind, "literal.Target", 0, 2, 4))
			case "Zcall", "Zcallduff":
				arguments, symbol := "·Target+7(SB)", "literal.Target"
				addend := int64(7)
				if operand.ZCase == "Zcallduff" {
					symbol, addend = "runtime."+strings.ToLower(entry.Opcode), 37
					arguments = "$" + strings.Replace(symbol, ".", "·", 1) + "+37(SB)"
				}
				code, displacement := []byte{payload[offset], 0, 0, 0, 0}, 1
				if operand.ZCase == "Zcallduff" && arch == "amd64" {
					code = append(append(append([]byte(nil), duffBefore...), code...), duffAfter...)
					displacement += len(duffBefore)
				}
				add(arguments, code, 0, rel("R_CALL", symbol, addend, displacement, 4))
			case "Zcallcon", "Zjmpcon":
				opcode := payload[offset]
				if operand.ZCase == "Zjmpcon" {
					opcode = payload[offset+1]
				}
				add("$37", []byte{opcode, 0, 0, 0, 0}, 0, rel("R_PCREL", "", 37, 1, 4))
			case "Zloop", "Zjmp":
				code := []byte{payload[offset], 1}
				if entry.Opcode == "JCXZL" {
					code = append([]byte{0x67}, code...)
				}
				add("after", code, 1)
				if operand.ZCase == "Zjmp" {
					add("after", []byte{payload[offset+1], 160, 0, 0, 0}, 160)
					add("·Target(SB)", []byte{payload[offset+1], 0, 0, 0, 0}, 0,
						rel("R_CALL", "literal.Target", 0, 1, 4))
				}
			default:
				t.Fatal("unmodeled original stack/control zcase", entry, operand)
			}
		}
	}
	if rows != 40 || len(result) != 44 {
		t.Fatal("complete stack/control source inventory changed", rows, len(result))
	}
	return result
}

func x86StackControlOriginalSource(cases []x86StackControlOriginalCase) (string, []x86StackControlOriginalCase) {
	var source strings.Builder
	for index := range cases {
		fixture := &cases[index]
		fixture.symbol = fmt.Sprintf("StackControl%d", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),516,$0-0\n", fixture.symbol)
		operation := strings.Fields(fixture.witness.Instruction)[0]
		width := 0
		if strings.HasPrefix(operation, "PUSH") || strings.HasPrefix(operation, "POP") {
			width = map[byte]int{'W': 2, 'L': 4, 'Q': 8}[operation[len(operation)-1]]
		}
		if strings.HasPrefix(operation, "POP") {
			fmt.Fprintf(&source, "ADJSP $%d\n", width)
		}
		fixture.line = strings.Count(source.String(), "\n") + 1
		fmt.Fprintln(&source, fixture.witness.Instruction)
		if strings.HasPrefix(operation, "PUSH") {
			fmt.Fprintf(&source, "ADJSP $-%d\n", width)
		}
		for index := 0; index < fixture.padding; index++ {
			source.WriteString("BYTE $144\n")
		}
		if fixture.padding != 0 {
			source.WriteString("after:\n")
		}
		source.WriteString("RET\n")
	}
	return source.String(), cases
}

func x86StackControlRelocationEnums(t *testing.T) map[string]string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/objabi/reloctype_string.go"))
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, kind := range []string{"R_ADDR", "R_PCREL", "R_CALL", "R_CALLIND"} {
		expression := `(?m)^[\t ]*_ = x\[` + kind + `-([0-9]+)\][\t ]*$`
		matches := regexp.MustCompile(expression).FindAllStringSubmatch(string(source), -1)
		if len(matches) != 1 {
			t.Fatal("selected SDK lacks one exact relocation enum assertion", kind, len(matches))
		}
		result[matches[0][1]] = kind
	}
	return result
}

func x86StackControlVerifyListing(listing string, cases []x86StackControlOriginalCase, enums map[string]string) error {
	var packed []x86OfficialPackedCase
	owners := map[string]x86StackControlOriginalCase{}
	for _, fixture := range cases {
		packed, owners[fixture.symbol] = append(packed, fixture.x86OfficialPackedCase), fixture
	}
	if err := x86OfficialPackedVerifyListing(listing, packed); err != nil {
		return err
	}
	var owner string
	pc, target := -1, -1
	var observed []x86StackControlRelocation
	finish := func() error {
		if owner == "" {
			return nil
		}
		fixture := owners[owner]
		if pc < 0 {
			return fmt.Errorf("missing actual source PC: %s", fixture.row)
		}
		expected := append([]x86StackControlRelocation(nil), fixture.relocations...)
		for index := range expected {
			expected[index].Offset += pc
		}
		if !reflect.DeepEqual(observed, expected) {
			return fmt.Errorf("actual PC/relocation differs for %s: got=%+v want=%+v", fixture.row, observed, expected)
		}
		if fixture.padding != 0 && target-pc != len(fixture.witness.Encoding)+fixture.padding {
			return fmt.Errorf("local branch lost actual target PC for %s: %d -> %d", fixture.row, pc, target)
		}
		return nil
	}
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "0x") && strings.HasPrefix(fields[1], "S") {
			if err := finish(); err != nil {
				return err
			}
			owner, pc, target, observed = "", -1, -1, nil
			if fields[1] == "STEXT" || fields[1] == "STEXTFIPS" {
				owner = strings.TrimPrefix(strings.TrimPrefix(fields[0], "literal."), `"".`)
			}
			continue
		}
		if owner == "" {
			continue
		}
		if match := x86OfficialPackedListingInstruction.FindStringSubmatch(line); match != nil {
			position, _ := strconv.Atoi(match[2])
			lineNumber, _ := strconv.Atoi(match[3])
			if lineNumber == owners[owner].line {
				pc = position
			}
			if match[4] == "RET" {
				target = position
			}
		}
		if len(fields) != 0 && fields[0] == "rel" {
			if len(fields) != 4 || !strings.HasPrefix(fields[2], "t=") {
				return fmt.Errorf("malformed complete relocation: %s", line)
			}
			var offset, size int
			if _, err := fmt.Sscanf(fields[1], "%d+%d", &offset, &size); err != nil || fields[1] != fmt.Sprintf("%d+%d", offset, size) {
				return fmt.Errorf("invalid relocation span: %s", line)
			}
			kind := strings.TrimPrefix(fields[2], "t=")
			if symbolic, found := enums[kind]; found {
				kind = symbolic
			}
			separator := strings.LastIndex(fields[3], "+")
			if separator < 0 {
				return fmt.Errorf("missing exact relocation symbol/addend: %s", line)
			}
			addend, err := strconv.ParseInt(fields[3][separator+1:], 10, 64)
			if err != nil {
				return err
			}
			symbol := fields[3][:separator]
			if strings.HasPrefix(symbol, `"".`) {
				symbol = "literal." + strings.TrimPrefix(symbol, `"".`)
			}
			observed = append(observed, x86StackControlRelocation{offset, size, kind, symbol, addend})
		}
	}
	return finish()
}

func TestX86StackControlOriginalGoBytesPCAndRelocations(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	enums := x86StackControlRelocationEnums(t)
	accepted, refused := 0, 0
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var positives []x86StackControlOriginalCase
			for _, fixture := range x86StackControlOriginalCases(t, catalog, arch) {
				if fixture.origin != "stock-asm" {
					continue
				}
				if fixture.refused {
					refused++
					t.Run(fixture.row, func(t *testing.T) {
						source, _ := x86StackControlOriginalSource([]x86StackControlOriginalCase{fixture})
						listing, _ := x86ScalarLiteralExpectedGoListing(t, arch, source, false)
						if !strings.Contains(listing, "asmins: illegal") || !strings.Contains(listing, strings.Fields(fixture.witness.Instruction)[0]) {
							t.Fatal("missing actual mode refusal for original source", fixture.row, listing)
						}
					})
					continue
				}
				accepted++
				positives = append(positives, fixture)
			}
			for start := 0; start < len(positives); start += 16 {
				end := start + 16
				if end > len(positives) {
					end = len(positives)
				}
				source, batch := x86StackControlOriginalSource(append([]x86StackControlOriginalCase(nil), positives[start:end]...))
				listing, _ := x86ScalarLiteralGoListing(t, arch, source)
				if err := x86StackControlVerifyListing(listing, batch, enums); err != nil {
					t.Fatalf("actual stock-asm bytes/PC/relocations: %v\n%s", err, listing)
				}
			}
		})
	}
	if accepted != 70 || refused != 14 {
		t.Fatal("complete stock-asm source/mode inventory changed", accepted, refused)
	}
}

// The tests-only probe deliberately calls existing source views, so an absent
// new view produces real FEATURE RED assertions, never undefined-symbol 0 RUN.
func x86StackControlExistingSourceJoin(t *testing.T, catalog goasmrules.X86LegacyCatalog, arch string) map[string]x86StackControlSourceRow {
	t.Helper()
	joined := map[string]x86StackControlSourceRow{}
	for _, load := range []func(goasmrules.X86LegacyCatalog, string) ([]goasmrules.X86ScalarRMWRow, error){
		goasmrules.X86ScalarRMWRows, goasmrules.X86ScalarRMRegisterRows, goasmrules.X86ZeroOperandRows,
	} {
		rows, err := load(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			observed := x86StackControlSourceRow{Opcode: row.Opcode, ModeFiltered: row.ModeFiltered}
			for _, witness := range row.Witnesses {
				observed.Witnesses = append(observed.Witnesses, x86StackControlSourceWitness{X86ScalarRMWWitness: witness, Origin: "stock-asm"})
			}
			joined[row.ID] = observed
		}
	}
	return joined
}

func TestX86StackControlCompleteSourceJoin(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			joined := x86StackControlExistingSourceJoin(t, catalog, arch)
			expected := map[string][]x86StackControlOriginalCase{}
			for _, fixture := range x86StackControlOriginalCases(t, catalog, arch) {
				expected[fixture.row] = append(expected[fixture.row], fixture)
			}
			for id, fixtures := range expected {
				t.Run(id, func(t *testing.T) {
					actual, found := joined[id]
					if !found {
						t.Fatal("STACK_CONTROL_SOURCE_ID_FEATURE_GAP", id)
					}
					if actual.Opcode != strings.Fields(fixtures[0].witness.Instruction)[0] {
						t.Fatal("source opcode disagrees with its complete original ID", id, actual)
					}
					if fixtures[0].refused {
						if actual.ModeFiltered == "" || len(actual.Witnesses) != 0 {
							t.Fatal("actual mode-refused source became a byte witness", id, actual)
						}
						return
					}
					if actual.ModeFiltered != "" || len(actual.Witnesses) != len(fixtures) {
						t.Fatal("complete source witness count changed", id, len(actual.Witnesses), len(fixtures))
					}
					for index, observed := range actual.Witnesses {
						fixture := fixtures[index]
						if observed.Instruction != fixture.witness.Instruction || observed.Destination != fixture.witness.Destination ||
							!bytes.Equal(observed.Encoding, fixture.witness.Encoding) || observed.Origin != fixture.origin ||
							!reflect.DeepEqual(observed.Relocations, fixture.relocations) {
							t.Fatal("exact source instruction/bytes/destination/origin/relocations changed", observed, fixture)
						}
					}
				})
			}
			if len(expected) != 40 {
				t.Fatal("source ID denominator changed", len(expected))
			}
		})
	}
}

type x86StackControlBackendRecord struct {
	Arch, Opcode, Origin string
	PC                   int64
	Encoding             []byte
	Offset, Size, Kind   int
	Symbol               string
	Add                  int64
}

func x86StackControlVerifyBackendRecord(record x86StackControlBackendRecord, arch string, fixture x86StackControlOriginalCase, kind int) error {
	if record.Arch != arch || record.Opcode != strings.Fields(fixture.witness.Instruction)[0] ||
		record.Origin != "stock-backend" || fixture.origin != "stock-backend" || record.PC != 13 ||
		!bytes.Equal(record.Encoding, fixture.witness.Encoding) || len(fixture.relocations) != 1 {
		return fmt.Errorf("original backend source identity/PC/bytes changed: %+v", record)
	}
	expected := fixture.relocations[0]
	if record.Offset != int(record.PC)+expected.Offset || record.Size != expected.Size || record.Kind != kind ||
		record.Symbol == "" || record.Symbol != expected.Symbol || record.Add != expected.Add {
		return fmt.Errorf("original backend relocation identity changed: %+v", record)
	}
	return nil
}

func TestX86StackControlOriginalGoBackendDuffs(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]x86StackControlOriginalCase{}
	for _, arch := range []string{"amd64", "386"} {
		for _, fixture := range x86StackControlOriginalCases(t, catalog, arch) {
			if fixture.origin == "stock-backend" {
				expected[arch+"/"+strings.Fields(fixture.witness.Instruction)[0]] = fixture
			}
		}
	}
	kind := -1
	for number, name := range x86StackControlRelocationEnums(t) {
		if name == "R_CALL" {
			kind, _ = strconv.Atoi(number)
		}
	}
	output := x86OriginalGoBackendOutput(t, "testdata/goasm/stack_control_backend_test.go", "TestPlan9asmOriginalDuffSource")
	if destination := os.Getenv("PLAN9ASM_STACK_CONTROL_BACKEND_OUTPUT"); destination != "" {
		if err := os.WriteFile(destination, output, 0600); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	runs, passes := 0, 0
	for _, line := range bytes.Split(output, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event struct{ Action, Test, Output string }
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal("non-JSON actual backend command output", err, string(line))
		}
		if event.Test == "TestPlan9asmOriginalDuffSource" && event.Action == "run" {
			runs++
		} else if event.Test == "TestPlan9asmOriginalDuffSource" && event.Action == "pass" {
			passes++
		} else if event.Action == "fail" || event.Action == "skip" {
			t.Fatal("backend observer failed or skipped", event)
		}
		const marker = "PLAN9ASM_SOURCE_DUFF "
		position := strings.Index(event.Output, marker)
		if event.Action != "output" || position < 0 {
			continue
		}
		var record x86StackControlBackendRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(event.Output[position+len(marker):])), &record); err != nil {
			t.Fatal(err)
		}
		key := record.Arch + "/" + record.Opcode
		fixture, found := expected[key]
		if !found || seen[key] {
			t.Fatal("unowned or duplicate actual backend source record", key)
		}
		if err := x86StackControlVerifyBackendRecord(record, record.Arch, fixture, kind); err != nil {
			t.Fatal(err)
		}
		t.Logf("ACTUAL_STACK_CONTROL_BACKEND %s", strings.TrimSpace(event.Output[position+len(marker):]))
		seen[key] = true
	}
	if runs != 1 || passes != 1 || len(seen) != 4 || len(expected) != 4 {
		t.Fatal("incomplete actual backend observation", runs, passes, len(seen), len(expected))
	}
	t.Log("STACK_CONTROL_BACKEND_SOURCE rows=2 actual_mode_records=4 stock_frontend_successes=0 native_execution=0")
}

func TestX86StackControlBackendEvidenceRejectsCounterfeits(t *testing.T) {
	fixture := x86StackControlOriginalCase{origin: "stock-backend",
		x86OfficialPackedCase: x86OfficialPackedCase{witness: goasmrules.X86PackedBinaryWitness{
			Instruction: "DUFFCOPY $runtime·duffcopy+37(SB)", Encoding: []byte{0xe8, 0, 0, 0, 0}}},
		relocations: []x86StackControlRelocation{{1, 4, "R_CALL", "runtime.duffcopy", 37}}}
	original := x86StackControlBackendRecord{"amd64", "DUFFCOPY", "stock-backend", 13,
		[]byte{0xe8, 0, 0, 0, 0}, 14, 4, 93, "runtime.duffcopy", 37}
	if err := x86StackControlVerifyBackendRecord(original, "amd64", fixture, 93); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*x86StackControlBackendRecord){
		"nil-symbol":              func(r *x86StackControlBackendRecord) { r.Symbol = "" },
		"foreign-symbol":          func(r *x86StackControlBackendRecord) { r.Symbol = "runtime.duffzero" },
		"foreign-relocation":      func(r *x86StackControlBackendRecord) { r.Kind++ },
		"wrong-addend":            func(r *x86StackControlBackendRecord) { r.Add++ },
		"wrong-PC":                func(r *x86StackControlBackendRecord) { r.PC++ },
		"correlated-wrong-PC":     func(r *x86StackControlBackendRecord) { r.PC++; r.Offset++ },
		"wrong-relocation-offset": func(r *x86StackControlBackendRecord) { r.Offset++ },
		"wrong-relocation-size":   func(r *x86StackControlBackendRecord) { r.Size = 0 },
		"frontend-misattribution": func(r *x86StackControlBackendRecord) { r.Origin = "stock-asm" },
		"foreign-mode":            func(r *x86StackControlBackendRecord) { r.Arch = "386" },
		"truncated-bytes":         func(r *x86StackControlBackendRecord) { r.Encoding = r.Encoding[:4] },
		"different-opcode":        func(r *x86StackControlBackendRecord) { r.Encoding = []byte{0xe9, 0, 0, 0, 0} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if err := x86StackControlVerifyBackendRecord(changed, "amd64", fixture, 93); err == nil {
				t.Fatal("counterfeit backend source evidence was accepted", name, changed)
			}
		})
	}
}

func TestX86StackControlListingRejectsIncompleteRelocations(t *testing.T) {
	fixture := x86StackControlOriginalCase{origin: "stock-asm",
		x86OfficialPackedCase: x86OfficialPackedCase{row: "optab/fixture/CALL/ycall/3", symbol: "Row0", line: 2,
			witness: goasmrules.X86PackedBinaryWitness{Instruction: "CALL ·Target+7(SB)", Destination: "·Target+7(SB)",
				Encoding: []byte{0xe8, 0, 0, 0, 0}}},
		relocations: []x86StackControlRelocation{{1, 4, "R_CALL", "literal.Target", 7}}}
	listing := `literal.Row0 STEXT nosplit asm size=6 align=0x0 args=0x0 locals=0x0
  0x0000 00000 (literal.s:1) TEXT literal.Row0(SB), NOSPLIT|NOFRAME, $0-0
  0x0000 00000 (literal.s:2) CALL literal.Target+7(SB)
  0x0005 00005 (literal.s:3) RET
` + fmt.Sprintf("  0x0000%-48s  ......\n", " e8 00 00 00 00 c3") + "\trel 1+4 t=R_CALL literal.Target+7\n"
	enums := map[string]string{"93": "R_CALL"}
	for _, compatible := range []string{listing, strings.Replace(listing, "t=R_CALL", "t=93", 1),
		strings.ReplaceAll(listing, "literal.", `"".`)} {
		if err := x86StackControlVerifyListing(compatible, []x86StackControlOriginalCase{fixture}, enums); err != nil {
			t.Fatal("complete known SDK listing spelling was lost", err)
		}
	}
	for name, changed := range map[string]string{
		"missing-relocation":   strings.Replace(listing, "\trel 1+4 t=R_CALL literal.Target+7\n", "", 1),
		"duplicate-relocation": listing + "\trel 1+4 t=R_CALL literal.Target+7\n",
		"unknown-numeric-kind": strings.Replace(listing, "t=R_CALL", "t=94", 1),
		"foreign-kind":         strings.Replace(listing, "t=R_CALL", "t=R_PCREL", 1),
		"wrong-symbol":         strings.Replace(listing, "t=R_CALL literal.Target", "t=R_CALL literal.Other", 1),
		"wrong-addend":         strings.Replace(listing, "t=R_CALL literal.Target+7", "t=R_CALL literal.Target+8", 1),
		"wrong-offset":         strings.Replace(listing, "rel 1+4", "rel 2+4", 1),
		"wrong-size":           strings.Replace(listing, "rel 1+4", "rel 1+8", 1),
		"trailing-fields":      strings.Replace(listing, "t=R_CALL literal.Target+7", "t=R_CALL literal.Target+7 extra", 1),
		"truncated-record":     strings.Replace(listing, "t=R_CALL literal.Target+7", "t=R_CALL", 1),
		"wrong-PC":             strings.Replace(listing, "0x0005 00005", "0x0004 00004", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := x86StackControlVerifyListing(changed, []x86StackControlOriginalCase{fixture}, enums); err == nil {
				t.Fatal("unchanged zero bytes concealed invalid PC/relocation evidence", name)
			}
		})
	}
}
