package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func arm64MOVSelectedGoSource(t *testing.T) (string, string) {
	t.Helper()
	root := testGOROOT(t)
	source, err := os.ReadFile(filepath.Join(root, "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	name := strings.SplitN(strings.TrimSpace(string(version)), "\n", 2)[0]
	t.Logf("MOV_ROW_SOURCE version=%s source_sha256=%x", name, sha256.Sum256(source))
	return string(source), name
}

type arm64MOVAttributeMutation struct {
	name, source string
}

// These mutations edit complete selected-SDK rows, not production properties.
// Each preserves all per-opcode/case counts and the unsigned alias statements.
func arm64MOVSameCountMutations(source string) ([]arm64MOVAttributeMutation, error) {
	var changes []arm64MOVAttributeMutation
	for _, name := range []string{"param", "pool_flag", "prepost", "code_size", "class", "case_role"} {
		lines := strings.Split(source, "\n")
		changed := 0
		for index, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "{AMOVH,") {
				continue
			}
			end := strings.IndexByte(trimmed, '}')
			if end < 0 {
				return nil, fmt.Errorf("unterminated original MOV row")
			}
			fields := strings.Split(trimmed[1:end], ",")
			if len(fields) != 10 && len(fields) != 11 {
				return nil, fmt.Errorf("unknown original MOV row shape")
			}
			for field := range fields {
				fields[field] = strings.TrimSpace(fields[field])
			}
			kindAt := len(fields) - 5
			kind, err := strconv.Atoi(fields[kindAt])
			if err != nil {
				return nil, err
			}
			edit := false
			switch name {
			case "param":
				edit = changed == 0 && kind == 20 && fields[4] == "C_UAUTO8K"
				if edit {
					fields[kindAt+2] = "0"
				}
			case "pool_flag":
				edit = changed == 0 && kind == 30 && fields[kindAt+3] == "LTO"
				if edit {
					fields[kindAt+3] = "0"
				}
			case "prepost", "class":
				edit = changed == 0 && kind == 22 && fields[kindAt+4] == "C_XPRE"
				if edit && name == "prepost" {
					fields[kindAt+4] = "C_XPOST"
				} else if edit {
					fields[1] = "C_NSOREG"
				}
			case "code_size":
				edit = changed == 0 && kind == 30
				if edit {
					fields[kindAt+1] = "4"
				}
			case "case_role":
				edit = changed == 0 && kind == 20 || changed == 1 && kind == 21
				if edit {
					fields[kindAt] = strconv.Itoa(41 - kind)
				}
			}
			if edit {
				lines[index] = "\t{" + strings.Join(fields, ", ") + "},"
				changed++
			}
		}
		want := 1
		if name == "case_role" {
			want = 2
		}
		if changed != want {
			return nil, fmt.Errorf("%s requires %d actual row edits, got %d", name, want, changed)
		}
		changes = append(changes, arm64MOVAttributeMutation{name, strings.Join(lines, "\n")})
	}
	return changes, nil
}

func TestARM64ScalarMemoryGoRowsRejectSameCountAttributeMutations(t *testing.T) {
	source, version := arm64MOVSelectedGoSource(t)
	count, err := arm64ScalarMemoryLegacyGoRows(source)
	if err != nil {
		t.Fatalf("unmodified actual SDK prerequisites: %v", err)
	}
	if _, _, err := arm64MOVCheckCompleteGoRows(source, version); err != nil {
		t.Fatalf("unmodified complete SDK prerequisites: %v", err)
	}
	mutations, err := arm64MOVSameCountMutations(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if mutation.source == source {
				t.Fatal("attribute mutation did not change the actual input")
			}
			if got, err := arm64ScalarMemoryLegacyGoRows(mutation.source); err != nil || got != count {
				t.Fatalf("mutation changed the legacy denominator/aliases: %d/%d %v", got, count, err)
			}
			if _, _, err := arm64MOVCheckCompleteGoRows(mutation.source, version); err == nil {
				t.Fatal("complete MOV oracle accepted a changed attribute despite identical legacy counts/aliases")
			}
		})
	}
}

func TestARM64ScalarMemoryGoRowsMatchCompleteSelectedTable(t *testing.T) {
	source, version := arm64MOVSelectedGoSource(t)
	rows, columns, err := arm64MOVCheckCompleteGoRows(source, version)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"AMOVB", "AMOVH", "AMOVW", "AMOVD"} {
		t.Run(op, func(t *testing.T) {
			previous := -1
			for _, row := range rows[op] {
				t.Run(fmt.Sprintf("row_%d", row.ordinal), func(t *testing.T) {
					if len(row.fields) != columns || row.ordinal <= previous || row.line <= 0 {
						t.Fatal("complete row/physical order was discarded")
					}
					previous = row.ordinal
					t.Logf("MOV_ROW line=%d ordinal=%d fields=%v", row.line, row.ordinal, row.fields)
				})
			}
		})
	}
}

func arm64MOVReplaceSourceRow(t *testing.T, source string, row arm64MOVGoRow, fields []string) string {
	t.Helper()
	lines := strings.Split(source, "\n")
	if row.line <= 0 || row.line > len(lines) || !strings.Contains(lines[row.line-1], "{"+row.fields[0]+",") {
		t.Fatal("mutation lost the actual source-row identity")
	}
	lines[row.line-1] = "\t{" + strings.Join(fields, ", ") + "},"
	changed := strings.Join(lines, "\n")
	if changed == source {
		t.Fatal("source row was not changed")
	}
	return changed
}

func TestARM64ScalarMemoryGoRowsRejectEveryRetainedFieldMutation(t *testing.T) {
	source, version := arm64MOVSelectedGoSource(t)
	rows, columns, err := arm64MOVCheckCompleteGoRows(source, version)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"as", "a1", "a2", "a3", "a4"}
	values := []string{"AMOVUNKNOWN", "C_UNKNOWN", "C_UNKNOWN", "C_UNKNOWN", "C_UNKNOWN"}
	if columns == 11 {
		names, values = append(names, "a5"), append(values, "C_UNKNOWN")
	}
	names = append(names, "type_", "size_", "param", "flag", "scond")
	values = append(values, "127", "3", "REGTMP", "LFROM | LTO", "C_XUNKNOWN")
	row := rows["AMOVH"][0]
	for index, name := range names {
		t.Run(name, func(t *testing.T) {
			fields := append([]string(nil), row.fields...)
			fields[index] = values[index]
			changed := arm64MOVReplaceSourceRow(t, source, row, fields)
			if _, _, err := arm64MOVCheckCompleteGoRows(changed, version); err == nil {
				t.Fatal("an independent encoder field was discarded")
			}
		})
	}
}

func TestARM64ScalarMemoryGoRowsRejectUnknownRolesAndDuplicates(t *testing.T) {
	source, version := arm64MOVSelectedGoSource(t)
	rows, _, err := arm64MOVCheckCompleteGoRows(source, version)
	if err != nil {
		t.Fatal(err)
	}
	row := rows["AMOVH"][2] // First type-20 AUTO store, followed by the OREG store.
	extraField := append(append([]string(nil), row.fields...), "0")
	duplicate := arm64MOVReplaceSourceRow(t, source, rows["AMOVH"][3], row.fields)
	aliasSwap := strings.NewReplacer("oprangeset(AMOVHU, t)", "oprangeset(AMOVWU, t)",
		"oprangeset(AMOVWU, t)", "oprangeset(AMOVHU, t)").Replace(source)
	for _, change := range []struct{ name, source, version string }{
		{"unknown_version", source, "go1.99.1"},
		{"unknown_schema", strings.Replace(source, "type Optab struct {", "type Optab struct {\nforeign int", 1), version},
		{"missing_table", strings.Replace(source, "var optab", "var unrelatedOptab", 1), version},
		{"unknown_table_type", strings.Replace(source, "var optab = []Optab", "var optab = []Foreign", 1), version},
		{"extra_row_attribute", arm64MOVReplaceSourceRow(t, source, row, extraField), version},
		{"duplicate_same_count_row", duplicate, version},
		{"wrong_alias_base", aliasSwap, version},
		{"extra_alias", strings.Replace(source, "func buildop(ctxt *obj.Link) {", "func buildop(ctxt *obj.Link) {\noprangeset(AMOVHU, nil)", 1), version},
	} {
		t.Run(change.name, func(t *testing.T) {
			if change.source == source && change.version == version {
				t.Fatal("negative fixture did not change the source role")
			}
			if _, _, err := arm64MOVCheckCompleteGoRows(change.source, change.version); err == nil {
				t.Fatal("unknown role or duplicate was silently reduced to known MOV rows")
			}
		})
	}
}

// This bridge checks semantic shapes, not which overlapping row oplook chose
// for a concrete object. It creates no storage/carrier/native certificate.
func TestARM64ScalarMemoryGoRowsAndTypedShapesAgree(t *testing.T) {
	source, version := arm64MOVSelectedGoSource(t)
	rows, columns, err := arm64MOVCheckCompleteGoRows(source, version)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		op, base string
		bits     int
		signed   bool
	}{
		{"MOVB", "AMOVB", 8, true}, {"MOVBU", "AMOVB", 8, false},
		{"MOVH", "AMOVH", 16, true}, {"MOVHU", "AMOVH", 16, false},
		{"MOVW", "AMOVW", 32, true}, {"MOVWU", "AMOVW", 32, false},
		{"MOVD", "AMOVD", 64, false},
	} {
		t.Run(family.op, func(t *testing.T) {
			for _, row := range rows[family.base] {
				t.Run(fmt.Sprintf("row_%d", row.ordinal), func(t *testing.T) {
					kind := row.fields[columns-5]
					store := kind == "20" || kind == "30" || kind == "23" || kind == "99" || kind == "64"
					class := row.fields[1]
					if store {
						class = row.fields[4]
					}
					memory := "0(R0)"
					switch {
					case class == "C_ADDR":
						memory = "payload(SB)"
					case class == "C_ROFF":
						memory = "(R0)(R2)"
					case class == "C_NSAUTO":
						memory = "local-1(SP)"
					case class == "C_NSOREG":
						memory = "-1(R0)"
					case strings.HasPrefix(class, "C_UAUTO"):
						memory = "local+0(SP)"
					case strings.HasPrefix(class, "C_LAUTO"):
						memory = "local+65536(SP)"
						if strings.HasSuffix(class, "POOL") {
							memory = "local-8192(SP)"
						}
					case strings.HasPrefix(class, "C_LOREG") && kind != "22" && kind != "23":
						memory = "65536(R0)"
						if strings.HasSuffix(class, "POOL") {
							memory = "-8192(R0)"
						}
					}
					pre, post := row.fields[columns-1] == "C_XPRE", row.fields[columns-1] == "C_XPOST"
					suffix := ""
					if pre {
						suffix = ".W"
					} else if post {
						suffix = ".P"
					}
					operands := memory + ",R1"
					if store {
						operands = "R1," + memory
					}
					text := family.op + suffix + " " + operands
					file, err := Parse(ArchARM64, "TEXT shape(SB),516,$0-0\n"+text+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					fn, err := normalizeARM64ScalarMemoryFrame(file.Funcs[0])
					if err != nil {
						t.Fatal(err)
					}
					ins := fn.Instrs[1]
					form, handled, err := parseARM64ScalarMemoryForm(Op(family.op), ins)
					if !handled || err != nil || form.bits != family.bits || form.signed != family.signed ||
						form.store != store || form.pre != pre || form.post != post || form.data != "R1" {
						t.Fatalf("complete independent row disagrees with typed shape %s: %+v handled=%v error=%v", text, form, handled, err)
					}
					wantScratch := kind == "30" || kind == "31" || kind == "64" || kind == "65"
					if form.scratch != wantScratch {
						t.Fatalf("source expansion role disagrees for %s: %+v", text, form)
					}
				})
			}
		})
	}
}
