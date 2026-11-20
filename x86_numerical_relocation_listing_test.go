package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Older SDK listings print the relocation number instead of its name. Bind
// that spelling to the selected SDK's generated compile-time enum assertion,
// not a current object schema or a hard-coded historical relocation number.
func x86NumericalPCRelEnumKind(source string) (string, error) {
	assertions := regexp.MustCompile(`(?m)^[\t ]*_ = x\[R_PCREL-([0-9]+)\][\t ]*$`).FindAllStringSubmatch(source, -1)
	if len(assertions) != 1 {
		return "", fmt.Errorf("selected SDK lacks one exact R_PCREL enum assertion: got %d", len(assertions))
	}
	return assertions[0][1], nil
}

func x86NumericalPCRelListingRow(listing, numericKind string, offset, addend int) error {
	var rows []string
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 0 && fields[0] == "rel" {
			rows = append(rows, strings.TrimSpace(line))
		}
	}
	if len(rows) != 1 {
		return fmt.Errorf("expected one complete relocation row, got %d: %v", len(rows), rows)
	}
	named := fmt.Sprintf("rel %d+4 t=R_PCREL table+%d", offset, addend)
	numeric := fmt.Sprintf("rel %d+4 t=%s table+%d", offset, numericKind, addend)
	if rows[0] != named && rows[0] != numeric {
		return fmt.Errorf("unexpected relocation row %q; want %q or %q", rows[0], named, numeric)
	}
	return nil
}

func x86NumericalRequirePCRelListing(t testing.TB, listing []byte, offset, addend int) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "objabi", "reloctype_string.go"))
	if err != nil {
		t.Fatal(err)
	}
	kind, err := x86NumericalPCRelEnumKind(string(source))
	if err != nil {
		t.Fatal(err)
	}
	if err := x86NumericalPCRelListingRow(string(listing), kind, offset, addend); err != nil {
		t.Fatalf("actual selected-SDK R_PCREL listing prerequisite: %v\n%s", err, listing)
	}
}

func TestX86NumericalPCRelListingEnumIdentity(t *testing.T) {
	const assertion = "\t_ = x[R_PCREL-93]\n"
	for _, test := range []struct {
		name, source, want string
	}{
		{"exact", assertion, "93"},
		{"different-SDK-value", "\t_ = x[R_PCREL-14]\n", "14"},
		{"missing", "\t_ = x[R_ADDR-93]\n", ""},
		{"duplicate", assertion + assertion, ""},
		{"ambiguous", assertion + "\t_ = x[R_PCREL-94]\n", ""},
		{"wrong-namespace", "\t_ = x[other.R_PCREL-93]\n", ""},
		{"wrong-array", "\t_ = y[R_PCREL-93]\n", ""},
		{"comment-only", "// _ = x[R_PCREL-93]\n", ""},
		{"trailing-expression", "\t_ = x[R_PCREL-93] + 1\n", ""},
		{"truncated", "\t_ = x[R_PCREL-93\n", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind, err := x86NumericalPCRelEnumKind(test.source)
			if test.want == "" {
				if err == nil || kind != "" {
					t.Fatal("unbound SDK relocation enum was accepted", kind, err)
				}
			} else if err != nil || kind != test.want {
				t.Fatal("exact SDK relocation enum was lost", kind, err)
			}
		})
	}
}

func TestX86NumericalPCRelListingDisplayContracts(t *testing.T) {
	const named = "rel 5+4 t=R_PCREL table+-18"
	const numeric = "rel 5+4 t=93 table+-18"
	for _, test := range []struct {
		name, listing string
		accepted      bool
	}{
		{"named", "\t" + named + "\n", true},
		{"selected-SDK-numeric", "\t" + numeric + "\n", true},
		{"negative-addend-spelling", "rel 5+4 t=R_PCREL table-18\n", false},
		{"missing", "boundary STEXT size=11\n", false},
		{"duplicate-named", named + "\n" + named + "\n", false},
		{"duplicate-numeric", numeric + "\n" + numeric + "\n", false},
		{"duplicate-mixed", named + "\n" + numeric + "\n", false},
		{"foreign-numeric", "rel 5+4 t=94 table+-18\n", false},
		{"foreign-kind", "rel 5+4 t=R_ADDR table+-18\n", false},
		{"extra-foreign-row", named + "\nrel 0+4 t=R_ADDR other+0\n", false},
		{"wrong-offset", "rel 6+4 t=R_PCREL table+-18\n", false},
		{"wrong-size", "rel 5+8 t=R_PCREL table+-18\n", false},
		{"wrong-symbol", "rel 5+4 t=R_PCREL other+-18\n", false},
		{"wrong-addend", "rel 5+4 t=R_PCREL table+-17\n", false},
		{"symbol-prefix", "rel 5+4 t=R_PCREL table2+-18\n", false},
		{"trailing-fields", named + " unexpected\n", false},
		{"truncated", "rel 5+4 t=R_PCREL\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := x86NumericalPCRelListingRow(test.listing, "93", 5, -18)
			if (err == nil) != test.accepted {
				t.Fatal("SDK display compatibility changed the exact relocation contract", err)
			}
		})
	}
	for _, offset := range []int{5, 6} {
		for _, addend := range []int{-18, -17, 16, 17} {
			for _, kind := range []string{"R_PCREL", "93"} {
				listing := fmt.Sprintf("rel %d+4 t=%s table+%d\n", offset, kind, addend)
				if err := x86NumericalPCRelListingRow(listing, "93", offset, addend); err != nil {
					t.Fatal("exact opcode-specific displacement/addend was lost", err)
				}
			}
		}
	}
}
