package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func arm64CarryProbeGoOptabColumns(source, version string) (int, error) {
	match := regexp.MustCompile(`^go1\.(20|21|22|23|24|25|26|27)(?:\.[0-9]+)?$`).FindStringSubmatch(version)
	if len(match) != 2 {
		return 0, fmt.Errorf("unrecognized complete Optab SDK version %q", version)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "asm7.go", source, parser.SkipObjectResolution)
	if err != nil {
		return 0, err
	}
	var actual []string
	declarations := 0
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.TYPE {
			continue
		}
		for _, spec := range group.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			if typeSpec.Name.Name != "Optab" {
				continue
			}
			declarations++
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok || typeSpec.Assign.IsValid() {
				return 0, fmt.Errorf("Go Optab is not an original struct definition")
			}
			for _, field := range structure.Fields.List {
				if len(field.Names) != 1 || field.Tag != nil {
					return 0, fmt.Errorf("unrecognized grouped, embedded or tagged Optab field")
				}
				var fieldType string
				switch typ := field.Type.(type) {
				case *ast.Ident:
					fieldType = typ.Name
				case *ast.SelectorExpr:
					if object, ok := typ.X.(*ast.Ident); ok {
						fieldType = object.Name + "." + typ.Sel.Name
					}
				}
				actual = append(actual, field.Names[0].Name+" "+fieldType)
			}
		}
	}
	want := []string{"as obj.As", "a1 uint8", "a2 uint8", "a3 uint8", "a4 uint8"}
	extraDestination := match[1] != "20" && match[1] != "21"
	if extraDestination {
		want = append(want, "a5 uint8")
	}
	want = append(want, "type_ int8", "size_ int8", "param int16", "flag int8")
	if extraDestination {
		want = append(want, "scond uint8")
	} else {
		want = append(want, "scond uint16")
	}
	if declarations != 1 || !reflect.DeepEqual(actual, want) {
		return 0, fmt.Errorf("complete Go %s Optab schema changed: declarations=%d got %v want %v", version, declarations, actual, want)
	}
	return len(want), nil
}

func TestARM64CarryProbeMatchesCompleteGoTable(t *testing.T) {
	roots := []string{testGOROOT(t)}
	if additional := os.Getenv("PLAN9ASM_TEST_CARRY_SDK_ROOTS"); additional != "" {
		roots = append(roots, filepath.SplitList(additional)...)
	}
	seen := make(map[string]bool)
	for _, root := range roots {
		physical, err := filepath.EvalSymlinks(root)
		if err != nil || !filepath.IsAbs(physical) {
			t.Fatalf("actual SDK root required: %q: %v", root, err)
		}
		if seen[physical] {
			continue
		}
		seen[physical] = true
		t.Run(filepath.Base(physical), func(t *testing.T) {
			arm64CarryProbeCheckCompleteGoTable(t, physical)
		})
	}
}

func TestARM64CarryProbeGoOptabRejectsUnknownSchemas(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	versionData, err := os.ReadFile(filepath.Join(testGOROOT(t), "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	version := strings.SplitN(strings.TrimSpace(string(versionData)), "\n", 2)[0]
	for _, change := range []struct{ name, source, version string }{
		{"foreign_sdk", source, "go1.99.1"},
		{"unknown_field", strings.Replace(source, "type Optab struct {", "type Optab struct {\nforeign int", 1), version},
		{"changed_opcode_type", regexp.MustCompile(`(?m)^(\s*as\s+)obj\.As`).ReplaceAllString(source, "${1}int"), version},
		{"changed_condition_type", regexp.MustCompile(`(?m)^(\s*scond\s+)uint(?:8|16)`).ReplaceAllString(source, "${1}uint32"), version},
		{"duplicate_definition", source + "\ntype Optab struct {}\n", version},
	} {
		t.Run(change.name, func(t *testing.T) {
			if change.source == source && change.version == version {
				t.Fatal("negative schema fixture did not change its input")
			}
			if _, err := arm64CarryProbeGoOptabColumns(change.source, change.version); err == nil {
				t.Fatal("unknown actual schema was silently reduced to known encoder rows")
			}
		})
	}
}
