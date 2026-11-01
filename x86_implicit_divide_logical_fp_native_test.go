package plan9asm

import (
	"fmt"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// This independent directory is portable to inspect, not to execute. The two
// required Linux owners below execute the complete unmodified FP programs;
// object compilation or a non-x86 host does not qualify their #DE behavior.
func TestX86ImplicitDivideLogicalFPNativeDirectoryAndSource(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86DivideLogicalFPNativeRows(arch)
			values, faults := x86DivideNativeCases(rows, arch)
			wantRows, wantValues, wantFaults, offset := 8, 128, 24, 24
			if arch == "386" {
				wantRows, wantValues, wantFaults, offset = 6, 96, 18, 20
			}
			if len(rows) != wantRows || len(values) != wantValues || len(faults) != wantFaults || len(rows)*2 > 96 {
				t.Fatal("complete FP native width/signedness/value/#DE directory changed", len(rows), len(values), len(faults))
			}
			var assembly strings.Builder
			for index, row := range rows {
				name := "DIV"
				if row.signed {
					name = "IDIV"
				}
				name += map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[row.bits]
				instruction := fmt.Sprintf("%s divisor+%d(FP)\n", name, offset)
				if row.source != "FP" || row.memory || strings.Count(row.assembly, instruction) != 2 ||
					!strings.Contains(row.assembly, fmt.Sprintf("TEXT ·Dead%d(SB)", index)) {
					t.Fatal("native FP live/dead row lost its original named divisor", row)
				}
				valueCount, faultKinds := 0, make(map[string]bool)
				for _, value := range values {
					if value.row == index {
						valueCount++
					}
				}
				for _, fault := range faults {
					if fault.row == index {
						faultKinds[fault.fault] = true
					}
				}
				if valueCount != 16 || !faultKinds["zero"] || !faultKinds["overflow"] ||
					row.signed && (!faultKinds["wide-min/-1"] || !faultKinds["narrow-min/-1"]) {
					t.Fatal("native FP row omits whole-result or mandatory #DE boundaries", row, valueCount, faultKinds)
				}
				assembly.WriteString(row.assembly)
			}
			goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
			_, declarations := x86DivideNativeDeclarationSources(rows)
			original := fmt.Sprintf(x86DivideNativeOriginalGo, "", "")
			for name, contents := range map[string]string{"value.go": declarations, "value_test.go": original} {
				if _, err := parser.ParseFile(token.NewFileSet(), name, contents, parser.AllErrors); err != nil {
					t.Fatal("complete original Go native fixture is not a valid compilation unit", name, err)
				}
			}
		})
	}
}
