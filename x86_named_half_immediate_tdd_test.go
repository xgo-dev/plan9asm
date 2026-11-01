package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86NamedHalfOriginalIntegerExpressionImmediates(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			cases := []struct {
				expression string
				control    int
				width      int
			}{
				{"(1<<2)|3", 7, 16},
				{"255&7", 7, 64},
				{"-1+0", -1, 32},
				{"~0&255", 255, 64},
				{"(7-3)*2", 8, 16},
			}
			if arch == "386" {
				cases = append(cases, struct {
					expression string
					control    int
					width      int
				}{"(1<<32)+4", 4, 16})
			}
			var source, declarations strings.Builder
			for index, row := range cases {
				name := fmt.Sprint("HalfImmediate", index)
				shape := x86NamedHalfCase{narrow: true, width: row.width, immediate: row.control}
				body, declaration := x86NamedHalfInitialized(name, arch, shape, false)
				original := shape.instruction()
				replacement := strings.Replace(original, fmt.Sprintf("$%d,", row.control), "$"+row.expression+",", 1)
				if original == replacement || strings.Count(body, original) != 1 {
					t.Fatal("integer-expression fixture lost its sole original instruction", original, replacement)
				}
				source.WriteString(strings.Replace(body, original, replacement, 1))
				declarations.WriteString(declaration)
			}
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			// The complete original Go program is the grammar prior, before any
			// API observes its original expression or classified imm8 value.
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
					if err != nil {
						t.Fatal("Go-valid half integer expression lost its original native control", err)
					}
					for index, row := range cases {
						x86NamedHalfRequireOriginalControl(t, ir, fmt.Sprint("HalfImmediate", index), row.control)
					}
				})
			}
		})
	}
}
