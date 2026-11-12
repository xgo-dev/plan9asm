package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestRuntimeOracleModulesUseSupportedLanguageMinimum(t *testing.T) {
	// These are first-party, Go 1.20-compatible runtime fixtures. Their language
	// directive must not force a newer compiler than the SDK selected by the
	// test matrix. External modules and feature-profile originals are separate.
	for _, source := range []string{
		"arm64_go_internal_aggregate_test.go",
		"arm64_raw_private_frame_runtime_test.go",
		"arm_conditional_flags_runtime_test.go",
		"arm_kernel_continuation_runtime_test.go",
		"arm_kernel_helper_test.go",
		"arm_raw_status_runtime_test.go",
		"arm_register_address_test.go",
		"arm_shifter_runtime_test.go",
		"arm_status_cfg_runtime_test.go",
		"arm_symbol_memory_test.go",
		"arm_symbol_scratch_test.go",
	} {
		t.Run(source, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			modules := 0
			ast.Inspect(file, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(value, "module ") {
					modules++
					if !strings.Contains(value, "\ngo 1.20\n") {
						t.Errorf("runtime fixture unnecessarily forces a newer SDK: %q", value)
					}
				}
				return true
			})
			if modules != 1 {
				t.Fatalf("expected exactly one literal first-party oracle module, found %d", modules)
			}
		})
	}
}
