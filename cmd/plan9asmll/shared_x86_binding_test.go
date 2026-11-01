package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsSharedX86RequiresTypedBinding(t *testing.T) {
	cases := []struct {
		name, source string
		want         bool
	}{
		{"typed_parameter", `func f(code Op) { switch code { case "VBOUND": } }`, true},
		{"string_named_op", `func f(op string) { switch op { case "VBOUND": } }`, false},
		{"shadowed_op", `func f(op Op, condition string) { { op := condition; switch op { case "VBOUND": } } }`, false},
		{"var_alias", `func f(code Op) { var name = string(code); switch name { case "VBOUND": } }`, true},
		{"parallel_alias", `func f(code Op, condition string) { other, name := condition, string(code); _ = other; switch name { case "VBOUND": } }`, true},
		{"instruction_field", `func f(source Instr) { switch source.Op { case "VBOUND": } }`, true},
		{"unrelated_field", `func f(source struct{Op string}) { switch source.Op { case "VBOUND": } }`, false},
		{"typed_conversion", `func f(code Op) { switch Op(string(code)) { case "VBOUND": } }`, true},
		{"untyped_conversion", `func f(condition string) { switch Op(condition) { case "VBOUND": } }`, false},
		{"strings_import_alias", `import textstrings "strings"
func f(code Op) { name, _, _ := textstrings.Cut(textstrings.ToUpper(string(code)), "."); switch name { case "VBOUND": } }`, true},
		{"cut_suffix", `import "strings"
func f(op Op) { _, suffix, _ := strings.Cut(string(op), "."); switch suffix { case "VBOUND": } }`, false},
		{"shadowed_strings", `func f(op Op) { strings := struct{ToUpper func(string) string}{}; switch strings.ToUpper(string(op)) { case "VBOUND": } }`, false},
		{"operand_comparison", `func f(op string) { if op == "VBOUND" {} }`, false},
		{"typed_comparison", `func f(code Op) { if code == "VBOUND" {} }`, true},
		{"reassigned_alias", `func f(op Op, condition string) {
	name := string(op)
	name = condition
	switch name { case "VBOUND": }
}`, false},
		{"conditionally_reassigned_alias", `func f(op Op, condition string, replace bool) {
	name := string(op)
	if replace { name = condition }
	switch name { case "VBOUND": }
}`, false},
		{"shadowed_opcode_type", `func f(condition string) {
	type Op string
	var op Op = Op(condition)
	switch op { case "VBOUND": }
}`, false},
		{"shadowed_instruction_type", `func f() {
	type Instr struct { Op string }
	var source Instr
	switch source.Op { case "VBOUND": }
}`, false},
		{"shadowed_string_conversion", `func f(op Op, condition string) {
	string := func(Op) string { return condition }
	switch string(op) { case "VBOUND": }
}`, false},
		{"shadowed_opcode_conversion", `func f(op Op, condition string) {
	Op := func(Op) string { return condition }
	switch Op(op) { case "VBOUND": }
}`, false},
		{"foreign_strings_import", `import strings "example.com/conditions"
func f(op Op) { switch strings.ToUpper(string(op)) { case "VBOUND": } }`, false},
		{"shadowed_import_parameter", `import "strings"
func f(op Op, strings struct { ToUpper func(string) string }) {
	switch strings.ToUpper(string(op)) { case "VBOUND": }
}`, false},
		{"parallel_var_alias", `func f(code Op, condition string) {
	var other, name = condition, string(code)
	_ = other
	switch name { case "VBOUND": }
}`, true},
		{"local_opcode_map", `func f(code Op) {
	table := map[string]int{"VBOUND": 1}
	_ = table[string(code)]
}`, true},
		{"parallel_local_opcode_maps", `func f(code Op, condition string) {
	operand, opcode := map[string]int{"EQ": 1}, map[string]int{"VBOUND": 1}
	_ = operand[condition]
	_ = opcode[string(code)]
}`, true},
		{"parallel_var_opcode_maps", `func f(code Op, condition string) {
	var operand, opcode = map[string]int{"EQ": 1}, map[string]int{"VBOUND": 1}
	_ = operand[condition]
	_ = opcode[string(code)]
}`, true},
		{"opcode_map_alias", `var original = map[string]int{"VBOUND": 1}
func f(code Op) { table := original; _ = table[string(code)] }`, true},
		{"typed_opcode_map", `var table = map[Op]int{"VBOUND": 1}
func f(code Op) { _ = table[Op(string(code))] }`, true},
		{"shadowed_opcode_map_type", `func f(condition string) {
	type Op string
	table := map[Op]int{"VBOUND": 1}
	_ = table[Op(condition)]
}`, false},
		{"mutable_opcode_map", `func f(op Op, other map[string]int) {
	var table = map[string]int{"VBOUND": 1}
	table = other
	_ = table[string(op)]
}`, false},
		{"parallel_operand_map", `func f(code Op, condition string) {
	var operand, opcode = map[string]int{"VBOUND": 1}, map[string]int{"EQ": 1}
	_ = operand[condition]
	_ = opcode[string(code)]
}`, false},
		{"cut_found_result", `import "strings"
func f(op Op) { _, _, found := strings.Cut(string(op), "."); if found == true {} }`, false},
		{"inline_opcode_map", `func f(code Op) { _ = map[string]int{"VBOUND": 1}[string(code)] }`, true},
		{"reassigned_parallel_alias", `func f(op Op, condition string) {
	name, other := string(op), condition
	name, other = other, name
	switch name { case "VBOUND": }
}`, false},
		{"reassigned_map_alias", `var original = map[string]int{"VBOUND": 1}
func f(op Op, other map[string]int) {
	table := original
	table = other
	_ = table[string(op)]
}`, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, source := range map[string]string{
				"translate.go":   "package sample\n",
				"types.go":       sharedX86CanonicalTestTypes,
				"x86_binding.go": "package sample\n" + test.source,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, arch := range []string{"386", "amd64"} {
				t.Run(arch, func(t *testing.T) {
					supported, err := extractSupportedOps(dir, arch)
					if err != nil {
						t.Fatal(err)
					}
					if _, found := supported["VBOUND"]; found != test.want {
						t.Errorf("opcode role advertised=%t, want %t", found, test.want)
					}
				})
			}
		})
	}
}

const sharedX86CanonicalTestTypes = "package sample\ntype Op string\ntype Instr struct { Op Op }\n"

func TestExtractSupportedOpsSharedX86RequiresCanonicalTypes(t *testing.T) {
	cases := []struct {
		name, types, source string
	}{
		{"absent_types", "", `func f(op Op) { switch op { case "VBOUND": } }`},
		{"opcode_alias_of_string", "package sample\ntype Op = string\ntype Instr struct { Op Op }\n",
			`func f(op Op) { switch op { case "VBOUND": } }`},
		{"instruction_string_field", "package sample\ntype Op string\ntype Instr struct { Op string }\n",
			`func f(source Instr) { switch source.Op { case "VBOUND": } }`},
		{"foreign_types_package", "package foreign\ntype Op string\ntype Instr struct { Op Op }\n",
			`func f(op Op) { switch op { case "VBOUND": } }`},
		{"package_opcode_redeclaration", sharedX86CanonicalTestTypes,
			`type Op string
func f(op Op) { switch op { case "VBOUND": } }`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"translate.go":   "package sample\n",
				"x86_binding.go": "package sample\n" + test.source,
			}
			if test.types != "" {
				files["types.go"] = test.types
			}
			for name, source := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, arch := range []string{"386", "amd64"} {
				t.Run(arch, func(t *testing.T) {
					supported, err := extractSupportedOps(dir, arch)
					if err != nil {
						t.Fatal(err)
					}
					if _, found := supported["VBOUND"]; found {
						t.Fatal("unbound canonical type advertised an opcode")
					}
				})
			}
		})
	}
}
