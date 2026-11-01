package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsSharedX86TypedGrammar(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repo, "x86_broadcast_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	types, err := os.ReadFile(filepath.Join(repo, "types.go"))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	for name, data := range map[string][]byte{
		"x86_broadcast_forms.go": source,
		"translate.go":           []byte("package plan9asm\n"),
		"types.go":               types,
	} {
		if err := os.WriteFile(filepath.Join(isolated, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{
		"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ",
		"VBROADCASTSS", "VBROADCASTSD",
	}
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			supported, err := extractSupportedOps(isolated, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				_, found := supported[name]
				if found != (arch == "386" || arch == "amd64") {
					t.Errorf("shared typed grammar %s: advertised=%t", name, found)
				}
			}
		})
	}
}

func TestExtractSupportedOpsSharedX86DispatchDoesNotAdvertiseConditions(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"translate.go": "package sample\n",
		"types.go":     sharedX86CanonicalTestTypes,
		"x86_shared.go": `package sample
import "strings"
var sharedTable = map[string]int{"VTABLEOP": 1}
var unrelatedNames = map[string]int{"EQ": 1, "NE": 1}
func dispatch(op Op, condition string) {
	name, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	_ = sharedTable[name]
	_ = unrelatedNames[condition]
	switch name {
	case "VSHAREDOP":
	}
	switch condition {
	case "EQ", "NE":
	}
}
`,
		"x86_shared_test.go": `package sample
func testOnly(op Op) {
	switch op {
	case "VTESTONLY":
	}
}
`,
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
			for _, name := range []string{"VSHAREDOP", "VTABLEOP"} {
				if _, found := supported[name]; !found {
					t.Errorf("shared opcode dispatch %s was not observed", name)
				}
			}
			for _, name := range []string{"EQ", "NE", "VTESTONLY"} {
				if _, found := supported[name]; found {
					t.Errorf("non-dispatch string %s was advertised", name)
				}
			}
		})
	}
}
