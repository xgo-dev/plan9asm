package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteScalarLOCKRMWFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps("../..", arch)
		if err != nil {
			t.Fatal(err)
		}
		widths := "BWL"
		if arch == "amd64" {
			widths += "Q"
		}
		count := 0
		for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR", "INC", "DEC", "NEG", "NOT", "BTC", "BTR", "BTS"} {
			for _, width := range widths {
				if width == 'B' && (stem == "BTC" || stem == "BTR" || stem == "BTS") {
					continue
				}
				opcode := stem + string(width)
				if _, present := supported[opcode]; !present {
					t.Error("complete typed RMW family omitted from supported-op extraction", arch, opcode)
				}
				count++
			}
		}
		want := 39
		if arch == "amd64" {
			want = 53
		}
		if count != want {
			t.Fatal("complete independent opcode denominator changed", arch, count)
		}
		if _, present := supported["LOCK"]; !present {
			t.Fatal("source prefix was omitted from extraction", arch)
		}
	}
}

func TestExtractSupportedOpsUsesDeclaredX86Widths(t *testing.T) {
	root := t.TempDir()
	source := `package plan9asm
type x86OpcodeWidths map[string]string
var families = x86OpcodeWidths{"ADC": "BWLQ", "BTC": "WLQ"}
`
	if err := os.WriteFile(filepath.Join(root, "amd64_widths.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(root, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ADCB", "ADCW", "ADCL", "ADCQ", "BTCW", "BTCL", "BTCQ", "BTCB", "ADC"} {
			_, found := supported[name]
			want := name != "BTCB" && name != "ADC" &&
				(arch == "amd64" || name != "ADCQ" && name != "BTCQ")
			if found != want {
				t.Errorf("%s %s support = %t, want %t", arch, name, found, want)
			}
		}
	}
}
