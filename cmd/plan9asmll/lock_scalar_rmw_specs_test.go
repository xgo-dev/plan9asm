package main

import "testing"

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
