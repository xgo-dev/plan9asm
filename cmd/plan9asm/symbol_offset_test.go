package main

import "testing"

func TestSplitSymbolOffsetExpressions(t *testing.T) {
	tests := []struct {
		input string
		name  string
		off   int64
	}{
		{"data+ 8", "data", 8},
		{"data - 8", "data", -8},
		{"data+(4*2)", "data", 8},
		{"data+8-4", "data", 4},
		{"data-name", "data-name", 0},
	}
	for _, tt := range tests {
		name, off := splitSymPlusOff(tt.input)
		if name != tt.name || off != tt.off {
			t.Errorf("splitSymPlusOff(%q) = %q, %d; want %q, %d", tt.input, name, off, tt.name, tt.off)
		}
	}
}
