package plan9asm

import "testing"

func TestParseSymbolOffsetsWithGoExpressionWhitespace(t *testing.T) {
	tests := []struct {
		text string
		name string
		off  int64
		kind OperandKind
	}{
		{"z+ 0(FP)", "z", 0, OpFP},
		{"x + 8(FP)", "x", 8, OpFP},
		{"y - 16(FP)", "y", -16, OpFP},
		{"result+(4*2)(FP)", "result", 8, OpFP},
		{"result+8-4(FP)", "result", 4, OpFP},
		{"$result + 8(FP)", "result", 8, OpFPAddr},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got, err := parseOperand(tt.text)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tt.kind || got.FPName != tt.name || got.FPOffset != tt.off {
				t.Fatalf("parseOperand(%q) = %+v, want %v %q %+d", tt.text, got, tt.kind, tt.name, tt.off)
			}
		})
	}
}

func TestSplitSymbolOffsetsWithGoExpressionWhitespace(t *testing.T) {
	tests := []struct {
		text string
		name string
		off  int64
	}{
		{"foo+ 8", "foo", 8},
		{"foo - 8", "foo", -8},
		{"foo+(2*4)", "foo", 8},
		{"foo+8-4", "foo", 4},
		{"foo-bar", "foo-bar", 0},
	}
	for _, tt := range tests {
		gotName, gotOff := splitSymPlusOff(tt.text)
		if gotName != tt.name || gotOff != tt.off {
			t.Errorf("splitSymPlusOff(%q) = %q, %d; want %q, %d", tt.text, gotName, gotOff, tt.name, tt.off)
		}
	}
}

func TestParseFPRejectsUnresolvedOffsets(t *testing.T) {
	for _, source := range []string{"arg+unknown(FP)", "arg-unknown(FP)"} {
		if _, _, ok := parseFP(source); ok {
			t.Errorf("parseFP(%q) accepted an unresolved offset", source)
		}
	}
}
