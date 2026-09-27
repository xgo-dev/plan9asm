package plan9asm

import "testing"

func TestParseCharacterImmediateAndExpressions(t *testing.T) {
	for _, tc := range []struct {
		text string
		want int64
	}{
		{text: "$'\\n'", want: 10},
		{text: "$'Z'", want: 'Z'},
		{text: "$'\\x7f'", want: 0x7f},
		{text: "$'\\377'", want: 0xff},
		{text: "$'\\u03bb'", want: '\u03bb'},
		{text: "$'A'+1", want: 'B'},
		{text: "$('A' * 2)", want: 130},
	} {
		t.Run(tc.text, func(t *testing.T) {
			op, err := parseOperand(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if op.Kind != OpImm || op.Imm != tc.want || op.ImmRaw != "" {
				t.Fatalf("parseOperand(%q) = %#v, want immediate %d", tc.text, op, tc.want)
			}
		})
	}
}

func TestParseRejectsInvalidCharacterImmediate(t *testing.T) {
	for _, text := range []string{"$''", "$'ab'", "$'\\q'", "$'unterminated"} {
		t.Run(text, func(t *testing.T) {
			if _, err := parseOperand(text); err == nil {
				t.Fatalf("parseOperand(%q) unexpectedly succeeded", text)
			}
		})
	}
}

func TestParseAssemblyWithCharacterImmediate(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT character(SB),NOSPLIT,$0-0\n\tCMPB (SI), $'\\n'\n\tCMPB AX, $'Z'\n\tMOVD $',', R0\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[1].Args[1].Imm; got != '\n' {
		t.Fatalf("newline immediate = %d, want %d", got, '\n')
	}
	if got := file.Funcs[0].Instrs[2].Args[1].Imm; got != 'Z' {
		t.Fatalf("Z immediate = %d, want %d", got, 'Z')
	}
	if got := file.Funcs[0].Instrs[3].Args[0].Imm; got != ',' {
		t.Fatalf("comma immediate = %d, want %d", got, ',')
	}
}
