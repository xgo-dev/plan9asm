package plan9asm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func x86FrameDiagnosticFixture(t *testing.T, source string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "frame.s")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestGoAssemblerOracleX86FrameRebaseCompleteContext(t *testing.T) {
	for _, test := range []struct {
		name, source, listing string
		line                  int
	}{
		{"param-zero", "TEXT probe(SB),4,$0-32\nMOVOA a+0(FP),X8\nRET\n", "MOVO a+4(FP),X8", 2},
		{"param-frame", "TEXT probe(SB),4,$16-32\nMOVOA renamed+8(FP),X8\nRET\n", "MOVO renamed+28(FP),X8", 2},
		{"param-negative", "TEXT probe(SB),4,$16-32\nMOVOA a-8(FP),X8\nRET\n", "MOVO a+12(FP),X8", 2},
		{"param-negative-frame", "TEXT probe(SB),4,$-4-32\nMOVOA a+0(FP),X8\nRET\n", "MOVO a+4(FP),X8", 2},
		{"auto-zero", "TEXT probe(SB),4,$16-32\nMOVOA local-16(SP),X8\nRET\n", "MOVO local(SP),X8", 2},
		{"auto-bare", "TEXT probe(SB),4,$16-32\nMOVOA tmp(SP),X8\nRET\n", "MOVO tmp+16(SP),X8", 2},
		{"auto-negative", "TEXT probe(SB),4,$0-32\nMOVOA tmp-16(SP),X8\nRET\n", "MOVO tmp-16(SP),X8", 2},
		{"store-param", "TEXT probe(SB),4,$16-32\nMOVOA X15,result+8(FP)\nRET\n", "MOVO X15,result+28(FP)", 2},
		{"store-auto", "TEXT probe(SB),4,$16-32\nMOVOA X15,local-8(SP)\nRET\n", "MOVO X15,local+8(SP)", 2},
		{"push-long", "TEXT probe(SB),4,$16-32\nPUSHL AX\nMOVOA a+0(FP),X8\nPOPL AX\nRET\n", "MOVO a+24(FP),X8", 3},
		{"push-word", "TEXT probe(SB),4,$0-32\nPUSHW AX\nMOVOA a+0(FP),X8\nPOPW AX\nRET\n", "MOVO a+6(FP),X8", 3},
		{"push-flags", "TEXT probe(SB),4,$0-32\nPUSHFL\nMOVOA a+0(FP),X8\nPOPFL\nRET\n", "MOVO a+8(FP),X8", 3},
		{"adj-positive", "TEXT probe(SB),4,$0-32\nADJSP $8\nMOVOA a+0(FP),X8\nADJSP $-8\nRET\n", "MOVO a+12(FP),X8", 3},
		{"adj-negative", "TEXT probe(SB),4,$16-32\nADJSP $-8\nMOVOA a+0(FP),X8\nADJSP $8\nRET\n", "MOVO a+12(FP),X8", 3},
		{"other-alias", "TEXT probe(SB),4,$16-32\nMOVD a+0(FP),X8\nRET\n", "MOVQ a+20(FP),X8", 2},
		{"address-role", "TEXT probe(SB),4,$16-32\nMOVOA $a+0(FP),X8\nRET\n", "MOVO $a+20(FP),X8", 2},
		{"index-param", "TEXT probe(SB),4,$16-32\nMOVOA a+0(FP)(SI*2),X8\nRET\n", "MOVO a+20(FP)(SI*2),X8", 2},
		{"index-auto", "TEXT probe(SB),4,$16-32\nMOVOA tmp-8(SP)(SI*4),X8\nRET\n", "MOVO tmp+8(SP)(SI*4),X8", 2},
		{"later-text", "TEXT earlier(SB),4,$64-32\nMOVOA a+0(FP),X8\nRET\nTEXT probe(SB),4,$0-32\nMOVOA a+0(FP),X8\nRET\n", "MOVO a+4(FP),X8", 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := x86FrameDiagnosticFixture(t, test.source)
			listing := "asm: asmins: illegal in mode 32: 00000 (" + source + ":" + strconv.Itoa(test.line) + ") " + test.listing + " (24 66)\n"
			if !goAssemblerOracleX86SourceDiagnostic(source, "386", listing) {
				t.Errorf("complete original TEXT/stack role did not bind the exact rewritten listing: %s", test.listing)
			}
			if goAssemblerOracleX86SourceDiagnostic(source, "amd64", listing) {
				t.Fatal("mode32 stack rewrite borrowed the AMD64 target")
			}
		})
	}
}

func TestGoAssemblerOracleX86FrameRebaseRejectsInventedContext(t *testing.T) {
	valid := "TEXT probe(SB),4,$16-32\nMOVOA a+0(FP),X8\nRET\n"
	for _, test := range []struct{ name, source, instruction string }{
		{"wrong-frame", strings.Replace(valid, "$16-32", "$0-32", 1), "MOVO a+20(FP),X8"},
		{"wrong-slot", valid, "MOVO b+20(FP),X8"},
		{"wrong-offset", valid, "MOVO a+19(FP),X8"},
		{"wrong-register", valid, "MOVO a+20(FP),X9"},
		{"wrong-role", valid, "MOVO a+20(SP),X8"},
		{"invented-index", valid, "MOVO a+20(FP)(SI*2),X8"},
		{"invented-address", valid, "MOVO $a+20(FP),X8"},
		{"truncated", valid, "MOVO a+20(FP)"},
		{"missing-text", "MOVOA a+0(FP),X8\nRET\n", "MOVO a+4(FP),X8"},
		{"unknown-frame", strings.Replace(valid, "$16-32", "$FRAME-32", 1), "MOVO a+20(FP),X8"},
		{"expression-frame", strings.Replace(valid, "$16-32", "$(8+8)-32", 1), "MOVO a+20(FP),X8"},
		{"unknown-flags", strings.Replace(valid, ",4,", ",FLAGS,", 1), "MOVO a+20(FP),X8"},
		{"overflow-frame", strings.Replace(valid, "$16-32", "$2147483648-32", 1), "MOVO a+20(FP),X8"},
		{"unaligned-frame", strings.Replace(valid, "$16-32", "$15-32", 1), "MOVO a+19(FP),X8"},
		{"unknown-offset", strings.Replace(valid, "a+0", "a+UNKNOWN", 1), "MOVO a+20(FP),X8"},
		{"expression-offset", strings.Replace(valid, "a+0", "a+(0+0)", 1), "MOVO a+20(FP),X8"},
		{"invalid-scale", strings.Replace(valid, "a+0(FP)", "a+0(FP)(SI*3)", 1), "MOVO a+20(FP)(SI*3),X8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := x86FrameDiagnosticFixture(t, test.source)
			line := 2
			if test.name == "missing-text" {
				line = 1
			}
			listing := "asm: asmins: illegal in mode 32: 00000 (" + source + ":" + strconv.Itoa(line) + ") " + test.instruction + " (24 66)\n"
			if goAssemblerOracleX86SourceDiagnostic(source, "386", listing) {
				t.Fatal("unbound or changed complete stack role acquired a diagnostic join")
			}
		})
	}
	for _, prefix := range []string{
		"JMP after\nafter:\n", "JEQ after\nafter:\n", "CALL helper(SB)\n", "MOVL AX,SP\n",
		"ADJSP $UNKNOWN\n", "ADJSP $2147483648\n", "PUSHQ AX\n", "#include \"frame.h\"\n",
		"RET\n", "MOVL $0,SP\n", "LEAL 4(SP),SP\n",
	} {
		t.Run("unknown-prefix/"+strings.TrimSpace(prefix), func(t *testing.T) {
			text := strings.Replace(valid, "MOVOA", prefix+"MOVOA", 1)
			source := x86FrameDiagnosticFixture(t, text)
			line := 2 + strings.Count(prefix, "\n")
			listing := "asm: asmins: illegal in mode 32: 00000 (" + source + ":" + strconv.Itoa(line) + ") MOVO a+20(FP),X8 (24 66)\n"
			if goAssemblerOracleX86SourceDiagnostic(source, "386", listing) {
				t.Fatal("unknown flow/CPP/stack delta was guessed as a frame relocation")
			}
		})
	}
	for _, mutation := range []string{
		"asm: asmins: illegal in mode 64: ", "asm: invalid instruction: ",
		"(24 66) extra", "(24 90)", "(024 66)", "(24,66)",
	} {
		t.Run("backend-boundary/"+mutation, func(t *testing.T) {
			source := x86FrameDiagnosticFixture(t, valid)
			listing := x86Mode32Diagnostic(source, "MOVO a+20(FP),X8", "(24 66)")
			if strings.HasPrefix(mutation, "asm:") {
				listing = strings.Replace(listing, "asm: asmins: illegal in mode 32: ", mutation, 1)
			} else {
				listing = strings.Replace(listing, "(24 66)", mutation, 1)
			}
			if goAssemblerOracleX86SourceDiagnostic(source, "386", listing) {
				t.Fatal("stack join lost its complete class-tail/backend role")
			}
		})
	}
}
