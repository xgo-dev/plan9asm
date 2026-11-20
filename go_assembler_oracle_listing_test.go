package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoAssemblerOracleBackendListingsBindTheFixture(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "forms.s")
	if err := os.WriteFile(source, []byte("TEXT bad(SB),$0-0\nMOVK $65537,R0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range []string{
		"asm: bad constant for MOVK: 0x10001\n00000 (" + source + ":2)\tMOVK\t$65537, R0\nasm: assembly failed\n",
		"asm: illegal SYS argument\n00000 (" + source + ":2)\tSYS\t$1\nasm: assembly failed\n",
	} {
		// SYS deliberately points at a MOVK source line: a listing is not a
		// bound source diagnostic merely because its filename matches.
		want := strings.HasPrefix(diagnostic, "asm: bad constant")
		if got := goAssemblerOracleSourceDiagnostic(source, diagnostic); got != want {
			t.Fatalf("backend listing binding = %v, want %v: %s", got, want, diagnostic)
		}
	}
	for _, diagnostic := range []string{
		"00000 (" + source + ":2)\tMOVK\t$65537,R0\nasm: assembly failed\n",
		"asm: bad constant for MOVK\n00000 (" + source + ":0)\tMOVK\t$65537,R0\n",
		"asm: bad constant for MOVK\n00000 (" + source + ":4)\tMOVK\t$65537,R0\n",
		"asm: bad constant for MOVK\nnot-a-pc (" + source + ":2)\tMOVK\t$65537,R0\n",
		"asm: bad constant for MOVK\n999999999999999999999999 (" + source + ":2)\tMOVK\t$65537,R0\n",
		"asm: bad constant for MOVK\n000000 (" + source + ":2)\tMOVK\t$65537,R0\n",
		"asm: assembly failed\n00000 (" + source + ":2)\tMOVK\t$65537,R0\n",
	} {
		if goAssemblerOracleSourceDiagnostic(source, diagnostic) {
			t.Fatalf("unbound backend listing accepted: %s", diagnostic)
		}
	}
}

func TestGoAssemblerOracleActualPositionlessFrameRejection(t *testing.T) {
	for _, source := range []string{
		"TEXT bad(SB),516,$8-0\nRET\n",
		"TEXT bad(SB),512,$16-0\nRET\n",
	} {
		// This is an actual source error on both current and older Go, not an
		// expected tool crash, footer-only error or missing compiler.
		goAssemblerOracleOutput(t, "arm64", source, "", false)
	}
	goAssemblerOracleOutput(t, "arm64", "TEXT valid(SB),516,$0-0\nRET\n", "", true)
}

func TestGoAssemblerOraclePositionlessDiagnosticsRequireExactSource(t *testing.T) {
	source := filepath.Join(t.TempDir(), "forms.s")
	for _, test := range []struct {
		name, arch, assembly, diagnostic string
		want                             bool
	}{
		{"frame", "arm64", "TEXT bad(SB),516,$8-0\nRET\n", "NOFRAME functions must have a frame size of 0, not 8", true},
		{"different-frame", "arm64", "TEXT bad(SB),516,$16-0\nRET\n", "NOFRAME functions must have a frame size of 0, not 8", false},
		{"framed", "arm64", "TEXT valid(SB),4,$8-0\nRET\n", "NOFRAME functions must have a frame size of 0, not 8", false},
		{"zero-frame", "arm64", "TEXT valid(SB),516,$0-0\nRET\n", "NOFRAME functions must have a frame size of 0, not 8", false},
		{"unknown-flags", "arm64", "TEXT bad(SB),UNKNOWN_FLAGS,$8-0\nRET\n", "NOFRAME functions must have a frame size of 0, not 8", false},
		{"address", "386", "TEXT bad(SB),$0-0\nVSCATTERPF0DPD K1,(R8)(Y2*8)\nRET\n", "asmidx: bad address 8/Y2/R8", true},
		{"different-base", "386", "TEXT bad(SB),$0-0\nVSCATTERPF0DPD K1,(R9)(Y2*8)\nRET\n", "asmidx: bad address 8/Y2/R8", false},
		{"different-scale", "386", "TEXT bad(SB),$0-0\nVSCATTERPF0DPD K1,(R8)(Y2*4)\nRET\n", "asmidx: bad address 8/Y2/R8", false},
		{"different-mode", "amd64", "TEXT valid(SB),$0-0\nVSCATTERPF0DPD K1,(R8)(Y2*8)\nRET\n", "asmidx: bad address 8/Y2/R8", false},
		{"float-return", "amd64", "TEXT bad(SB),$0-0\nIRETW $0.0\nRET\n", "unexpected addr1: type=5 $(0.0)", true},
		{"different-float", "amd64", "TEXT bad(SB),$0-0\nIRETW $1.5\nRET\n", "unexpected addr1: type=5 $(0.0)", false},
		{"integer-return", "amd64", "TEXT bad(SB),$0-0\nIRETW $0\nRET\n", "unexpected addr1: type=5 $(0.0)", false},
		{"float-move", "amd64", "TEXT valid(SB),$0-0\nMOVSS $0.0,X0\nRET\n", "unexpected addr1: type=5 $(0.0)", false},
		{"unknown-diagnostic", "arm64", "TEXT bad(SB),516,$8-0\nRET\n", "unclassified tool failure", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(source, []byte(test.assembly), 0600); err != nil {
				t.Fatal(err)
			}
			output := "asm: " + test.diagnostic + "\nasm: assembly failed\n"
			if got := goAssemblerOraclePositionlessDiagnostic(source, test.arch, output); got != test.want {
				t.Fatalf("source-bound backend diagnostic=%v, want %v", got, test.want)
			}
		})
	}
	if goAssemblerOraclePositionlessDiagnostic(source+".missing", "arm64", "asm: NOFRAME functions must have a frame size of 0, not 8\n") {
		t.Fatal("missing original fixture certified a backend refusal")
	}
}
