package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPreprocessAssemblyCPPOutputPhysicalOrigins(t *testing.T) {
	const source = "#include \"registers.h\"\n#define register indirect\n#line 900 \"logical-only.s\"\nTEXT ·Probe(SB),4,$0-0\nMOVL $42,register\nRET\n"
	options := AssemblyPreprocessOptions{FileName: "entry.s", ReadInclude: func(parent, name string) (string, []byte, error) {
		if parent != "entry.s" || name != "registers.h" {
			return "", nil, fmt.Errorf("unbound include")
		}
		return name, []byte("#define indirect AX\n"), nil
	}}
	plain, err := ObserveAssemblyCPP(source, options)
	if err != nil {
		t.Fatal(err)
	}
	observed, tokens, err := ObserveAssemblyCPPOutput(source, options)
	if err != nil || !reflect.DeepEqual(plain, observed) || len(tokens) == 0 {
		t.Fatalf("emitted tape changed existing observation: %v", err)
	}
	var opcode, register bool
	previous := 0
	for _, token := range tokens {
		if token.Start < previous || token.End < token.Start || token.End > len(observed.Output) {
			t.Fatalf("invalid emitted byte span: %+v", token)
		}
		previous = token.End
		if token.Kind != '\n' && observed.Output[token.Start:token.End] != token.Text {
			t.Fatalf("emitted token differs from exact CPP output: %+v", token)
		}
		if token.Text == "MOVL" || token.Text == "AX" {
			if token.Position.File != "entry.s" || token.Position.Line != 5 {
				t.Fatalf("logical filename or macro-definition line replaced physical invocation: %+v", token)
			}
			opcode = opcode || token.Text == "MOVL" && token.Expansion == 0
			register = register || token.Text == "AX" && token.Expansion > 0
		}
	}
	if !opcode || !register {
		t.Fatal("physical opcode and transitive register expansion were not both observed")
	}
	// The physical-origin query must preserve original Go acceptance and bytes.
	for _, target := range []string{"linux/386", "linux/amd64"} {
		t.Run(target, func(t *testing.T) {
			original := ppMacroControlGoObject(t, target, source, map[string]string{"registers.h": "#define indirect AX\n"}, "output-origin-original")
			normalized := ppMacroControlGoObject(t, target, observed.Output, nil, "output-origin-normalized")
			if !strings.Contains(string(original), "2a") || !strings.Contains(string(normalized), "2a") {
				t.Fatal("original/normalized Go objects lack the immediate marker")
			}
		})
	}
}

func TestPreprocessAssemblyCPPOutputFailureHasNoTape(t *testing.T) {
	for _, source := range []string{"#include \"missing.h\"\n", "TEXT ·Probe(SB),4,$0-0\nRET"} {
		observed, tokens, err := ObserveAssemblyCPPOutput(source, AssemblyPreprocessOptions{FileName: "entry.s"})
		if err == nil || tokens != nil || !reflect.DeepEqual(observed, AssemblyCPPObservation{}) {
			t.Fatalf("failed preprocessing supplied an emitted proof: %v / %+v / %+v", err, observed, tokens)
		}
	}
}
