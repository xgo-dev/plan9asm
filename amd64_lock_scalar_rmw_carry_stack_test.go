package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86LockScalarRMWCarryStackDoesNotInventWholeFlagsWord(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, counter := "Q", "JCXZQ"
		if arch == "386" {
			word, counter = "L", "JCXZL"
		}
		for _, suffix := range []string{"W", word} {
			compare := "AND" + suffix + " $2048,AX\nCMP" + suffix + " AX,$1"
			for _, control := range []struct {
				name, body string
				known      bool
			}{
				{"unknown OF through flags word", "CLC\nPUSHF" + suffix + "\nPOP" + suffix + " AX\n" + compare, false},
				{"CF-only flags roundtrip", "CLC\nPUSHF" + suffix + "\nPOPF" + suffix, true},
				{"defined whole numerical word", "PUSH" + suffix + " DX\nPOP" + suffix + " AX\n" + compare, true},
				{"mixed flags and numerical join", "CLC\n" + counter + " flags\nPUSH" + suffix + " DX\nPOP" + suffix + " AX\nJMP compare\nflags:\nPUSHF" + suffix + "\nPOP" + suffix + " AX\ncompare:\n" + compare, false},
				{"partial flags word through GP", "CLC\nPUSHF" + suffix + "\nPOP" + suffix + " AX\nPUSH" + suffix + " AX\nPOPF" + suffix, false},
			} {
				t.Run(arch+"/"+suffix+"/"+control.name, func(t *testing.T) {
					source := x86NamedLockOracleSource(arch, control.body+"\nLOCK\nADCL CX,(SI)")
					x86LockScalarOriginalInstruction(t, arch, source)
					triple := testTargetTriple("linux", arch)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86OrderingHintTranslateAPI(t, api, source,
								"package ordering\nfunc locked(p *[16]byte)\n", arch, triple)
							if control.known {
								if err != nil || !strings.Contains(ir, "lock; adcl") {
									t.Fatal("known numerical word or CF roundtrip was lost", err)
								}
							} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("CF-only PUSHF falsely defined unknown GP/OF bits", err)
							}
						})
					}
				})
			}
		}
	}
}
