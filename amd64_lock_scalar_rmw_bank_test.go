package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86LockScalarRMWByteSourcePhysicalBank(t *testing.T) {
	for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR"} {
		for _, source := range []string{"AH", "CH", "DH", "BH"} {
			for _, address := range []struct {
				name, setup, memory string
				rex                 bool
			}{
				{"SI", "", "(SI)", false},
				{"R8", "MOVQ SI,R8\n", "(R8)", true},
				{"R15", "MOVQ SI,R15\n", "(R15)", true},
				{"R8-index", "MOVQ $0,R8\n", "(SI)(R8*1)", true},
				{"R15-index", "MOVQ $0,R15\n", "(SI)(R15*1)", true},
			} {
				t.Run(stem+"/"+source+"/"+address.name, func(t *testing.T) {
					assembly := x86NamedLockOracleSource("amd64", address.setup+
						"CLC\nLOCK\n"+stem+"B "+source+","+address.memory)
					code := x86LockScalarOriginalInstruction(t, "amd64", assembly)
					physical, err := x86asm.Decode(code, 64)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("actual original Go bytes=%x operands=%s", code, x86asm.GoSyntax(physical, 0, nil))
					want := map[string]x86asm.Reg{"AH": x86asm.AH, "CH": x86asm.CH,
						"DH": x86asm.DH, "BH": x86asm.BH}[source]
					if address.rex {
						want = map[string]x86asm.Reg{"AH": x86asm.SPB, "CH": x86asm.BPB,
							"DH": x86asm.SIB, "BH": x86asm.DIB}[source]
					}
					if physical.Args[1] != want {
						t.Fatalf("actual source physical bank=%v, want %v", physical.Args[1], want)
					}
					triple := "x86_64-unknown-linux-gnu"
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86OrderingHintTranslateAPI(t, api, assembly,
								"package ordering\nfunc locked(p *[16]byte)\n", "amd64", triple)
							if !address.rex {
								if err != nil || !strings.Contains(ir, "lock; "+strings.ToLower(stem)+"b") {
									t.Fatal("native high byte without REX lost its actual source bank", err)
								}
							} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("source high-byte spelling borrowed a different REX physical bank", err)
							}
						})
					}
				})
			}
		}
	}
}
