package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// One concrete original-Go representative for each existing terminal mechanism.
// Complete opcode/width/byte catalogs keep their existing independent owners.
// These rows are not a production classifier or a native execution oracle.
func x86TerminalPrefixMechanismFixtures() []struct{ name, instruction string } {
	return []struct{ name, instruction string }{
		{"undefined", "UNDEF"},
		{"packed-move", "VMOVUPS.Z X1,K1,(AX)"},
		{"compact", "VCOMPRESSPS.Z X1,K1,(AX)"},
		{"single-source-narrow", "VPMOVDB.Z X1,K1,(AX)"},
		{"insert-extract", "VEXTRACTF32X4.Z $0,Y1,K1,(AX)"},
		{"named-half", "VCVTPS2PH.Z $7,X1,K1,(AX)"},
		{"scalar-nontemporal", "MOVNTIL CX,AX"},
		{"vector-nontemporal", "MOVNTPS X1,AX"},
	}
}

func TestX86ArchitecturalTerminalKeepsPrefixMemoryObligations(t *testing.T) {
	for _, family := range x86TerminalPrefixMechanismFixtures() {
		for _, result := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/result=%t", family.name, result), func(t *testing.T) {
				frame, returns := 0, ""
				if result {
					frame, returns = 8, " uint64"
				}
				declaration := "func TerminalPrefix()" + returns + "\n"
				base := fmt.Sprintf("TEXT ·TerminalPrefix(SB),4,$0-%d\n%s\nRET\n", frame, family.instruction)
				prefixes := []struct{ name, source string }{
					{"pure-terminal", ""},
					{"read", "MOVQ (AX),CX\n"},
					{"known-data-store", "MOVQ $1,CX\nMOVQ CX,(AX)\n"},
				}
				for _, prefix := range prefixes {
					source := strings.Replace(base, family.instruction, prefix.source+family.instruction, 1)
					goAssemblerOracleOutput(t, "amd64", source, "", true)
				}
				for _, api := range []string{"text", "module", "Go"} {
					// Validate the original positive before judging its mutations.
					const triple = "x86_64-unknown-linux-gnu"
					ir, err := x86ScalarFPBitViewAPI(t, base, declaration, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete terminal positive was not admitted before prefix controls", family.name, api, err)
					}
					if _, err := x86OfficialMoveFaultBody(ir, "TerminalPrefix"); err != nil {
						t.Fatal("terminal body must not need an incoming numerical/mask/address value", family.name, api, err)
					}
					for _, prefix := range prefixes {
						t.Run(api+"/"+prefix.name, func(t *testing.T) {
							source := strings.Replace(base, family.instruction, prefix.source+family.instruction, 1)
							text, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
							if prefix.source == "" {
								if err != nil || text == "" {
									t.Fatal("pure terminal must retain its original no-input continuation", family.name, api, err)
								}
								return
							}
							if text != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("later architectural terminal authorized an earlier unknown address", family.name, prefix.name, api, err)
							}
						})
					}
				}
			})
		}
	}
}

func TestX86ArchitecturalTerminalKnownPrefixesRemainAdmitted(t *testing.T) {
	for _, family := range x86TerminalPrefixMechanismFixtures() {
		for _, prefix := range []struct{ name, declaration, source string }{
			{"scalar-parameter", "x uint64", "MOVQ x+0(FP),CX\n"},
			{"caller-read", "p *[8]byte", "MOVQ p+0(FP),AX\nMOVQ (AX),CX\n"},
			{"caller-write", "p *[8]byte", "MOVQ p+0(FP),AX\nMOVQ $1,CX\nMOVQ CX,(AX)\n"},
		} {
			t.Run(family.name+"/"+prefix.name, func(t *testing.T) {
				source := "TEXT ·TerminalPrefix(SB),4,$0-8\n" + prefix.source + family.instruction + "\nRET\n"
				declaration := "func TerminalPrefix(" + prefix.declaration + ")\n"
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						text, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil || text == "" {
							t.Fatal("terminal prefix lost an original declared numerical/address input", family.name, prefix.name, api, err)
						}
					})
				}
			})
		}
	}
}

func TestX86ArchitecturalTerminalMixedReturnStillNeedsWrittenResults(t *testing.T) {
	for _, complete := range []bool{true, false} {
		write := ""
		if complete {
			write = "MOVQ $17,ret+8(FP)\n"
		}
		source := "TEXT ·MixedTerminal(SB),4,$0-16\nMOVQ x+0(FP),AX\nCMPQ AX,$0\nJE terminal\n" +
			write + "RET\nterminal:\nUNDEF\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("written=%t/%s", complete, api), func(t *testing.T) {
				text, err := x86ScalarFPBitViewAPI(t, source, "func MixedTerminal(x uint64) uint64\n",
					"amd64", "x86_64-unknown-linux-gnu", api)
				if complete {
					if err != nil || text == "" {
						t.Fatal("complete normal return and separate terminal branch must both close", api, err)
					}
				} else if text != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("one trapping branch authorized another path's unwritten return", api, err)
				}
			})
		}
	}
}
