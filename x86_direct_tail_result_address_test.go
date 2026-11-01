package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86DirectTailResultAddressFixture(arch, setup, body string) (string, string) {
	word, typ, width := "Q", "uint64", 8
	if arch == "386" {
		word, typ, width = "L", "uint32", 4
	}
	source := fmt.Sprintf(`TEXT ·First(SB),NOSPLIT,$0-%d
 MOV%s a+0(FP),SI
 LEA%s ret+%d(FP),DI
 %s
 JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
 %s
 RET
`, width*2, word, word, width, setup, body)
	return strings.ReplaceAll(source, "WORD", word), "func First(a " + typ + ") " + typ + "\n"
}

func TestX86DirectTailResultAddressScalarWidthsAndPhysicalBanks(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, offset, triple := "Q", 8, "x86_64-unknown-linux-gnu"
		registers := strings.Fields("AX CX DX BX SI DI R8 R9 R10 R11 R12 R13 R15")
		if arch == "386" {
			word, offset, triple = "L", 4, "i386-unknown-linux-gnu"
			registers = strings.Fields("AX CX DX BX SI DI")
		}
		for _, register := range registers {
			for _, result := range []struct {
				typ, suffix string
				width       int
			}{
				{"uint8", "B", 1}, {"uint16", "W", 2}, {"uint32", "L", 4},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+register+"/"+result.typ+"/"+api, func(t *testing.T) {
						source := fmt.Sprintf(`TEXT ·First(SB),4,$0-%d
 LEA%s ret+%d(FP),%s
 JMP body<>(SB)
TEXT body<>(SB),4,$0-0
 MOV%s $7,(%s)
 RET
`, offset+result.width, word, offset, register, result.suffix, register)
						declaration := "func First(a uint8) " + result.typ
						if _, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
		for _, address := range []string{"a+0(FP)", "padding+2(FP)", "ret+4095(FP)"} {
			source, declarations := x86DirectTailResultAddressFixture(arch, "NOP", "MOVWORD SI,(DI)")
			source = strings.ReplaceAll(source, fmt.Sprintf("ret+%d(FP)", offset), address)
			if _, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, "text"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("parameter/padding/unbound field acquired an address", address, err)
			}
		}
		if arch == "amd64" {
			source, declarations := x86DirectTailResultAddressFixture(arch, "LEAQ ret+8(FP),R14", "MOVQ SI,(R14)")
			if _, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, "text"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("logical result address acquired Go hidden-register role", err)
			}
		}
	}
}

func TestX86DirectTailResultAddressOwnTypedStorage(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, test := range []struct{ name, setup, body string }{
			{"direct", "NOP", "MOVWORD SI,(DI)"},
			{"copy", "MOVWORD DI,BX", "MOVWORD SI,(BX)"},
			{"overlap_copy", "MOVWORD DI,BX\n MOVWORD BX,DI", "MOVWORD SI,(DI)"},
			{"same_slot_LEA", "LEAWORD 1(DI),BX\n LEAWORD -1(BX),BX", "MOVWORD SI,(BX)"},
			{"same_identity_join", "CMPWORD SI,$0\n JEQ alternate\n MOVWORD DI,BX\n JMP join\nalternate:\n LEAWORD 0(DI),BX\njoin:", "MOVWORD SI,(BX)"},
			{"write_then_read", "NOP", "MOVWORD SI,(DI)\n MOVWORD (DI),AX\n MOVWORD AX,(DI)"},
			{"write_then_source_PC", "NOP", "MOVWORD SI,(DI)\n CMPWORD SI,$0\n JEQ 2(PC)\n MOVWORD SI,(DI)"},
			{"overwritten_address", "MOVWORD $5,DI", "MOVWORD DI,ret+RESULT(FP)"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.arch+"/"+target.triple+"/"+test.name+"/"+api, func(t *testing.T) {
					source, declarations := x86DirectTailResultAddressFixture(target.arch, test.setup, test.body)
					width := "8"
					if target.arch == "386" {
						width = "4"
					}
					source = strings.ReplaceAll(source, "RESULT", width)
					if _, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86DirectTailResultAddressDoesNotGrantOtherStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, test := range []struct{ name, setup, body string }{
			{"undefined_value", "NOP", "MOVWORD AX,(DI)"},
			{"undefined_result_read", "NOP", "MOVWORD (DI),SI\n MOVWORD SI,(DI)"},
			{"load_overwrites_alias", "NOP", "MOVWORD SI,(DI)\n MOVWORD (DI),DI\n MOVWORD $7,(DI)"},
			{"parameter_address", "LEAWORD a+0(FP),DI", "MOVWORD SI,(DI)"},
			{"result_one_past", "LEAWORD ret+RESULT(FP),DI\n LEAWORD 8(DI),DI", "MOVWORD SI,(DI)"},
			{"out_of_bounds", "NOP", "MOVWORD SI,1(DI)"},
			{"negative_offset", "NOP", "MOVWORD SI,-1(DI)"},
			{"overflow_offset", "NOP", "MOVWORD SI,9223372036854775807(DI)"},
			{"dynamic_index", "MOVWORD $0,CX", "MOVWORD SI,(DI)(CX*1)"},
			{"lost_copy", "MOVB DI,BL", "MOVWORD SI,(BX)"},
			{"different_offset_join", "CMPWORD SI,$0\n JEQ alternate\n MOVWORD DI,BX\n JMP join\nalternate:\n LEAWORD 1(DI),BX\njoin:", "MOVWORD SI,(BX)"},
			{"address_NUM_result", "NOP", "MOVWORD DI,ret+RESULT(FP)"},
			{"address_vector", "MOVL DI,X0", "MOVWORD SI,(DI)"},
			{"address_compare", "CMPWORD DI,$0", "MOVWORD SI,(DI)"},
			{"address_escaped_input", "MOVWORD DI,a+0(FP)", "MOVWORD SI,(DI)"},
			{"address_escaped_native", "MOVWORD $0,BX", "MOVWORD DI,(BX)\n MOVWORD SI,(DI)"},
			{"cross_field_LEA", "LEAWORD 8(DI),DI", "MOVWORD SI,(DI)"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					source, declarations := x86DirectTailResultAddressFixture(arch, test.setup, test.body)
					width := "8"
					if arch == "386" {
						width = "4"
					}
					source = strings.ReplaceAll(source, "RESULT", width)
					_, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unclosed result-address role: %v", err)
					}
				})
			}
		}
	}
}

func TestX86DirectTailResultAddressNativeAliasOrdering(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, width, typ, triple := "Q", 8, "uint64", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, width, typ, triple = "L", 4, "uint32", "i386-unknown-linux-gnu"
		}
		for _, after := range []bool{false, true} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/after_write_%t/%s", arch, after, api), func(t *testing.T) {
					load, store := " MOVL (BX),AX\n", " MOVWORD SI,(DI)\n"
					body := load + store
					if after {
						body = store + load
					}
					source := fmt.Sprintf(`TEXT ·First(SB),NOSPLIT,$0-%d
 MOV%s p+0(FP),BX
 MOV%s a+%d(FP),SI
 LEA%s ret+%d(FP),DI
 JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
%s RET
`, width*3, word, word, width, word, width*2, strings.ReplaceAll(body, "WORD", word))
					declarations := "func First(p *uint32,a " + typ + ") " + typ
					_, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
					if after && !errors.Is(err, ErrProbeNeedsContext) || !after && err != nil {
						t.Fatalf("native read ordering after=%t: %v", after, err)
					}
				})
			}
		}
	}
}
