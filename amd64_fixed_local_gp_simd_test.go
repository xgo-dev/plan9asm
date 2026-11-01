package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent Go spellings: MOVD and MOVDQ2Q are MOVQ aliases. The MMX row
// and decoder-only VMOVW retain their separate physical-state contracts.
var fixedLocalGPSIMDNames = []struct {
	name   string
	bits   int
	legacy bool
}{
	{"MOVL", 32, true}, {"MOVQ", 64, true},
	{"MOVD", 64, true}, {"MOVDQ2Q", 64, true},
	{"VMOVD", 32, false}, {"VMOVQ", 64, false},
}

type fixedLocalGPSIMDCase struct {
	name, body string
	result     string
}

func fixedLocalGPSIMDCases() []fixedLocalGPSIMDCase {
	var rows []fixedLocalGPSIMDCase
	for _, family := range fixedLocalGPSIMDNames {
		banks := []string{"X1"}
		if !family.legacy {
			banks = append(banks, "X31")
		}
		for _, bank := range banks {
			seed, extract := "MOVOU 16(SP),"+bank, "MOVQ "+bank+",AX"
			if bank == "X31" {
				seed, extract = "VMOVQ AX,"+bank, "VMOVQ "+bank+",AX"
			}
			add := func(label, body, result string) {
				rows = append(rows, fixedLocalGPSIMDCase{family.name + "/" + bank + "/" + label, body, result})
			}
			add("GP to X", family.name+" AX,"+bank+"\n"+extract, "uint64")
			add("X to GP", seed+"\n"+family.name+" "+bank+",AX", "uint64")
			for _, address := range []string{"16(SP)", "17(SP)", "1(SI)"} {
				add("load "+address, family.name+" "+address+","+bank+"\n"+extract, "uint64")
				add("store "+address, seed+"\n"+family.name+" "+bank+","+address, "uint64")
			}
			input := "a+8(FP)"
			if family.bits == 32 {
				input = "b+16(FP)"
			}
			add("FP input", family.name+" "+input+","+bank+"\n"+extract, "uint64")
			add("FP result", seed+"\n"+family.name+" "+bank+",ret+24(FP)", fmt.Sprintf("uint%d", family.bits))
			if family.bits == 64 {
				add("X copy", family.name+" X0,"+bank+"\n"+extract, "uint64")
				add("X self", seed+"\n"+family.name+" "+bank+","+bank+"\n"+extract, "uint64")
			}
		}
	}
	return rows
}

func fixedLocalGPSIMDFixture(t *testing.T, row fixedLocalGPSIMDCase) (Func, FuncSig, string) {
	t.Helper()
	body := "MOVQ p+0(FP),SI\nMOVQ a+8(FP),AX\nMOVL b+16(FP),BX\n" +
		"MOVQ AX,16(SP)\nMOVQ AX,24(SP)\nMOVOU 16(SP),X0\n" + row.body + "\n"
	if !strings.HasSuffix(row.name, "/FP result") {
		body += "MOVQ AX,ret+24(FP)\n"
	}
	_, _, sig, source := x86ResultInitializationFixture(t, "amd64",
		"func Value(p *uint64, a uint64, b uint32) "+row.result, body+"RET")
	source = strings.Replace(source, "$0-", "$80-", 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig, source
}

func TestGoAMD64FixedLocalGPSIMDCompleteSources(t *testing.T) {
	rows := fixedLocalGPSIMDCases()
	if len(rows) != 90 {
		t.Fatal("complete GP/X source inventory changed", len(rows))
	}
	var original strings.Builder
	for index, row := range rows {
		_, _, source := fixedLocalGPSIMDFixture(t, row)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	// An original assembler/fixture failure is not a translator rejection.
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalGPSIMDFixture(t, row)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("original complete GP/X transfer lacks fixed-local support", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalGPSIMDCompleteObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := fixedLocalGPSIMDCases()
	for index, row := range rows {
		_, _, source := fixedLocalGPSIMDFixture(t, row)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64, a uint64, b uint32) %s\n", name, row.result)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalGPSIMDDefinedBytes(t *testing.T) {
	for _, family := range fixedLocalGPSIMDNames {
		for _, direction := range []string{"GP to X", "X to GP", "X self"} {
			if direction == "X self" && family.bits == 32 {
				continue
			}
			t.Run(family.name+"/"+direction, func(t *testing.T) {
				width := family.bits / 8
				low := uint64(1)<<uint(width) - 1
				for _, input := range []uint64{0, 1, 0x55 & low, low &^ 1, low} {
					const upper = uint64(0x5500000012340000)
					state := cloneFixedLocalState(x86FixedLocalState{
						known:   map[Reg]uint8{AX: uint8(input)},
						vectors: map[Reg]uint64{"Z1": upper | input}, flags: x86ByteFlagsAll,
						constants: map[Reg]int64{AX: 42}, booleans: map[Reg]uint8{AX: 255},
					})
					operands := "AX,X1"
					if direction == "X to GP" {
						operands = "X1,AX"
					} else if direction == "X self" {
						operands = "X1,X1"
					}
					ins := x86ScalarLaneInstruction(t, family.name+" "+operands)
					if err := fixedLocalStep(&ins, &state, FuncSig{}, nil, 0); err != nil {
						t.Fatal("byte-preserving numeric register transfer rejected", input, err)
					}
					if state.flags != x86ByteFlagsAll {
						t.Fatal("numeric transfer changed FLAGS")
					}
					if direction == "X to GP" {
						_, constant := state.constants[AX]
						if state.known[AX] != uint8(input)|^uint8(low) || constant || state.booleans[AX] != ^uint8(low) {
							t.Fatal("unknown input retained old GP facts or lost zero-extension", input, state)
						}
						if state.vectors["Z1"] != upper|input {
							t.Fatal("GP destination changed source X aliases")
						}
						continue
					}
					want := ^low | input
					if family.legacy {
						want = upper | (0xffff &^ low) | input
					}
					if state.vectors["Z1"] != want || state.known[AX] != uint8(input) {
						t.Fatal("transfer lost unknown bytes, zeroed X bytes or upper aliases", input, state.vectors["Z1"], want)
					}
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalGPSIMDConsumerBoundaries(t *testing.T) {
	for _, family := range fixedLocalGPSIMDNames {
		for _, row := range []struct{ name, body string }{
			{"private address", family.name + " SP,X1"},
			{"native address", family.name + " SI,X1"},
			{"undefined stored bytes", family.name + " X15,16(SP)"},
			{"undefined result bytes", family.name + " X15,AX\nMOVQ AX,16(SP)"},
			{"missing private byte", "MOVB AX,32(SP)\n" + family.name + " 32(SP),X1"},
			{"private pointer spill", "MOVQ SP,16(SP)\n" + family.name + " 16(SP),X1"},
			{"native pointer spill", "MOVQ SI,16(SP)\n" + family.name + " 16(SP),X1"},
			{"past private frame", family.name + " 80(SP),X1"},
			{"untyped FP input", family.name + " p+0(FP),X1"},
			{"FP padding", family.name + " b+20(FP),X1"},
			{"input FP store", family.name + " X0,a+8(FP)"},
			{"numeric bits are not address", family.name + " X0,CX\nMOVQ (CX),AX"},
			{"readonly unowned symbol", family.name + " X0,literal<>(SB)"},
			{"MMX needs physical owner", "MOVQ X0,M0\nEMMS"},
		} {
			t.Run(family.name+"/"+row.name, func(t *testing.T) {
				fn, sig, source := fixedLocalGPSIMDFixture(t, fixedLocalGPSIMDCase{body: row.body, result: "uint64"})
				requireX86GoAssemblerResult(t, "amd64", source, true)
				if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("numeric transfer acquired missing bytes or another binding role", err)
				}
			})
		}
	}
}
