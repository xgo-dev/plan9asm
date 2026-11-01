package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The family and physical widths are an independent inventory; the existing
// official-table owner checks these names against Go's complete multiply rows.
var fixedLocalImplicitMultiplyWidths = []struct {
	suffix string
	width  int64
	input  uint8
	output uint8
}{
	{"B", 1, 1, 3},
	{"W", 2, 3, 3},
	{"L", 4, 15, 255},
	{"Q", 8, 255, 255},
}

func TestGoAMD64FixedLocalImplicitMultiplyForms(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, stem := range []string{"MUL", "IMUL"} {
		for _, width := range fixedLocalImplicitMultiplyWidths {
			name := stem + width.suffix
			inputs := []string{"AX", "CX", "DX", "R8", "8(SP)", "(DX)"}
			if width.width == 1 {
				inputs = append(inputs, "AL", "AH")
			}
			for _, input := range inputs {
				t.Run(name+"/"+input, func(t *testing.T) {
					body := "MOVQ AX,CX\nMOVQ AX,R8\nMOVQ AX,DX\nMOVQ AX,8(SP)\n"
					if input == "(DX)" {
						body += "LEAQ 8(SP),DX\n"
					}
					body += name + " " + input
					// A narrow output cannot overwrite only part of a private
					// pointer. Byte multiply leaves DX unchanged; qword replaces it.
					valid := input != "(DX)" || width.width == 1 || width.width == 8
					fn, sig, source := fixedLocalGPFixture(t, body)
					original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
					count++
					proved, err := proveX86FixedLocal(fn, sig)
					if !valid {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("partial output overwrote a private pointer", err)
						}
						return
					}
					if err != nil {
						t.Fatal("complete initialized implicit multiply rejected", err)
					}
					observed := 0
					for _, ins := range proved.Instrs {
						if string(ins.Op) != name {
							continue
						}
						observed++
						access, found := ins.x86FixedLocalMemory[0]
						memory := strings.Contains(input, "(")
						if found != memory || found && (access.width != width.width || access.write ||
							access.nativeInput || access.owner != proved.x86FixedLocal) {
							t.Fatal("multiply did not preserve its exact private read", access)
						}
					}
					if observed != 1 {
						t.Fatalf("proved source retained %d multiply instructions, want one", observed)
					}
				})
			}
		}
	}
	if count != 52 {
		t.Fatalf("independent multiply inventory changed: %d", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalImplicitMultiplyByteEffects(t *testing.T) {
	for _, stem := range []string{"MUL", "IMUL"} {
		for _, width := range fixedLocalImplicitMultiplyWidths {
			sources := []struct {
				name, root Reg
				mask       uint8
			}{{AX, AX, width.input}, {CX, CX, width.input}, {DX, DX, width.input}}
			if width.width == 1 {
				sources = append(sources, struct {
					name, root Reg
					mask       uint8
				}{"AH", AX, 2})
			}
			for _, source := range sources {
				name := stem + width.suffix
				t.Run(name+"/"+string(source.name), func(t *testing.T) {
					ins := x86YMMReadSource(t, name+" "+string(source.name))
					effect, known, err := fixedLocalGPByteEffect(ins)
					if !known || err != nil || !effect.requiresResultProof {
						t.Fatal("closed implicit family lacks its existing numerical effect", known, err)
					}
					state := x86FixedLocalState{
						known:    map[Reg]uint8{AX: width.input, DX: 0, CX: 0},
						booleans: make(map[Reg]uint8),
						flags:    x86ByteFlagsAll,
					}
					state.known[source.root] |= source.mask
					before := cloneFixedLocalState(state)
					want := cloneFixedLocalState(before)
					want.known[AX] |= width.output
					if width.width != 1 {
						want.known[DX] |= width.output
					}
					want.flags = x86ByteFlagCF | x86ByteFlagOF
					if err := fixedLocalTypedByteStep(&ins, &state, FuncSig{}, nil, 0, effect); err != nil ||
						!reflect.DeepEqual(state.known, want.known) || state.flags != want.flags {
						t.Fatal("implicit accumulator/output width or FLAGS changed", state, want, err)
					}
					for _, input := range []struct {
						root Reg
						mask uint8
					}{{AX, width.input}, {source.root, source.mask}} {
						for bit := uint8(1); bit != 0; bit <<= 1 {
							if input.mask&bit == 0 {
								continue
							}
							missing := cloneFixedLocalState(before)
							missing.known[input.root] &^= bit
							if err := fixedLocalTypedByteStep(&ins, &missing, FuncSig{}, nil, 0, effect); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unknown input byte acquired a numerical result", input, bit, err)
							}
						}
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalImplicitMultiplyBoundaries(t *testing.T) {
	for _, stem := range []string{"MUL", "IMUL"} {
		for _, width := range fixedLocalImplicitMultiplyWidths {
			name := stem + width.suffix
			for _, row := range []struct {
				name, before, source, after string
				valid                       bool
			}{
				{"carry", "", "0(SP)", "ADCQ $0,AX", true},
				{"overflow", "", "0(SP)", "JOS done\ndone:", true},
				{"old zero revoked", "CMPQ AX,AX\n", "0(SP)", "JEQ done\ndone:", false},
				{"old parity revoked", "CMPQ AX,AX\n", "0(SP)", "JPS done\ndone:", false},
				{"old sign revoked", "CMPQ AX,AX\n", "0(SP)", "JMI done\ndone:", false},
				{"old auxiliary revoked", "CMPQ AX,AX\n", "0(SP)", "LAHF", false},
				{"missing source", "", "CX", "", false},
				{"private accumulator", "MOVQ SP,AX\n", "0(SP)", "", false},
				{"private source", "MOVQ SP,CX\n", "CX", "", false},
				{"unwritten memory", "", "8(SP)", "", false},
				{"one missing memory byte", "MOVQ AX,8(SP)\n", fmt.Sprintf("%d(SP)", 17-width.width), "", false},
				{"outside frame", "", "64(SP)", "", false},
				{"one byte outside frame", "MOVQ AX,56(SP)\n", fmt.Sprintf("%d(SP)", 65-width.width), "", false},
				{"numerical address", "", "(AX)", "", false},
				{"private spill", "MOVQ SP,8(SP)\n", "8(SP)", "", false},
			} {
				t.Run(name+"/"+row.name, func(t *testing.T) {
					fn, sig, _ := fixedLocalGPFixture(t, row.before+name+" "+row.source+"\n"+row.after)
					_, err := proveX86FixedLocal(fn, sig)
					if (err == nil) != row.valid {
						t.Fatalf("valid=%v: %v", row.valid, err)
					}
				})
			}
			for _, role := range []string{"accumulator", "source"} {
				t.Run(name+"/opaque "+role, func(t *testing.T) {
					body := "MOVQ SI,CX\n" + name + " CX"
					if role == "accumulator" {
						body = "MOVQ SI,AX\n" + name + " 0(SP)"
					}
					fn, sig, _ := fixedLocalInputFixture(t, body)
					if _, err := proveX86FixedLocal(fn, sig); err != nil {
						t.Fatal("complete native machine bits were rejected as multiply input", err)
					}
				})
			}
		}
	}
}
