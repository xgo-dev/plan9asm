package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86DirectionPOPFCompleteGoFlagStackRows(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}") {
		t.Fatal("complete Go no-operand grammar changed")
	}
	for _, width := range []struct{ name, prefix string }{{"W", "Pe"}, {"L", "P32"}, {"Q", "Py"}} {
		for _, action := range []struct{ name, opcode string }{{"PUSHF", "0x9c"}, {"POPF", "0x9d"}} {
			op := action.name + width.name
			row := fmt.Sprintf("{A%s, ynone, %s, opBytes{%s}},", op, width.prefix, action.opcode)
			if strings.Count(string(table), row) != 1 {
				t.Fatal("complete independent Go FLAGS stack encoding changed", row)
			}
			for _, arch := range []string{"amd64", "386"} {
				_, known, err := x86StackWidthProperties(x86ScalarLaneInstruction(t, op), arch)
				valid := width.name == "W" || arch == "386" && width.name == "L" || arch == "amd64" && width.name == "Q"
				if !known || (err == nil) != valid {
					t.Fatal("typed stack grammar changed source mode", arch, op, err)
				}
			}
		}
	}
}

func TestX86DirectionPOPFIndependentTransferRevokesPriorFact(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range []string{"W", "L", "Q"} {
			for direction := x86ResultDirectionUnknown; direction <= x86ResultDirectionEither; direction++ {
				t.Run(fmt.Sprintf("%s/%s/DF=%d", arch, width, direction), func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nPOPF"+width+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					valid := width == "W" || arch == "386" && width == "L" || arch == "amd64" && width == "Q"
					checked := false
					err = checkX86ResultSourceFlow(file.Funcs[0], x86ResultState{direction: direction}, nil, 0, arch,
						func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
							if spec, known, err := x86StackWidthProperties(ins, arch); known && spec.mode == amd64StackPopFlags {
								// This independent test-only role accepts a valid restore,
								// but supplies no private saved-bit observation.
								return err == nil
							}
							return x86ResultTransfer(ins, state, owned, offset, arch)
						}, func(state x86ResultState, _ int) error {
							checked = true
							if state.direction != x86ResultDirectionUnknown {
								return fmt.Errorf("unobserved POPF retained prior DF=%d", state.direction)
							}
							return nil
						})
					if valid && (err != nil || !checked) || !valid && (!errors.Is(err, ErrProbeNeedsContext) || checked) {
						t.Fatal("independent POPF role changed DF or source-mode boundaries", err, checked)
					}
				})
			}
		}
	}
}

func TestX86DirectionPOPFCheckedStackUsesOnlySavedBits(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		widths := []string{"W", "Q"}
		if arch == "386" {
			widths = []string{"W", "L"}
		}
		for _, width := range widths {
			for saved := x86ResultDirectionUnknown; saved <= x86ResultDirectionEither; saved++ {
				for _, savedID := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/DF=%d/ID=%t", arch, width, saved, savedID), func(t *testing.T) {
						file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nNOP\nPUSHF"+width+"\nNOP\nPOPF"+width+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						initial := x86ResultState{direction: saved, flags: 0x15}
						initial.gp[3] = 0x51
						checked := false
						err = checkX86ResultSourceFlow(file.Funcs[0], initial, nil, 0, arch,
							func(ordinal int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
								if ins.Op == "NOP" {
									if ordinal == 1 {
										state.valueStack.id = savedID
									} else {
										state.direction, state.flags, state.valueStack.id = x86ResultDirectionForward, x86ByteFlagsAll, true
									}
									return true
								}
								return x86ResultTransfer(ins, state, owned, offset, arch)
							}, func(state x86ResultState, _ int) error {
								checked = true
								want := x86ResultDirectionUnknown
								if saved != x86ResultDirectionUnknown {
									want = x86ResultDirectionEither // The private stack stores definedness, not a chosen bit value.
								}
								if state.direction != want || state.flags != initial.flags || state.gp != initial.gp ||
									state.valueStack.id != (width == "W" || savedID) || len(state.valueStack.bytes) != 0 {
									return fmt.Errorf("POPF borrowed current rather than saved DF/status/ID facts: DF=%d flags=%02x ID=%t", state.direction, state.flags, state.valueStack.id)
								}
								return nil
							})
						if err != nil || !checked {
							t.Fatal(err, checked)
						}
					})
				}
			}
			for _, right := range []string{"STD", "NOP"} {
				t.Run(arch+"/"+width+"/join-"+right, func(t *testing.T) {
					source := "TEXT f(SB),4,$0-0\nMOVL $1,AX\nCMPL AX,$0\nJZ right\nCLD\nPUSHF" + width +
						"\nJMP joined\nright:\n" + right + "\nPUSHF" + width + "\njoined:\nCLD\nPOPF" + width + "\nRET\n"
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					err = checkX86ResultSourceFlow(file.Funcs[0], x86ResultState{}, nil, 0, arch,
						func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
							return x86ResultTransfer(ins, state, owned, offset, arch)
						}, func(state x86ResultState, _ int) error {
							want := x86ResultDirectionEither
							if right == "NOP" {
								want = x86ResultDirectionUnknown
							}
							if state.direction != want {
								return fmt.Errorf("saved-bit CFG join became DF=%d, want %d", state.direction, want)
							}
							return nil
						})
					if err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86DirectionPOPFValueStackCloneJoinSavedFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		widths := []string{"W", "Q"}
		if arch == "386" {
			widths = []string{"W", "L"}
		}
		for _, width := range widths {
			t.Run(arch+"/"+width, func(t *testing.T) {
				state := x86ResultState{direction: x86ResultDirectionEither, flags: 0x15, valueStack: new(x86ResultValueStack)}
				if !x86ResultTransfer(x86ScalarLaneInstruction(t, "PUSHF"+width), &state, nil, 0, arch) {
					t.Fatal("actual private PUSHF failed")
				}
				clone := state.clone()
				clone.valueStack.bytes[len(clone.valueStack.bytes)-2] &^= 1 << 2 // Saved physical DF bit 10.
				if state.valueStack.bytes[len(state.valueStack.bytes)-2]&(1<<2) == 0 {
					t.Fatal("clone changed the independently saved DF mask")
				}
				for index, input := range []x86ResultState{state.clone(), clone.clone(), state.intersect(clone), clone.intersect(state)} {
					input.direction = x86ResultDirectionForward
					if !x86ResultTransfer(x86ScalarLaneInstruction(t, "POPF"+width), &input, nil, 0, arch) {
						t.Fatal("actual private POPF failed")
					}
					want := x86ResultDirectionUnknown
					if index == 0 {
						want = x86ResultDirectionEither
					}
					if input.direction != want || input.flags != state.flags || len(input.valueStack.bytes) != 0 {
						t.Fatal("clone/join borrowed a current or missing saved fact", index, input.direction)
					}
				}
			})
		}
	}
}
