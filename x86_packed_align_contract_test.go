package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86PackedAlignRows() []struct {
	op     string
	bits   int
	legacy bool
} {
	return []struct {
		op     string
		bits   int
		legacy bool
	}{
		{"PALIGNR", 8, true},
		{"VPALIGNR", 8, false},
		{"VALIGND", 32, false},
		{"VALIGNQ", 64, false},
	}
}

func x86PackedAlignInstruction(op, first, bank, mask string, immediate, destination int, legacy bool) string {
	arguments := fmt.Sprintf("$%d,%s,", immediate, first)
	if !legacy {
		arguments += bank + "1,"
	}
	return op + " " + arguments + mask + fmt.Sprint(bank, destination)
}

// This independent reference uses byte positions in the ISA concatenation,
// never a production selector or operand descriptor.
func x86PackedAlignExpectedKnown(op string, width, immediate int, first, second, old uint64, merge, legacy bool) uint64 {
	var defined uint64
	for output := 0; output < width; output++ {
		at, known := 0, false
		if op == "PALIGNR" || op == "VPALIGNR" {
			at = output%16 + immediate
			if at >= 32 {
				known = true
			} else if at < 16 {
				known = first>>uint(output/16*16+at)&1 != 0
			} else {
				known = second>>uint(output/16*16+at-16)&1 != 0
			}
		} else {
			bytes := 4
			if op == "VALIGNQ" {
				bytes = 8
			}
			at = (output/bytes+(immediate&(width/bytes-1)))*bytes + output%bytes
			if at < width {
				known = first>>uint(at)&1 != 0
			} else {
				known = second>>uint(at-width)&1 != 0
			}
		}
		if merge {
			known = known && old>>uint(output)&1 != 0
		}
		if known {
			defined |= uint64(1) << uint(output)
		}
	}
	upper := ^x86CallerVectorByteMask(int64(width))
	if legacy {
		upper &= old
	}
	return upper | defined
}

func TestX86PackedAlignSelectedBytesAndUnknownDeadDomain(t *testing.T) {
	for _, row := range x86PackedAlignRows() {
		banks := []string{"X", "Y", "Z"}
		if row.legacy {
			banks = banks[:1]
		}
		for _, bank := range banks {
			for _, mode := range []string{"plain", "merge", "zero"} {
				if row.legacy && mode != "plain" {
					continue
				}
				for _, alias := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/alias=%t", row.op, bank, mode, alias), func(t *testing.T) {
						width := amd64VectorByteWidth(Reg(bank + "0"))
						for immediate := 0; immediate < 256; immediate++ {
							for _, seed := range []uint64{0, 0x51a9435fa095f037, 0xffffffffffffffff} {
								state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
									fp: []bool{true, false}, auto: []bool{false, true}}
								state.writeVector(0, 64, seed, false)
								state.writeVector(1, 64, seed^0xf037954aa19359a7, false)
								state.writeVector(2, 64, seed^0xa37b9351b4a78c67, false)
								state.masks[1], state.pointerGP[3], state.gp[0] = true, true, 0x55
								destination := 2
								if alias {
									destination = 0
								}
								op, mask := row.op, ""
								if mode != "plain" {
									mask = "K1,"
								}
								if mode == "zero" {
									op += ".Z"
								}
								ins := x86ScalarLaneInstruction(t, x86PackedAlignInstruction(op, bank+"0", bank, mask, immediate, destination, row.legacy))
								first, second, old := state.vectorBytes(0), state.vectorBytes(1), state.vectorBytes(destination)
								if row.legacy {
									second = old
								}
								want := state.clone()
								want.writeVector(destination, 64, x86PackedAlignExpectedKnown(row.op, width, immediate,
									first, second, old, mode == "merge", row.legacy), false)
								if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, want) {
									t.Fatal("selector invented bytes, rejected a dead unknown register result or changed independent state", immediate, seed)
								}
								caller := x86SourceStackState{
									vectors: map[Reg]uint64{"Z0": seed, "Z1": seed ^ 0xf037954aa19359a7, "Z2": seed ^ 0xa37b9351b4a78c67},
									masks:   map[Reg]bool{"K1": true}, known: map[Reg]uint8{AX: 0xff},
									callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}},
								}
								wantCaller := x86CloneCallerState(caller)
								wantCaller.vectors[Reg(fmt.Sprint("Z", destination))] = x86PackedAlignExpectedKnown(row.op, width, immediate,
									first, second, old, mode == "merge", row.legacy)
								form, known, err := x86PackedAlignProperties(ins.Op, ins, "amd64")
								if !known || err != nil || !x86CallerPackedAlignStep(&ins, form, &caller, nil) || !reflect.DeepEqual(caller, wantCaller) {
									t.Fatal("caller and result consumers diverged on the independent selector", immediate, seed, err)
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestX86PackedAlignDeadNativeMemoryCannotDisappear(t *testing.T) {
	for _, row := range x86PackedAlignRows() {
		banks := []string{"X", "Y", "Z"}
		if row.legacy {
			banks = banks[:1]
		}
		for _, bank := range banks {
			t.Run(row.op+"/"+bank, func(t *testing.T) {
				width := amd64VectorByteWidth(Reg(bank + "0"))
				op, mask := row.op, "K1,"
				if row.legacy {
					mask = ""
				} else {
					op += ".Z"
				}
				instruction := x86PackedAlignInstruction(op, "(AX)", bank, mask, 255, 2, row.legacy)
				source := "TEXT ·Value(SB),4,$0-8\nMOVQ p+0(FP),AX\n" +
					"MOVL $0,BX\nKMOVD BX,K1\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n" + instruction + "\nRET\n"
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[64]byte)", "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil {
						t.Fatal("initialized dead native source lost its paired access", api, err)
					}
					optimized := x86DwordProductIROptimize(t, ir)
					for _, text := range []string{ir, optimized} {
						if row.legacy {
							if !strings.Contains(text, "asm sideeffect") || !strings.Contains(text, "palignr $$255") {
								t.Fatal("legacy alignment/fault opcode was removed or replaced", api)
							}
						} else if !strings.Contains(text, fmt.Sprintf("load volatile <%d x i8>", width)) {
							t.Fatal("E4NF zero-mask/large-count access was removed or narrowed", api)
						}
					}
				}
			})
		}
	}
}
