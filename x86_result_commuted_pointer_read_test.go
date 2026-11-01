package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86IncomingPointerCommutedReadThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		entry := fmt.Sprintf("%s p+0(FP),BX\n%s n+%d(FP),AX\n", move, move, word)
		type addressCase struct {
			name, setup, address string
			accept               bool
		}
		rows := []addressCase{
			{"pointer-base", entry, "-8(BX)(AX*1)", true},
			{"pointer-base-scaled-number", entry, "-8(BX)(AX*4)", true},
			{"pointer-index", entry, "-8(AX)(BX*1)", true},
			{"pointer-index-result-alias", entry, "-8(AX)(BX*1)", true},
			{"unknown-number", move + " p+0(FP),BX\n", "-8(AX)(BX*1)", false},
			{"unknown-pointer", fmt.Sprintf("%s n+%d(FP),AX\n", move, word), "-8(AX)(BX*1)", false},
			{"two-pointers", entry + move + " BX,AX\n", "-8(AX)(BX*1)", false},
			{"two-numbers", entry + move + " $64,BX\n", "-8(AX)(BX*1)", false},
			{"scaled-pointer-two", entry, "-8(AX)(BX*2)", false},
			{"scaled-pointer-four", entry, "-8(AX)(BX*4)", false},
			{"scaled-pointer-eight", entry, "-8(AX)(BX*8)", false},
			{"partial-pointer", entry + "MOVB $0,BX\n", "-8(AX)(BX*1)", false},
			{"same-pointer-twice", entry, "-8(BX)(BX*1)", false},
			{"loaded-number-is-not-pointer", entry + "MOVL -8(AX)(BX*1),BX\n", "(BX)", false},
			{"mixed-pointer-number-join", entry + "CMPL AX,$0\nJE joined\nMOVL $64,BX\njoined:\n", "-8(AX)(BX*1)", false},
			{"unbound-frame-index", entry, "-8(AX)(SP*1)", false},
		}
		if target.arch == "amd64" {
			rows = append(rows, addressCase{"unbound-frame-base", entry, "-8(BP)(BX*1)", false})
		} else {
			rows = append(rows, addressCase{"ordinary-mode32-BP-index", entry + "MOVL BX,BP\n", "-8(AX)(BP*1)", true})
		}
		for _, row := range rows {
			destination := "CX"
			if row.name == "pointer-index-result-alias" {
				destination = "BX"
			}
			body := row.setup + "MOVL " + row.address + "," + destination + "\n" +
				fmt.Sprintf("MOVL %s,ret+%d(FP)\nRET", destination, 2*word)
			declaration := "func Value(p *uint32,n uintptr) uint32"
			_, file, sig, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
			// Neither address order supplies a standalone memory/result query
			// with the paired original volatile-load continuation.
			for _, query := range []func(Func, FuncSig, string) error{
				CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
			} {
				if err := query(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("address spelling manufactured a standalone native read", row.name, err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if row.accept {
						if err != nil || !strings.Contains(ir, "load volatile i32,") {
							t.Fatal("typed pointer/NUM address lost its exact paired read", err)
						}
					} else if err == nil || ir != "" {
						t.Fatalf("unbound/scaled/nonnumeric address accepted: output=%t error=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestX86IncomingPointerCommutedReadRolesAndOriginalIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := x86ResultPointerWord(arch)
		base, numericMask, _ := x86ResultGP(AX, word, arch)
		pointer, _, _ := x86ResultGP(BX, word, arch)
		for _, row := range []struct {
			name, address                                string
			basePointer, indexPointer, baseNUM, indexNUM bool
			accept                                       bool
		}{
			{"original-order", "-8(AX)(BX*4)", true, false, false, true, true},
			{"commuted-order", "-8(AX)(BX*1)", false, true, true, false, true},
			{"unknown-base", "-8(AX)(BX*1)", false, true, false, false, false},
			{"unknown-index", "-8(AX)(BX*1)", false, false, true, false, false},
			{"two-pointers", "-8(AX)(BX*1)", true, true, false, false, false},
			{"two-numbers", "-8(AX)(BX*1)", false, false, true, true, false},
			{"scaled-pointer", "-8(AX)(BX*2)", false, true, true, false, false},
			{"same-pointer", "-8(BX)(BX*1)", false, true, true, false, false},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
				state.pointerGP[base], state.pointerGP[pointer] = row.basePointer, row.indexPointer
				if row.baseNUM {
					state.gp[base] = numericMask
				}
				if row.indexNUM {
					state.gp[pointer] = numericMask
				}
				ins := x86ScalarLaneInstruction(t, "MOVL "+row.address+",CX")
				before := state.clone()
				if row.name == "commuted-order" {
					if x86ResultIncomingPointerAddressIdentity(ins.Args[0], &state, arch) {
						t.Fatal("paired read widened the independent store/RMW address role")
					}
					lea := "LEAQ"
					if arch == "386" {
						lea = "LEAL"
					}
					address := x86ScalarLaneInstruction(t, lea+" "+row.address+",CX")
					if accepted, _ := x86ResultIncomingPointerTransfer(address, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("paired read created an independent commuted LEA pointer")
					}
				}
				if accepted, known := x86LoweredScalarNativeLoad(ins, &state, nil, 0, arch); !known || accepted != row.accept {
					t.Fatal("paired load disagrees with the independent address roles", accepted, known)
				}
				if !row.accept && !reflect.DeepEqual(state, before) {
					t.Fatal("rejected address changed result state")
				}
				if state.flags != before.flags || state.direction != before.direction {
					t.Fatal("address permutation changed FLAGS/DF")
				}
			})
		}
		for _, origin := range []string{"decoded", "raw", "raw-return", "address-size", "unbound-address", "segment"} {
			t.Run(arch+"/"+origin, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "MOVL -8(AX)(BX*1),CX")
				switch origin {
				case "decoded":
					ins.x86Encoded = true
				case "raw":
					ins.x86SourceRaw = new(x86SourceRawInstruction)
				case "raw-return":
					ins.x86RawNearReturn = new(x86RawNearReturnForm)
				case "address-size":
					ins.x86AddressBits = 32
				case "unbound-address":
					ins.x86UnboundAddressOverride = true
				case "segment":
					ins.x86SegmentPrefix = 0x64
				}
				state := x86ResultState{}
				state.gp[base], state.pointerGP[pointer] = numericMask, true
				before := state.clone()
				if accepted, _ := x86LoweredScalarNativeLoad(ins, &state, nil, 0, arch); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("commuted operand borrowed an unbound physical-source role")
				}
			})
		}
	}
}
