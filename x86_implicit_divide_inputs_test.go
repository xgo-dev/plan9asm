package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func x86ImplicitDivideInputState(bits int, arch string) x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
		fp: []bool{true, false}, auto: []bool{false, true},
		valueStack: &x86ResultValueStack{bytes: []uint8{255, 255, 255, 255}, id: true}}
	for index := range state.gp {
		state.gp[index], state.canonicalGP[index] = 0x80, 0xff
	}
	width, accumulator := int64(bits/8), int64(bits/8)
	if bits == 8 {
		accumulator = 2
	}
	for _, input := range []struct {
		reg   Reg
		bytes int64
	}{{AX, accumulator}, {DX, width}, {BX, width}} {
		index, mask, _ := x86ResultGP(input.reg, input.bytes, arch)
		state.gp[index] |= mask
	}
	state.pointerGP[6], state.callerAddressGP[6] = true, true
	state.writeVector(3, 64, 0x5555555555555555, false)
	state.masks[2] = true
	return state
}

func TestX86ImplicitDivideEveryInputByteAndExactOutputState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.name+" BX")
				before := x86ImplicitDivideInputState(row.bits, arch)
				state, expected := before.clone(), before.clone()
				expected.flags = 0
				width, accumulator := int64(row.bits/8), int64(row.bits/8)
				writes := []Reg{AX, DX}
				if row.bits == 8 {
					accumulator, writes = 2, writes[:1]
				}
				for _, register := range writes {
					bytes := width
					if row.bits == 8 {
						bytes = 2
					}
					index, mask, _ := x86ResultGP(register, bytes, arch)
					expected.gp[index] |= mask
					expected.canonicalGP[index] &^= mask
					if bytes == 4 {
						expected.gp[index] = 0xff
						if arch == "amd64" {
							expected.canonicalGP[index] |= 0xf0
						}
					}
				}
				if accepted, known := x86LoweredImplicitDivideStep(ins, &state, nil, arch); !known || !accepted || !reflect.DeepEqual(state, expected) {
					t.Fatal("division invented memory/aliases/canonical bytes or retained undefined status", state.gp, state.flags)
				}
				inputs := []struct {
					reg   Reg
					bytes int64
				}{{BX, width}, {AX, accumulator}}
				if row.bits != 8 {
					inputs = append(inputs, struct {
						reg   Reg
						bytes int64
					}{DX, width})
				}
				for _, input := range inputs {
					for missing := int64(0); missing < input.bytes; missing++ {
						t.Run(fmt.Sprintf("%s/byte%d", input.reg, missing), func(t *testing.T) {
							current := before.clone()
							index, _, _ := x86ResultGP(input.reg, input.bytes, arch)
							current.gp[index] &^= 1 << uint(missing)
							initial := current.clone()
							if accepted, known := x86LoweredImplicitDivideStep(ins, &current, nil, arch); !known || accepted || !reflect.DeepEqual(current, initial) {
								t.Fatal("division consumed an unknown input or partially changed rejected state")
							}
						})
					}
				}
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatal("standalone NUM query borrowed the native #DE continuation")
				}
				for _, change := range []string{"raw", "encoded", "address size", "address override", "segment prefix", "opaque divisor"} {
					changed, current := ins, before.clone()
					switch change {
					case "raw":
						changed.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
					case "encoded":
						changed.x86Encoded = true
					case "address size":
						changed.x86AddressBits = 16
					case "address override":
						changed.x86UnboundAddressOverride = true
					case "segment prefix":
						changed.x86SegmentPrefix = 0x64
					case "opaque divisor":
						index, _, _ := x86ResultGP(BX, width, arch)
						current.gp[index], current.pointerGP[index] = 0, true
					}
					initial := current.clone()
					if accepted, known := x86LoweredImplicitDivideStep(changed, &current, nil, arch); !known || accepted || !reflect.DeepEqual(current, initial) {
						t.Fatal("division borrowed another entry/source role or mutated failed state", change)
					}
				}
			})
		}
	}
}

func TestX86ImplicitDivideNativeReadRequiresActualAddressAndNoNewBacking(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.name+" 3(SI)(BX*2)")
				before := x86ImplicitDivideInputState(row.bits, arch)
				index, mask, _ := x86ResultGP(BX, x86ResultPointerWord(arch), arch)
				before.gp[index] = mask
				state := before.clone()
				if accepted, known := x86LoweredImplicitDivideStep(ins, &state, nil, arch); !accepted || !known || state.pointerGP != before.pointerGP || !reflect.DeepEqual(state.fp, before.fp) || !reflect.DeepEqual(state.auto, before.auto) {
					t.Fatal("paired native read did not retain exact input/address/storage obligations")
				}
				for _, missing := range []string{"pointer", "index"} {
					current := before.clone()
					if missing == "pointer" {
						current.pointerGP[6], current.gp[6] = false, 0xff
					} else {
						current.gp[index] = 0
					}
					initial := current.clone()
					if accepted, _ := x86LoweredImplicitDivideStep(ins, &current, nil, arch); accepted || !reflect.DeepEqual(current, initial) {
						t.Fatal("division gained an address from NUM or an unknown index", missing)
					}
				}
			})
		}
	}
}
