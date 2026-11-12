package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func x86LogicalFPDivideExpected(before x86ResultState, bits int, arch string) x86ResultState {
	expected := before.clone()
	writes, width := []Reg{AX, DX}, int64(bits/8)
	if bits == 8 {
		writes, width = writes[:1], 2 // Quotient AL and remainder AH, not DX.
	}
	for _, register := range writes {
		index, mask, _ := x86ResultGP(register, width, arch)
		expected.gp[index] |= mask
		expected.pointerGP[index], expected.callerAddressGP[index] = false, false
		expected.canonicalGP[index] &^= mask
		if width == 4 {
			expected.gp[index] = 255
			if arch == "amd64" {
				expected.canonicalGP[index] |= 0xf0
			}
		}
	}
	expected.flags = 0 // All six status flags are undefined, unlike DF/ID.
	return expected
}

func TestX86ImplicitDivideLogicalFPAllInputBytesAndAtomicOutputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		members := 0
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			members++
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				width := int64(row.bits / 8)
				ins := x86YMMReadSource(t, row.name+" divisor+3(FP)")
				before := x86ImplicitDivideInputState(row.bits, arch)
				before.fp = make([]bool, 24)
				owned := make([]bool, len(before.fp))
				for at := int64(3); at < 3+width; at++ {
					before.fp[at], owned[at] = true, true
				}
				state := before.clone()
				if accepted, known := x86LoweredImplicitDivideStep(ins, &state, owned, arch); !known || !accepted ||
					!reflect.DeepEqual(state, x86LogicalFPDivideExpected(before, row.bits, arch)) {
					t.Fatal("owned logical divisor lacks the exact paired #DE continuation or changed unrelated state", accepted, known)
				}
				for _, role := range []string{"FP value", "FP ownership", "AX", "DX"} {
					if role == "DX" && row.bits == 8 {
						continue // B has no implicit DX dividend dependency.
					}
					bytes := width
					if role == "AX" && row.bits == 8 {
						bytes = 2
					}
					for missing := int64(0); missing < bytes; missing++ {
						t.Run(fmt.Sprintf("missing-%s/byte%d", role, missing), func(t *testing.T) {
							current, extent := before.clone(), append([]bool(nil), owned...)
							switch role {
							case "FP value":
								current.fp[3+missing] = false
							case "FP ownership":
								extent[3+missing] = false
							default:
								index, _, _ := x86ResultGP(Reg(role), bytes, arch)
								current.gp[index] &^= 1 << uint(missing)
							}
							initial := current.clone()
							if accepted, known := x86LoweredImplicitDivideStep(ins, &current, extent, arch); !known || accepted || !reflect.DeepEqual(current, initial) {
								t.Fatal("division accepted a missing input or partially mutated rejected state", accepted, known)
							}
						})
					}
				}
				// Owned bytes do not authorize a standalone numerical division:
				// only the paired native opcode can preserve zero/overflow #DE.
				standalone := before.clone()
				if x86ScalarFPResultTransfer(ins, &standalone, owned, 0, arch) || !reflect.DeepEqual(standalone, before) {
					t.Fatal("standalone observer borrowed a native division continuation")
				}
			})
		}
		want := 8
		if arch == "386" {
			want = 6
		}
		if members != want {
			t.Fatal("complete signed/unsigned logical FP family directory changed", arch, members)
		}
	}
}

func TestX86ImplicitDivideLogicalFPSourceIdentityAndSpanRejections(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			original := x86YMMReadSource(t, row.name+" divisor+3(FP)")
			for _, change := range []string{"encoded", "raw", "address-size", "address-override", "segment", "foreign-read", "negative-offset", "out-of-bounds"} {
				t.Run(arch+"/"+row.name+"/"+change, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					state := x86ImplicitDivideInputState(row.bits, arch)
					state.fp = make([]bool, 16)
					owned := make([]bool, len(state.fp))
					for index := range state.fp {
						state.fp[index], owned[index] = true, true
					}
					switch change {
					case "encoded":
						ins.x86Encoded = true
					case "raw":
						ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
					case "address-size":
						ins.x86AddressBits = 16
					case "address-override":
						ins.x86UnboundAddressOverride = true
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "foreign-read":
						ins.x86NumericalRead = &x86NumericalReadCertificate{}
					case "negative-offset":
						ins.Args[0].FPOffset = -1
					case "out-of-bounds":
						ins.Args[0].FPOffset = int64(len(owned))
					}
					before := state.clone()
					if accepted, _ := x86LoweredImplicitDivideStep(ins, &state, owned, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("logical bytes acquired foreign source identity, extent or partial result state")
					}
				})
			}
		}
	}
}
