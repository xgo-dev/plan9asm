package plan9asm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Independent source integers at both signed boundaries. In 386 asm6.go's
// asmandsz accepts signed32 or uint32, then encodes int32: the complete named
// W/L grammar is unchanged, and no original source operand is rewritten.
func x86Mode32LEADisplacements() []int64 {
	return []int64{-2147483648, -1, 2147483647, 2147483648, 2147483649, 4294967295}
}

func TestX86ResultNumericalLEAMode32UnsignedShapeAndReachingDomains(t *testing.T) {
	for _, width := range []string{"W", "L"} {
		for _, displacement := range x86Mode32LEADisplacements() {
			for _, destination := range []string{"AX", "BX", "CX"} {
				t.Run(fmt.Sprintf("%s/%d/%s", width, displacement, destination), func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, fmt.Sprintf("LEA%s %d(AX)(BX*8),%s", width, displacement, destination))
					original := ins
					for _, shape := range []bool{false, true} {
						state := x86ResultState{shapeOnly: shape, flags: x86ByteFlagsAll}
						state.gp[0], state.gp[3], state.gp[1] = 0xff, 0xff, 0xff
						if !x86ResultTransfer(ins, &state, nil, 0, "386") || state.flags != x86ByteFlagsAll {
							t.Fatal("legal NUM-only LEA was stolen by the pointer source-shape branch", shape, state)
						}
						if !shape && (state.pointerGP[0] || state.pointerGP[1] || state.pointerGP[3]) {
							t.Fatal("numerical LEA created reaching pointer authority")
						}
					}
					for _, kind := range []string{"unknown base", "unknown index", "actual pointer"} {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0], state.gp[3] = 0xff, 0xff
						switch kind {
						case "unknown base":
							state.gp[0] = 0
						case "unknown index":
							state.gp[3] = 0
						case "actual pointer":
							state.gp[0], state.pointerGP[0] = 0, true
						}
						if kind == "actual pointer" && width == "L" && displacement <= 2147483647 {
							continue // Existing opaque pointer arithmetic has its own role.
						}
						if x86ResultTransfer(ins, &state, nil, 0, "386") {
							t.Fatal("shape fallback granted unknown bytes or widened actual pointer arithmetic", kind, state)
						}
					}
					if !reflect.DeepEqual(ins, original) {
						t.Fatal("source opcode/operand/Raw identity was normalized in place")
					}
				})
			}
		}
	}
}

func TestX86ResultNumericalLEAMode32UnsignedWholeThreeAPIs(t *testing.T) {
	for _, width := range []string{"W", "L"} {
		for _, displacement := range x86Mode32LEADisplacements() {
			row := x86NumericalLEARow{width: width, address: fmt.Sprintf("%d(AX)(BX*8)", displacement), destination: "AX"}
			source, declarations := x86NumericalLEASources("386", []x86NumericalLEARow{row}, false)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%d/%s", width, displacement, api), func(t *testing.T) {
					if _, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", "i386-unknown-linux-gnu", api); err != nil {
						t.Fatal("legal initialized uint32 address expression failed whole-source proof", err)
					}
				})
			}
		}
	}
	for _, body := range []string{
		"LEAL 0xffffffff(AX),AX\nMOVL AX,X0\nMOVL X0,AX\nMOVL AX,ret+4(FP)",
		"MOVL p+0(FP),AX\nLEAL 0xffffffff(AX),AX\nMOVL AX,X0\nMOVL X0,AX\nMOVL AX,ret+4(FP)",
		"MOVW $7,AX\nLEAL 0xffffffff(AX),AX\nMOVL AX,X0\nMOVL X0,AX\nMOVL AX,ret+4(FP)",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			_, err := x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-8\n"+body+"\nRET\n", "func view(p *byte) uint32\n", "386", "i386-unknown-linux-gnu", api)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unknown/partial/pointer input acquired NUM result bytes", api, body, err)
			}
		}
	}
}

func TestX86ResultNumericalLEAMode32UnsignedCannotBorrowPhysicalAddressRoles(t *testing.T) {
	for _, width := range []string{"W", "L"} {
		for _, displacement := range []int64{-2147483649, 4294967296} {
			ins := x86PureGPUnknownInstruction(t, fmt.Sprintf("LEA%s %d(AX),CX", width, displacement))
			state := x86ResultState{shapeOnly: true, flags: x86ByteFlagsAll}
			state.gp[0] = 0xff
			if x86ResultTransfer(ins, &state, nil, 0, "386") {
				t.Fatal("NUM source-shape fallback widened Go's encoded displacement range", width, displacement)
			}
		}
		for name, change := range map[string]func(*Instr){
			"physical decoder":      func(i *Instr) { i.x86Encoded = true },
			"explicit address size": func(i *Instr) { i.x86AddressBits = 16 },
			"unbound address size":  func(i *Instr) { i.x86UnboundAddressOverride = true },
			"segment":               func(i *Instr) { i.x86SegmentPrefix = 0x64 },
			"raw source":            func(i *Instr) { i.x86SourceRaw = &x86SourceRawInstruction{} },
		} {
			t.Run(width+"/"+name, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, "LEA"+width+" 0xffffffff(AX),CX")
				change(&ins)
				if _, registered, err := x86TypedLEAByteEffect(ins.Op, ins, "386"); registered || err != nil {
					t.Fatal("physical/address-size role borrowed a named NUM source registration", registered, err)
				}
			})
		}
	}
}

func TestX86ResultNumericalLEAMode32UnsignedOriginalEncoding(t *testing.T) {
	for _, width := range []string{"W", "L"} {
		for _, displacement := range x86Mode32LEADisplacements() {
			t.Run(fmt.Sprintf("%s/%d", width, displacement), func(t *testing.T) {
				original := fmt.Sprintf("TEXT encoded(SB),4,$0-0\nLEA%s %d(AX),AX\nRET\n", width, displacement)
				actual := x86MinimumPositionOriginalGoBytes(t, "386", original)
				var want []byte
				if width == "W" {
					want = append(want, 0x66)
				}
				offset := int32(displacement)
				if offset >= -128 && offset <= 127 {
					want = append(want, 0x8d, 0x40, byte(offset))
				} else {
					want = append(want, 0x8d, 0x80)
					var encoded [4]byte
					binary.LittleEndian.PutUint32(encoded[:], uint32(offset))
					want = append(want, encoded[:]...)
				}
				want = append(want, 0xc3)
				if !bytes.Equal(actual, want) {
					t.Fatalf("actual original Go mode32 encoded displacement differs: %x, want %x", actual, want)
				}
			})
		}
	}
}
