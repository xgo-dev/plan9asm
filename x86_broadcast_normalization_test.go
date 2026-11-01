package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86BroadcastMaskDataLowererCaseParity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				t.Run(arch+"/"+op+"/"+bank, func(t *testing.T) {
					for _, input := range []string{"K0", "K7"} {
						var expected string
						for _, spelling := range []string{op, strings.ToLower(op), "Vp" + strings.ToLower(op[2:])} {
							ins := x86YMMReadSource(t, op+" "+input+","+bank+"3")
							ins.Op, ins.Raw = Op(spelling), spelling+" "+input+","+bank+"3"
							c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "caseParity", Ret: Void}, nil)
							c.goarch = arch
							func() {
								defer func() {
									if panicValue := recover(); panicValue != nil {
										t.Fatalf("direct mask-data lowerer %q panicked: %v", spelling, panicValue)
									}
								}()
								known, terminated, err := c.lowerMaskRegisterBroadcast(Op(spelling), ins)
								if err != nil || !known || terminated {
									t.Fatalf("direct mask-data lowerer %q: known%t terminated%t err%v", spelling, known, terminated, err)
								}
							}()
							if spelling == op {
								expected = output.String()
							} else if output.String() != expected {
								t.Fatalf("%q emitted different numerical/alias IR from uppercase", spelling)
							}
							if strings.Contains(output.String(), "i0") {
								t.Fatalf("%q emitted a zero-width scalar", spelling)
							}
							for _, consumer := range x86ResultGPSIMDConsumers {
								for _, initialized := range []bool{false, true} {
									state := x86ResultState{flags: x86ByteFlagsAll}
									index, _ := amd64ParseKReg(ins.Args[0].Reg)
									state.masks[index] = initialized
									expected := state.clone()
									if initialized {
										expected.writeVector(3, 64, ^uint64(0), false)
									}
									if accepted := consumer.step(ins, &state, nil, 0, arch); accepted != initialized || !reflect.DeepEqual(state, expected) {
										t.Fatalf("%s %q lost actual mask-data input/output effects; initialized%t", consumer.name, spelling, initialized)
									}
								}
							}
						}
					}
				})
			}
		}
	}
}

func TestX86BroadcastMaskDataLowerVecRemainsUnknown(t *testing.T) {
	// K-data uses the preceding dedicated instruction dispatcher, not lowerVec.
	// Case normalization must not silently add a second admission path here.
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, spelling := range []string{op, strings.ToLower(op)} {
					c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "unknownCase", Ret: Void}, nil)
					c.goarch = arch
					ins := x86YMMReadSource(t, op+" K7,"+bank+"3")
					ins.Op = Op(spelling)
					before := output.String()
					known, terminated, err := c.lowerVec(Op(spelling), ins)
					if known || terminated || err != nil || output.String() != before {
						t.Fatalf("%s %s gained a lowerVec route: known%t terminated%t err%v", arch, spelling, known, terminated, err)
					}
				}
			}
		}
	}
}

func TestX86BroadcastMaskDataRawPrefixReparseAndTruncation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		mode := 64
		if arch == "386" {
			mode = 32
		}
		for _, op := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
			for width, bank := range []string{"X", "Y", "Z"} {
				code := assembleX87ControlBytes(t, arch, fmt.Sprintf("TEXT f(SB),4,$0-0\n%s K7,%s3\nRET\n", op, bank))
				if !bytes.Equal(code, append(x86MaskBroadcastPhysicalBytes(op, width, 7, 3), 0xc3)) {
					t.Fatalf("%s %s original physical witness: %x", arch, op, code)
				}
				for _, prefixes := range [][]byte{{0x64}, {0x65}, {0x67}, {0x64, 0x65}, {0x65, 0x64, 0x67}, {0x67, 0x64, 0x65}, {0x64, 0x67, 0x64, 0x67}} {
					physical := append(append([]byte(nil), prefixes...), code[:6]...)
					_, _, known, err := decodedX86VEXPackedBroadcastInstruction(physical, mode)
					if !known || err == nil {
						t.Fatalf("%s %s accumulated prefix%x escaped wrapper: known%t err%v", arch, op, prefixes, known, err)
					}
					// Even cleared caller annotations cannot hide actual prefixes:
					// the delegated K-data branch re-observes the complete bytes.
					_, _, known, err = decodedX86EVEXPackedBroadcastInstruction(physical, len(prefixes), mode, "", false)
					if !known || err == nil {
						t.Fatalf("%s %s lost original prefix index%x: known%t err%v", arch, op, prefixes, known, err)
					}
					for length := 0; length < len(physical); length++ {
						_, _, known, err := decodedX86VEXPackedBroadcastInstruction(physical[:length], mode)
						if length < len(prefixes)+5 {
							if known || err != nil {
								t.Fatalf("%s prefix%x truncated length%d claimed instruction: known%t err%v", op, prefixes, length, known, err)
							}
						} else if !known || err == nil {
							t.Fatalf("%s prefix%x missing ModRM was accepted", op, prefixes)
						}
					}
					if _, err := decodeX86RawDirectiveGroup(physical, mode, 0, "prefix guard", map[string]bool{}); err == nil {
						t.Fatalf("%s %s prefix%x escaped the full dispatcher", arch, op, prefixes)
					}
				}
			}
		}
	}
}
