package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent source spellings and returned byte widths. Neither this test
// inventory nor a segment name is an initialized-pointee or pointer witness.
type x86SegmentMOVRow struct {
	op, store, result string
	width             int
}

func x86SegmentMOVRows(arch string) []x86SegmentMOVRow {
	rows := []x86SegmentMOVRow{{"MOVB", "MOVB", "uint8", 1}, {"MOVW", "MOVW", "uint16", 2}, {"MOVL", "MOVL", "uint32", 4}}
	if arch == "amd64" {
		rows = append(rows, x86SegmentMOVRow{"MOVQ", "MOVQ", "uint64", 8},
			x86SegmentMOVRow{"MOVD", "MOVQ", "uint64", 8}, x86SegmentMOVRow{"MOVDQ2Q", "MOVQ", "uint64", 8})
	}
	return rows
}

func x86SegmentMOVAddress(arch, segment, kind string) (string, string) {
	move := "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	switch kind {
	case "fixed":
		return "", "24(" + segment + ")"
	case "fixed-zero":
		return "", "0(" + segment + ")"
	case "base":
		return move + " offset+0(FP),BX\n", "-8(BX)(" + segment + ")"
	case "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8":
		// The second register is the segment annotation, not a numerical
		// scaled index. The actual Go encoder ignores its scale field.
		scale := strings.TrimPrefix(kind, "segment-index-scale")
		return move + " offset+0(FP),BX\n", "-8(BX)(" + segment + "*" + scale + ")"
	case "mode32-BP":
		return "MOVL offset+0(FP),BP\n", "-8(BP)(" + segment + ")"
	default:
		panic("unknown independent segment address fixture")
	}
}

func x86SegmentMOVFixture(t *testing.T, arch string, row x86SegmentMOVRow, segment, address string, dead bool) (string, string) {
	t.Helper()
	setup, memory := x86SegmentMOVAddress(arch, segment, address)
	body := setup + row.op + " " + memory + ",DX\n"
	result := "DX"
	if dead {
		result = "$7"
	}
	body += row.store + " " + result + ",ret+RESULT(FP)"
	declaration := "func view(offset uintptr) " + row.result
	return x86ResultGPSIMDAdmissionSource(t, arch, declaration, body), declaration
}

func x86SegmentMOVReadIR(t *testing.T, ir string, width, addressSpace int) {
	x86SegmentMOVNamedReadIR(t, ir, "view", width, addressSpace)
}

func x86SegmentMOVNamedReadIR(t *testing.T, ir, name string, width, addressSpace int) {
	t.Helper()
	x86SegmentMOVReadBody(t, x86StringMemoryFunction(t, ir, name), width, addressSpace)
}

func x86SegmentMOVReadBody(t *testing.T, body string, width, addressSpace int) {
	t.Helper()
	want := fmt.Sprintf("load volatile i%d, ptr addrspace(%d)", 8*width, addressSpace)
	if strings.Count(body, want) != 1 || strings.Count(body, "load volatile ") != 1 {
		t.Fatalf("exact segment read/width/volatility was changed, duplicated or discarded; want %q\n%s", want, body)
	}
	if strings.Contains(body, fmt.Sprintf("load i%d, ptr addrspace(%d)", 8*width, addressSpace)) {
		t.Fatal("native segment read became an ordinary eliminable load", body)
	}
}

func TestX86SegmentMOVNumericalContinuationThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		addresses := []string{"fixed", "fixed-zero", "base", "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8"}
		if target.arch == "386" {
			addresses = append(addresses, "mode32-BP")
		}
		for _, row := range x86SegmentMOVRows(target.arch) {
			for _, segment := range []string{"FS", "GS"} {
				space := 257
				if segment == "GS" {
					space = 256
				}
				for _, address := range addresses {
					for _, dead := range []bool{false, true} {
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(fmt.Sprintf("%s/%s/%s/%s/dead%t/%s", target.triple, row.op, segment, address, dead, api), func(t *testing.T) {
								source, declaration := x86SegmentMOVFixture(t, target.arch, row, segment, address, dead)
								ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
								if err != nil || ir == "" {
									t.Fatal("paired segment read lost its exact numerical continuation", err)
								}
								x86SegmentMOVReadIR(t, ir, row.width, space)
								x86SegmentMOVReadIR(t, x86DwordProductIROptimize(t, ir), row.width, space)
							})
						}
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.op+"/"+segment+"/void-dead/"+api, func(t *testing.T) {
						source, declaration := x86SegmentMOVVoidFixture(target.arch, row, segment)
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("void discarded result lost its observable hardware read", err)
						}
						x86SegmentMOVReadIR(t, ir, row.width, space)
						x86SegmentMOVReadIR(t, x86DwordProductIROptimize(t, ir), row.width, space)
					})
				}
				for _, address := range []string{"fixed", "base"} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+row.op+"/"+segment+"/void-address/"+address+"/"+api, func(t *testing.T) {
							source, declaration := x86SegmentMOVVoidAddressFixture(target.arch, row, segment, address)
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("void native read rejected its actual hardware/NUM address", err)
							}
							x86SegmentMOVReadIR(t, ir, row.width, space)
							x86SegmentMOVReadIR(t, x86DwordProductIROptimize(t, ir), row.width, space)
						})
					}
				}
			}
		}
		if target.arch == "amd64" {
			for _, segment := range []string{"FS", "GS"} {
				for _, alias := range []string{"DH", "BH"} {
					for _, dead := range []bool{false, true} {
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(fmt.Sprintf("%s/REX/%s/%s/dead%t/%s", target.triple, segment, alias, dead, api), func(t *testing.T) {
								source, declaration := x86SegmentMOVREXFixture(t, segment, alias, dead)
								ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
								if err != nil || ir == "" {
									t.Fatal("actual REX byte alias lost its numerical low byte", err)
								}
								space := 257
								if segment == "GS" {
									space = 256
								}
								x86SegmentMOVReadIR(t, ir, 1, space)
								x86SegmentMOVReadIR(t, x86DwordProductIROptimize(t, ir), 1, space)
							})
						}
					}
				}
			}
		}
	}
}

func x86SegmentMOVVoidFixture(arch string, row x86SegmentMOVRow, segment string) (string, string) {
	// No GP initialization is needed for a hardware segment's fixed offset.
	// Its zero displacement is not a pointer to address-space-zero null.
	return "TEXT ·view(SB),4,$0-0\n" + row.op + " 0(" + segment + "),DX\nRET\n", "func view()"
}

func x86SegmentMOVVoidAddressFixture(arch string, row x86SegmentMOVRow, segment, address string) (string, string) {
	setup, memory := x86SegmentMOVAddress(arch, segment, address)
	frame, declaration := 0, "func view()"
	if address == "base" {
		frame, declaration = 8, "func view(offset uintptr)"
		if arch == "386" {
			frame = 4
		}
	}
	return fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s%s %s,DX\nRET\n", frame, setup, row.op, memory), declaration
}

func x86SegmentMOVREXFixture(t *testing.T, segment, alias string, dead bool) (string, string) {
	t.Helper()
	actual := "SI"
	if alias == "BH" {
		actual = "DI"
	} else if alias != "DH" {
		t.Fatal("unexpected independent REX alias fixture", alias)
	}
	result := actual
	if dead {
		result = "$7"
	}
	declaration := "func view(offset uintptr) uint8"
	body := "MOVQ offset+0(FP),R8\nMOVB -8(R8)(" + segment + ")," + alias + "\nMOVB " + result + ",ret+RESULT(FP)"
	return x86ResultGPSIMDAdmissionSource(t, "amd64", declaration, body), declaration
}

func TestX86SegmentMOVCannotGrantIndependentAuthority(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86SegmentMOVRows(target.arch) {
			for _, segment := range []string{"FS", "GS"} {
				load := row.op + " 24(" + segment + "),DX\n"
				finish := row.store + " $7,ret+RESULT(FP)"
				declaration := "func view(offset uintptr,p *byte) " + row.result
				controls := []struct{ name, body, declaration string }{
					{"missing-result", load, declaration},
					{"unused-bool-parameter-missing-result", load, "func view(offset uintptr,unused bool) " + row.result},
					{"other-storage-role-missing-result", load + "PXOR X0,X0", declaration},
					{"unknown-offset", row.op + " -8(BX)(" + segment + "),DX\n" + finish, declaration},
					{"partial-offset", "MOVW $8,BX\n" + row.op + " -8(BX)(" + segment + "),DX\n" + finish, declaration},
					{"pointer-offset", fmt.Sprintf("%s p+%d(FP),BX\n", move, word) + row.op + " -8(BX)(" + segment + "),DX\n" + finish, declaration},
					{"pointer-overwritten-offset", move + " offset+0(FP),BX\n" + fmt.Sprintf("%s p+%d(FP),BX\n", move, word) + row.op + " -8(BX)(" + segment + "),DX\n" + finish, declaration},
					{"unknown-join", move + " offset+0(FP),AX\nCMPL AX,$0\nJE joined\n" + move + " offset+0(FP),BX\njoined:\n" + row.op + " -8(BX)(" + segment + "),DX\n" + finish, declaration},
					{"TLS-pseudo-register", row.op + " 24(TLS),DX\n" + finish, declaration},
					{"physical-SP-offset", row.op + " -8(SP)(" + segment + "),DX\n" + finish, declaration},
					{"store-permission", load + "MOVL $7,AX\n" + row.store + " AX,24(" + segment + ")\n" + finish, declaration},
					{"numerical-address-not-pointer", move + " offset+0(FP),DI\n" + load + row.store + " DX,(DI)\n" + finish, declaration},
					{"loaded-value-not-pointer", "MOVL $0,DX\n" + load + "MOVB (DX),AX\n" + finish, declaration},
					{"result-address-not-pointer", "MOVL $0,DX\n" + load + move + " DX,SI\nMOVB $7,(SI)\n" + finish, declaration},
					{"noncanonical-bool", "MOVL $0,DX\n" + load + "MOVB DX,ret+RESULT(FP)", "func view(offset uintptr,p *byte) bool"},
					{"pointer-result", "MOVL $0,DX\n" + load + move + " DX,ret+RESULT(FP)", "func view(offset uintptr,p *byte) *byte"},
					{"unknown-FLAGS", load + "SETEQ AX\nMOVB AX,ret+RESULT(FP)", "func view(offset uintptr,p *byte) bool"},
				}
				if target.arch == "amd64" {
					controls = append(controls, []struct{ name, body, declaration string }{
						{"physical-BP-offset", row.op + " -8(BP)(" + segment + "),DX\n" + finish, declaration},
						{"physical-BP-destination", row.op + " 24(" + segment + "),BP\n" + finish, declaration},
						{"REX-SP-destination", "MOVQ offset+0(FP),R8\nMOVB -8(R8)(" + segment + "),AH\n" + finish, declaration},
						{"REX-BP-destination", "MOVQ offset+0(FP),R8\nMOVB -8(R8)(" + segment + "),CH\n" + finish, declaration},
					}...)
				}
				for _, control := range controls {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+row.op+"/"+segment+"/"+control.name+"/"+api, func(t *testing.T) {
							source := x86ResultGPSIMDAdmissionSource(t, target.arch, control.declaration, control.body)
							ir, err := x86ScalarFPBitViewAPI(t, source, control.declaration, target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("paired segment load granted another input/result/store/native contract", err)
							}
						})
					}
				}
				for _, control := range []struct{ name, setup string }{
					{"unknown-base", ""},
					{"partial-base", "MOVW $8,BX\n"},
					{"pointer-base", fmt.Sprintf("%s p+%d(FP),BX\n", move, word)},
					{"revoked-NUM-base", move + " offset+0(FP),BX\n" + fmt.Sprintf("%s p+%d(FP),BX\n", move, word)},
				} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+row.op+"/"+segment+"/void-address-denial/"+control.name+"/"+api, func(t *testing.T) {
							source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s%s -8(BX)(%s),DX\nRET\n", 2*word, control.setup, row.op, segment)
							ir, err := x86ScalarFPBitViewAPI(t, source, "func view(offset uintptr,p *byte)", target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("void discarded result bypassed its actual native address input", err)
							}
						})
					}
				}
				// A real GP index after a segment-as-base is rejected by
				// Go's encoder, independently of its initialized-byte role.
				// Do not count these as valid-format permission rejections.
				for _, format := range []struct{ name, setup string }{
					{"unknown-index", ""},
					{"partial-index", "MOVW $8,CX\n"},
					{"full-index", move + " offset+0(FP),CX\n"},
					{"pointer-index", fmt.Sprintf("%s p+%d(FP),CX\n", move, word)},
				} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+row.op+"/"+segment+"/format-rejection/"+format.name+"/"+api, func(t *testing.T) {
							body := format.setup + row.op + " -8(" + segment + ")(CX*4),DX\n" + finish
							source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err == nil || ir != "" {
								t.Fatal("actual-Go illegal segment/index format was published", err)
							}
						})
					}
				}
				// Both standalone queries still lack the paired emitter, even
				// for a complete fixed-displacement read and exact return width.
				body := load + fmt.Sprintf("%s DX,ret0+0(FP)\nRET", row.store)
				_, file, sig, _ := x86ResultInitializationFixture(t, target.arch, "func Value() "+row.result, body)
				for _, query := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := query(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("declaration-only query borrowed a segment hardware input", row.op, segment, err)
					}
				}
			}
		}
	}
}

func TestX86SegmentMOVStateAndOriginalRoleBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86SegmentMOVRows(arch) {
			for _, segment := range []string{"FS", "GS"} {
				for _, address := range []string{"fixed", "fixed-zero", "base", "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8"} {
					t.Run(arch+"/"+row.op+"/"+segment+"/"+address, func(t *testing.T) {
						_, memory := x86SegmentMOVAddress(arch, segment, address)
						ins := x86ScalarLaneInstruction(t, row.op+" "+memory+",DX")
						state := x86ResultState{flags: 0x15, direction: x86ResultDirectionBackward, fp: []bool{true}, auto: []bool{true}}
						if address == "base" || strings.HasPrefix(address, "segment-index-scale") {
							state.gp[3] = 0xff
						}
						state.pointerGP[7], state.callerAddressGP[7], state.callerAddressOrigin[7] = true, true, 9
						state.pointerGP[2], state.callerAddressGP[2], state.callerAddressOrigin[2] = true, true, 3
						expected := state.clone()
						expected.pointerGP[2] = false
						expected.gp[2] = uint8(1<<uint(row.width) - 1)
						if row.width >= 4 {
							expected.gp[2] = 0xff
						}
						if accepted, known := x86LoweredScalarNativeLoad(ins, &state, nil, 0, arch); !known || !accepted || !reflect.DeepEqual(state, expected) {
							t.Fatal("segment continuation changed more than the exact numerical destination", accepted, known)
						}
						before, origins := state.callerAddressGP, state.callerAddressOrigin
						state.callerAddressGP = x86ResultCallerAddressesAfterTransfer(ins, before, state.callerAddressGP, nil, arch)
						state.callerAddressOrigin = x86ResultCallerOriginsAfter(ins, origins, state.callerAddressGP, map[int64]bool{8: true}, arch)
						expected.callerAddressGP[2], expected.callerAddressOrigin[2] = false, 0
						if !reflect.DeepEqual(state, expected) {
							t.Fatal("shared post-consumer retained the overwritten identity or revoked an unrelated one")
						}
					})
				}
				origins := []string{"encoded", "source-raw", "raw-return", "address-size", "unbound-address", "raw-segment", "numerical-certificate", "unmodeled-CS-role", "unresolved-offset", "index-extension", "invalid-scale", "wide-displacement", "unknown-offset", "partial-offset", "pointer-offset", "illegal-source-GP-scaled-index", "unknown-index", "partial-index", "pointer-index", "SP-destination", "SP-base", "SP-index"}
				if arch == "amd64" {
					origins = append(origins, "BP-destination", "BP-base", "BP-index", "REX-SP-destination", "REX-BP-destination")
				}
				for _, origin := range origins {
					t.Run(arch+"/"+row.op+"/"+segment+"/"+origin, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, row.op+" 24("+segment+"),DX")
						state := x86ResultState{flags: 0x15, direction: x86ResultDirectionForward}
						switch origin {
						case "encoded":
							ins.x86Encoded = true
						case "source-raw":
							ins.x86SourceRaw = new(x86SourceRawInstruction)
						case "raw-return":
							ins.x86RawNearReturn = new(x86RawNearReturnForm)
						case "address-size":
							ins.x86AddressBits = 32
						case "unbound-address":
							ins.x86UnboundAddressOverride = true
						case "raw-segment":
							ins.x86SegmentPrefix = 0x64
						case "numerical-certificate":
							ins.x86NumericalRead = new(x86NumericalReadCertificate)
						case "unmodeled-CS-role":
							ins.Args[0].Mem.Segment = "CS"
						case "unresolved-offset":
							ins.Args[0].Mem.OffRaw = "missing"
						case "index-extension":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.IndexExt, ins.Args[0].Mem.Scale = CX, "UXTW", 4
							state.gp[1] = 0xff
						case "invalid-scale":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
							state.gp[1] = 0xff
						case "wide-displacement":
							ins.Args[0].Mem.Off = 1 << 32
						case "unknown-offset", "partial-offset", "pointer-offset":
							ins.Args[0].Mem.Base = BX
							if origin == "partial-offset" {
								state.gp[3] = 3
							} else if origin == "pointer-offset" {
								state.pointerGP[3], state.callerAddressGP[3] = true, true
							}
						case "illegal-source-GP-scaled-index", "unknown-index", "partial-index", "pointer-index":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 4
							if origin == "illegal-source-GP-scaled-index" {
								state.gp[1] = 0xff
							} else if origin == "partial-index" {
								state.gp[1] = 3
							} else if origin == "pointer-index" {
								state.pointerGP[1], state.callerAddressGP[1] = true, true
							}
						case "SP-destination":
							ins.Args[1].Reg = SP
						case "BP-destination":
							ins.Args[1].Reg = BP
						case "SP-base", "BP-base":
							ins.Args[0].Mem.Base = SP
							if origin == "BP-base" {
								ins.Args[0].Mem.Base = BP
							}
						case "SP-index", "BP-index":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = SP, 4
							if origin == "BP-index" {
								ins.Args[0].Mem.Index = BP
							}
						case "REX-SP-destination", "REX-BP-destination":
							// Only the byte row has Go's high-byte/REX alias.
							ins.Op, ins.Args[0].Mem.Base, ins.Args[1].Reg = "MOVB", "R8", AH
							state.gp[8] = 0xff
							if origin == "REX-BP-destination" {
								ins.Args[1].Reg = CH
							}
						}
						before := state.clone()
						if accepted, _ := x86LoweredScalarNativeLoad(ins, &state, nil, 0, arch); accepted || !reflect.DeepEqual(state, before) {
							t.Fatal("unbound physical/source role acquired numerical segment bytes", origin)
						}
					})
				}
			}
		}
	}
}
