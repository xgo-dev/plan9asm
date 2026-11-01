package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86CRC32SparseNUMFlagsAndSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86CRC32ResultCases(arch) {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				register := x86ScalarLaneInstruction(t, row.op+" BX,AX")
				native := x86ScalarLaneInstruction(t, row.op+" -1(DX)(BX*1),AX")
				bx, _, _ := x86ResultGP(BX, 4, arch)
				dx, _, _ := x86ResultGP(DX, 4, arch)
				for mask := 0; mask < 256; mask++ {
					for _, sourceMask := range []uint8{0, 1, 3, 15, 255} {
						for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagZF, x86ByteFlagsAll} {
							state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward}
							state.gp[0], state.gp[bx] = uint8(mask), sourceMask
							before := state.clone()
							accepted := mask&15 == 15 && int(sourceMask)&((1<<uint(row.width))-1) == (1<<uint(row.width))-1
							if got := x86ScalarFPResultTransfer(register, &state, nil, 0, arch); got != accepted {
								t.Fatal("CRC did not read exact old-low32 and source bytes", mask, sourceMask, got, accepted)
							}
							if accepted {
								before.gp[0] = 255
							}
							if !reflect.DeepEqual(state, before) {
								t.Fatal("CRC changed unrelated bytes/status/direction", state, before)
							}
						}
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
						state.gp[0], state.gp[bx], state.pointerGP[dx] = uint8(mask), sourceMask, true
						before := state.clone()
						indexMask := uint8(255)
						if arch == "386" {
							indexMask = 15
						}
						accepted := mask&15 == 15 && sourceMask&indexMask == indexMask
						if got, known := x86LoweredCRC32NativeRead(native, &state, nil, 0, arch); !known || got != accepted {
							t.Fatal("native CRC inferred input/address knowledge", mask, sourceMask, got, known)
						}
						if accepted {
							before.gp[0] = 255
						}
						if !reflect.DeepEqual(state, before) {
							t.Fatal("native CRC changed unrelated state", state, before)
						}
					}
				}
				for _, origin := range []string{"raw", "decoded", "address", "segment", "numerical-address", "pointer-accumulator"} {
					changed := native
					state := x86ResultState{}
					state.gp[0], state.gp[bx], state.pointerGP[dx] = 255, 255, true
					switch origin {
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "decoded":
						changed.x86Encoded = true
					case "address":
						changed.x86AddressBits = 32
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "numerical-address":
						state.pointerGP[dx], state.gp[dx] = false, 255
					case "pointer-accumulator":
						state.pointerGP[0], state.gp[0] = true, 0
					}
					before := state.clone()
					if accepted, known := x86LoweredCRC32NativeRead(changed, &state, nil, 0, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("unbound CRC origin gained a conditional read", origin)
					}
				}
			})
		}
	}
}

func TestX86CRC32GrammarBanksAndOriginalIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86CRC32ResultCases(arch) {
			for _, bank := range []string{"source", "destination"} {
				for _, reg := range strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15 AL AH BL BH CL CH DL DH SPB BPB SIB DIB R8B R9B R10B R11B R12B R13B R14B R15B X0 Y0 Z0 K1 M0 FS TLS R16") {
					t.Run(arch+"/"+row.op+"/"+bank+"/"+reg, func(t *testing.T) {
						source, dest := reg, "AX"
						if bank == "destination" {
							source, dest = "BX", reg
						}
						ins := x86ScalarLaneInstruction(t, row.op+" "+source+","+dest)
						original := ins
						original.Args = append([]Operand(nil), ins.Args...)
						gp := strings.Contains(" AX CX DX BX SP BP SI DI ", " "+reg+" ") || arch == "amd64" && strings.Contains(" R8 R9 R10 R11 R12 R13 R14 R15 ", " "+reg+" ")
						valid := gp
						if bank == "source" && row.width == 1 {
							valid = gp && (arch != "386" || reg != "SP") || strings.Contains(" AL AH BL BH CL CH DL DH ", " "+reg+" ") || arch == "amd64" && strings.Contains(" BPB SIB DIB R8B R9B R10B R11B R12B R13B R14B R15B ", " "+reg+" ")
						}
						_, known, err := x86CRC32Properties(ins.Op, ins, arch)
						if !known || (err == nil) != valid || !reflect.DeepEqual(ins, original) {
							t.Fatal("CRC bank grammar or original identity changed", valid, known, err)
						}
						if _, registered, _ := x86TypedGPByteEffect(ins.Op, ins, arch); registered {
							t.Fatal("NUM grammar leaked into independent raw/caller GP directory")
						}
					})
				}
			}
		}
		for _, source := range []string{"CRC32L $1,AX", "CRC32L $0.5,AX", "CRC32L $table(SB),AX", "CRC32L (BX)(SI*3),AX", "CRC32L (BX)(SP*1),AX", "CRC32L.Z BX,AX", "CRC32L BX", "CRC32L AX,BX,CX"} {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+source+"\nRET\n")
			if err != nil {
				continue // Invalid parser syntax never reaches a typed instruction row.
			}
			ins := file.Funcs[0].Instrs[1]
			if _, known, err := x86CRC32Properties(ins.Op, ins, arch); !known || err == nil {
				t.Fatal("invalid CRC row granted an effect", arch, source)
			}
		}
	}
	for _, source := range []string{"CRC32B AH,R8", "CRC32B CH,R8"} {
		ins := x86ScalarLaneInstruction(t, source)
		ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
		before := output.String()
		if known, _, err := ctx.lowerCrc32(ins.Op, ins); !known || !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
			t.Fatal("derived physical SP/BP source acquired a binding", source, err)
		}
	}
}

func TestX86CRC32PhysicalByteNormalizationAndScanner(t *testing.T) {
	for _, row := range []struct{ source, destination, physical string }{
		{"SI", "AX", "DH"}, {"DI", "AX", "BH"}, {"BP", "AX", "CH"}, {"SP", "AX", "AH"},
		{"SI", "R8", "SI"}, {"AH", "R8", "SP"}, {"CH", "R8", "BP"}, {"SIB", "AX", "SIB"},
	} {
		ins := x86ScalarLaneInstruction(t, "CRC32B "+row.source+","+row.destination)
		form, known, err := x86CRC32Properties(ins.Op, ins, "amd64")
		if !known || err != nil || form.source.Reg != Reg(row.physical) {
			t.Fatal("typed CRC differs from independently observed original Go bytes", row, form, err)
		}
		fn := Func{Instrs: []Instr{ins}}
		ctx, _ := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Ret: Void}, nil)
		root := form.source.Reg
		if base, _, valid := amd64ByteAlias(root); valid {
			root = base
		}
		if !ctx.usedRegs[root] {
			t.Fatal("register scan omitted actual CRC source", row, root)
		}
		ins.x86Encoded = true
		raw, _, err := x86CRC32Properties(ins.Op, ins, "amd64")
		if err != nil || raw.source.Reg != ins.Args[0].Reg {
			t.Fatal("named source byte alias was lent to physical raw syntax", row, raw, err)
		}
	}
}

func TestX86CRC32UnownedMemoryAndProvenanceThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86CRC32ResultCases(target.arch) {
			for _, memory := range []string{"(SI)", "table(SB)", "-4(SP)", "ret+1(FP)"} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.op+"/"+memory+"/"+api, func(t *testing.T) {
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-4\nMOVL $0,AX\nMOVL $7,SI\n%s %s,AX\nMOVL AX,ret+0(FP)\nRET\n", row.op, memory)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("CRC shape supplied native/FP/AUTO/SB backing", err)
						}
					})
				}
			}
		}
	}
}
