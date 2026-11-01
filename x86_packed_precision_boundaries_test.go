package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86PackedPrecisionMaskMergeBytesAndSourceAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86PackedPrecisionOracleRows() {
			if row.source != "register" || row.mode == "" {
				continue
			}
			for _, missing := range []string{"none", "mask", "active-old", "zeroed-tail"} {
				t.Run(arch+"/"+row.instruction()+"/"+missing, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.instruction())
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.writeVector(0, 64, ^uint64(0), true)
					state.writeVector(1, 64, ^uint64(0), true)
					state.masks[1], state.pointerGP[3], state.callerAddressGP[7] = true, true, true
					switch missing {
					case "mask":
						state.masks[1] = false
					case "active-old":
						state.writeVector(1, 64, ^uint64(1), true)
					case "zeroed-tail":
						state.writeVector(1, 64, x86CallerVectorByteMask(int64(row.output)), true)
					}
					before, want := state.clone(), state.clone()
					valid := missing != "mask" && (missing != "active-old" || row.mode == "zero")
					if valid {
						want.writeVector(1, row.carrier, x86CallerVectorByteMask(int64(row.carrier)), false)
					}
					if accepted := x86ResultTransfer(ins, &state, nil, 0, arch); accepted != valid || !reflect.DeepEqual(state, want) {
						t.Fatal("mask/merge obligation, forced tail zero or unrelated FLAGS/DF/storage changed", missing, accepted, valid, before, state)
					}
				})
			}
		}
	}
}

func TestX86PackedPrecisionInitializedPublicInputsCannotBorrowOtherRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := int(goWordSize(arch)), "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, base := range x86PackedPrecisionBaseRows() {
			for _, kind := range []string{"register", "native", "FP"} {
				row := base
				row.source = kind
				source, declaration, _ := x86PackedPrecisionProgram(row, 0, arch)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%d/%s/%s", arch, row.op, row.carrier, kind, api), func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil || ir == "" {
							t.Fatal("legitimate complete source failed before its independent authority negatives", err)
						}
						mutations := map[string]string{
							"output pointer": strings.Replace(source, move+" out+64(FP),DI\n", "", 1),
						}
						if kind == "register" {
							mutations["source vector"] = strings.Replace(source, "VMOVDQU64 (BX),Z0\n", "", 1)
						} else if kind == "native" {
							mutations["native address"] = strings.Replace(source, fmt.Sprintf("%s input+%d(FP),BX\n", move, 64+word), "", 1)
						} else {
							mutations["pointer bits"] = strings.Replace(source, "value+0(FP)", "out+64(FP)", 1)
							mutations["undeclared bytes"] = strings.Replace(source, "value+0(FP)", "value+128(FP)", 1)
						}
						for name, changed := range mutations {
							if changed == source {
								t.Fatal("source/input mutation did not apply", name)
							}
							if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("packed precision borrowed undeclared/native/pointer authority", name, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86PackedPrecisionDeadNativeReadsRetainExactE2Opcode(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range x86PackedPrecisionOracleRows() {
			if row.source != "native" {
				continue
			}
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				declaration := "func view(p *byte)\n"
				prepare := ""
				if row.mode != "" {
					prepare = "MOVL $0,AX\nKMOVD AX,K1\n"
				}
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s p+0(FP),BX\n%s%s\nRET\n", goWordSize(arch), move, prepare, row.instruction())
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete dead E2 native source lost its paired continuation", err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86ScalarPrecisionRequireNativeEffects(t, text, map[string][]string{"view": {x86PackedPrecisionNativeName(row.op)}})
							memory := fmt.Sprintf("elementtype([%d x i8])", row.sourceBytes())
							found := false
							for _, line := range strings.Split(text, "\n") {
								found = found || x86ScalarPrecisionNativeEffectLine(line, x86PackedPrecisionNativeName(row.op)) && strings.Contains(line, memory)
							}
							if !found {
								t.Fatal("actual E2 opcode lost its complete independent memory tuple", row.sourceBytes())
							}
						}
						missing := strings.Replace(source, move+" p+0(FP),BX\n", "", 1)
						if ir, err := x86ScalarFPBitViewAPI(t, missing, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void or an all-zero mask waived the real address input", err)
						}
						if row.mode != "" {
							missingMask := strings.Replace(source, "KMOVD AX,K1\n", "", 1)
							if ir, err := x86ScalarFPBitViewAPI(t, missingMask, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("a dead conversion waived its actual mask source", err)
							}
						}
					})
				}
			})
		}
	}
}

func TestX86PackedPrecisionForeignTargetCannotClaimNativeMXCSR(t *testing.T) {
	for _, row := range x86PackedPrecisionBaseRows() {
		row.source = "register"
		source, declaration, _ := x86PackedPrecisionProgram(row, 0, "amd64")
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("%s/%d/%s", row.op, row.carrier, api), func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir == "" || err != nil {
					t.Fatal("native initialized control failed before cross-target qualification", err)
				}
				for _, triple := range []string{"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("pure fpext/fptrunc incorrectly certified original x86 MXCSR/exception effects", triple, err)
					}
				}
			})
		}
	}
}

func TestX86PackedPrecisionStandaloneRawAndPhysicalBanksStayIndependent(t *testing.T) {
	for _, row := range x86PackedPrecisionBaseRows() {
		row.source = "register"
		for _, mutation := range []string{"encoded", "origin", "address-size", "segment", "physical-mode32"} {
			t.Run(row.instruction()+"/"+mutation, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				arch := "amd64"
				switch mutation {
				case "encoded":
					ins.x86Encoded = true
				case "origin":
					ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: append([]Operand(nil), ins.Args...)}
				case "address-size":
					ins.x86AddressBits = 32
				case "segment":
					ins.x86SegmentPrefix = 0x64
				case "physical-mode32":
					arch = "386"
					ins.Args[len(ins.Args)-1].Reg = Reg(string(ins.Args[len(ins.Args)-1].Reg[:1]) + "16")
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.writeVector(0, 64, ^uint64(0), true)
				state.writeVector(1, 64, ^uint64(0), true)
				state.writeVector(16, 64, ^uint64(0), true)
				before := state.clone()
				if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone numerical query borrowed raw/physical permission", mutation)
				}
			})
		}
	}
}
