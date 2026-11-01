package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86HardwareRandomRawIdentityAndStorageBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RandomResultOracle {
			if arch == "386" && row.width == 8 {
				continue
			}
			source := "TEXT random(SB),4,$0-0\n" +
				x86RawDisplacementDirectives(x86RandomOracleBytes(row.width, row.extension, 3)) + "RET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn, err := decodeX86RawDirectives(file.Funcs[0], arch)
			if err != nil || len(fn.Instrs) != 3 || fn.Instrs[1].x86SourceRaw == nil {
				t.Fatal("missing complete decoder source", err)
			}
			original := fn.Instrs[1]
			for _, mutation := range []string{"unchanged", "operand", "origin-opcode", "origin-operand",
				"encoded", "address-size", "segment", "unbound-address", "raw-return", "constructed-operand"} {
				t.Run(arch+"/"+row.op+"/"+mutation, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					origin := *original.x86SourceRaw
					ins.x86SourceRaw = &origin
					switch mutation {
					case "operand":
						ins.Args[0].Reg = AX
					case "origin-opcode":
						origin.op = "NOP"
					case "origin-operand":
						origin.args = []Operand{{Kind: OpReg, Reg: AX}}
					case "encoded":
						ins.x86Encoded = true
					case "address-size":
						ins.x86AddressBits = 32
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "unbound-address":
						ins.x86UnboundAddressOverride = true
					case "raw-return":
						ins.x86RawNearReturn = new(x86RawNearReturnForm)
					case "constructed-operand":
						ins.Args[0].ImmRaw = "$unknown"
					}
					valid := mutation == "unchanged"
					state := x86ResultState{direction: x86ResultDirectionBackward,
						valueStack: &x86ResultValueStack{bytes: []uint8{1, 2, 3, 4}, id: true}}
					state.callerAddressGP[3], state.callerAddressGP[7] = true, true
					if x86RegisterQueryPreservesSourceState(ins) != valid {
						t.Fatal("random acquired a mismatched storage identity")
					}
					if valid {
						addresses := state.callerAddressGP
						addresses[3] = false
						if !x86ResultValueStackContinuation(ins, &state, arch) ||
							x86ResultDirectionAfter(ins, state.direction) != state.direction ||
							x86ResultCallerAddressesAfter(ins, state.callerAddressGP, nil, arch) != addresses {
							t.Fatal("random lost private storage/DF or its exact GP overwrite footprint")
						}
					}
					before := state.clone()
					if x86ResultTransfer(ins, &state, nil, 0, arch) != valid || !valid && !reflect.DeepEqual(state, before) {
						t.Fatal("mismatched random acquired numerical outputs or partially updated state")
					}
				})
			}
		}
	}
}

func TestX86HardwareRandomOriginalStatusWriterSource(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86RandomResultOracle {
			if target.arch == "386" && row.width == 8 {
				continue
			}
			t.Run(target.triple+"/"+row.op, func(t *testing.T) {
				// This is exactly the discovering fixture, not a replacement seed.
				source := x86DefinedZeroAFSource(target.arch, "status", row.op+" BX")
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func status()", target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "store i1 false, ptr %flags_af") != 2 {
						t.Fatal("original initialized status source still fails", api, err)
					}
				}
			})
		}
	}
}

func TestX86HardwareRandomLivePrivateStackAndCanonicalResult(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word := "L"
		if target.arch == "amd64" {
			word = "Q"
		}
		for _, row := range x86RandomResultOracle {
			if target.arch == "386" && row.width == 8 {
				continue
			}
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/raw=%t", target.triple, row.op, raw), func(t *testing.T) {
					body := row.op + " AX\n"
					if raw {
						body = x86RawDisplacementDirectives(x86RandomOracleBytes(row.width, row.extension, 0))
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-1\nMOVL $1,AX\nPUSH%s AX\n%sPOP%s BX\nMOVB BX,ret+0(FP)\nRET\n", word, body, word)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						// A preserved numerical private stack is not a canonical bool
						// transport. Use its numerical byte, then independently reject
						// a random value that overwrote a previous canonical constant.
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint8", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("random lost a live independent private stack", api, err)
						}
						bad := fmt.Sprintf("TEXT ·Value(SB),4,$0-1\nMOVL $1,AX\n%sMOVB AX,ret+0(FP)\nRET\n", body)
						ir, err = x86ScalarFPBitViewAPI(t, bad, "func Value() bool", target.arch, target.triple, api)
						if err == nil || ir != "" {
							t.Fatal("random result retained an overwritten canonical bool", api, err)
						}
					}
				})
			}
		}
	}
}
