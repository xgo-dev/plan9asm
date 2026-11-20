package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86SegmentRMWTestStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	if accepted, known := x86LoweredScalarMemoryRMW(ins, state, nil, arch); known {
		return accepted, known
	}
	return x86LoweredNativeBitTest(ins, state, nil, arch)
}

func TestX86ScalarRMWCompleteNativeSegmentInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var original strings.Builder
		count := 0
		for _, row := range x86LockScalarOracleForms(arch) {
			for _, segment := range []string{"FS", "GS"} {
				for _, address := range []string{"1(@)", "1(AX)(@*1)", "1(AX)(@*2)", "1(AX)(@*4)", "1(AX)(@*8)"} {
					text := strings.Replace(row.text, "1(SI)", strings.ReplaceAll(address, "@", segment), 1)
					fmt.Fprintf(&original, "TEXT ·segment%d(SB),4,$0-0\nLOCK\n%s\nRET\n", count, text)
					count++
					t.Run(arch+"/"+text, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, text)
						before := ins
						before.Args = append([]Operand(nil), ins.Args...)
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.gp[0], state.gp[1] = 0xff, 0xff
						state.pointerGP[2], state.callerAddressGP[2] = true, true
						want := state.clone()
						stem := row.op[:len(row.op)-1]
						if stem == "AND" || stem == "OR" || stem == "XOR" {
							want.flags &^= x86ByteFlagAF
						} else if strings.HasPrefix(stem, "BT") {
							want.flags = x86ByteFlagCF | x86ByteFlagZF
						}
						accepted, known := x86SegmentRMWTestStep(ins, &state, arch)
						if !known || !accepted || !reflect.DeepEqual(state, want) || !reflect.DeepEqual(ins, before) {
							t.Fatal("typed segment operation lost inputs or changed unrelated source/state", known, accepted)
						}
					})
				}
			}
		}
		want := 660
		if arch == "amd64" {
			want = 900
		}
		if count != want {
			t.Fatal("incomplete independent scalar/bit-string segment family", count)
		}
		t.Run(arch+"/complete-original-Go", func(t *testing.T) {
			goAssemblerOracleOutput(t, arch, original.String(), "", true)
		})
	}
}

func TestX86ScalarRMWSegmentCannotInventNumericalAddress(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ADCL", "BTCL"} {
			for _, mutation := range []string{"unknown-base", "pointer-base", "unknown-data", "raw", "address-override", "physical-SP", "symbol", "unknown-offset"} {
				t.Run(arch+"/"+op+"/"+mutation, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, op+" CX,1(AX)(FS*4)")
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.gp[0], state.gp[1] = 0xff, 0xff
					switch mutation {
					case "unknown-base":
						state.gp[0] = 0
					case "pointer-base":
						state.gp[0], state.pointerGP[0] = 0, true
					case "unknown-data":
						state.gp[1] = 0
					case "raw":
						ins.x86Encoded = true
					case "address-override":
						ins.x86AddressBits = 16
					case "physical-SP":
						ins.Args[1].Mem.Base = SP
					case "symbol":
						ins.Args[1].Mem.Sym = "external(SB)"
					case "unknown-offset":
						ins.Args[1].Mem.OffRaw = "missing"
					}
					before := state.clone()
					if accepted, _ := x86SegmentRMWTestStep(ins, &state, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("segment continuation manufactured inputs or changed rejected state")
					}
				})
			}
		}
	}
}
