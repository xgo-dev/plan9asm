package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Unknown nontrapping scratch results may remain dead. An ABI result or native
// store cannot turn those unknown bits into implementation-initialized zeroes.
func TestX86MULXObservableResultsRequireActualInputsThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := goWordSize(arch), "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		for _, op := range x86MULXTestOps(arch) {
			instruction := op + " AX,CX,BX"
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, instruction+"\nRET\n")
			if len(pcs) != 2 || pcs[1] != int64(len(code)-1) {
				t.Fatal("original complete MULX instruction boundary changed", pcs, code)
			}
			physical := x86RawDisplacementDirectives(code[:pcs[1]])
			for _, raw := range []bool{false, true} {
				for _, use := range []string{"two-FP-results", "Void-native-store", "dead-constant-FP-result"} {
					for _, input := range []string{"complete", "missing-DX", "missing-source", "partial-DX", "opaque-DX"} {
						t.Run(fmt.Sprintf("%s/%s/raw=%t/%s/%s", arch, op, raw, use, input), func(t *testing.T) {
							declaration := "func Value(out *[16]byte,p *[8]byte) (low,high uintptr)"
							frame := word * 4
							suffix := fmt.Sprintf("%s CX,low+%d(FP)\n%s BX,high+%d(FP)\nRET\n", move, word*2, move, word*3)
							prefix := ""
							if use == "Void-native-store" {
								declaration, frame = "func Value(out *[16]byte,p *[8]byte)", word*2
								prefix = fmt.Sprintf("%s out+0(FP),DI\n", move)
								suffix = fmt.Sprintf("%s CX,0(DI)\n%s BX,%d(DI)\nRET\n", move, move, word)
							} else if use == "dead-constant-FP-result" {
								declaration, frame = "func Value(out *[16]byte,p *[8]byte) (result uintptr)", word*3
								suffix = fmt.Sprintf("%s $23,result+%d(FP)\nRET\n", move, word*2)
							}
							if input != "missing-source" {
								prefix += "MOVL $7,AX\n"
							}
							switch input {
							case "complete", "missing-source":
								prefix += "MOVL $3,DX\n" // r32 zero-extension also defines the qword input.
							case "partial-DX":
								prefix += "MOVW $3,DX\n"
							case "opaque-DX":
								prefix += fmt.Sprintf("%s p+%d(FP),DX\n", move, word)
							}
							body := instruction + "\n"
							if raw {
								body = physical
							}
							source := fmt.Sprintf("TEXT Value(SB),4,$0-%d\n", frame) + prefix + body + suffix
							triple := x86AddressMemoryTargets(arch)[0]
							x86LEAActualTargetGoObject(t, arch, triple, source)
							pass := input == "complete" || use == "dead-constant-FP-result" && !raw && input != "opaque-DX"
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
								if pass {
									if err != nil || ir == "" {
										t.Fatal("complete inputs or genuinely dead unknown results lost their source contract", api, err)
									}
									if use == "dead-constant-FP-result" {
										x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{23})
									}
								} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("observable MULX result borrowed source or implicit DX bytes", api, err)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestX86MULXUnknownScratchTransferKeepsBothOutputsUnknown(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			t.Run(arch+"/"+op, func(t *testing.T) {
				ins := x86YMMReadSource(t, op+" AX,CX,BX")
				before := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				before.gp[0], before.gp[1], before.gp[3] = 0xff, 0xff, 0xff
				before.canonicalGP[1], before.canonicalGP[3] = 0xff, 0xff
				before.pointerGP[1], before.pointerGP[3] = true, true // Old destinations are never inputs.
				state := before.clone()
				if accepted, known := x86LoweredMULXResultStep(ins, &state, nil, 0, arch); !accepted || !known {
					t.Fatal("closed nontrapping scratch operation was rejected")
				}
				want := uint8(0xf0)
				if strings.HasSuffix(op, "Q") {
					want = 0
				}
				if state.gp[1] != want || state.gp[3] != want || state.canonicalGP[1] != want || state.canonicalGP[3] != want ||
					state.pointerGP[1] || state.pointerGP[3] ||
					state.flags != before.flags || state.direction != before.direction {
					t.Fatal("unknown product gained numerical outputs or changed FLAGS/DF", state)
				}
				opaque := before.clone()
				opaque.pointerGP[2] = true
				original := opaque.clone()
				if accepted, _ := x86LoweredMULXResultStep(ins, &opaque, nil, 0, arch); accepted || !reflect.DeepEqual(opaque, original) {
					t.Fatal("unknown-result fallback consumed an opaque pointer or mutated a rejected state")
				}
				if !x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, arch) {
					t.Fatal("Void or missing result declarations bypassed whole-source unknown/result propagation")
				}
			})
		}
	}
}

func TestX86MULXObservableBoolCannotBorrowOldCanonicalOutputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			for _, scenario := range []string{"bounded", "unbounded", "missing-DX-bounded"} {
				t.Run(arch+"/"+op+"/"+scenario, func(t *testing.T) {
					declaration := "func Value() (bool,uint32)"
					_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
					var boolean, number int64
					for _, slot := range sig.Frame.Results {
						if slot.Type == I1 {
							boolean = slot.Offset
						} else {
							number = slot.Offset
						}
					}
					// Both old outputs are canonical before being overwritten. A
					// known product is numerical, not necessarily zero or one.
					body := "MOVL $7,AX\nMOVL $1,CX\nMOVL $1,BX\n"
					if scenario != "missing-DX-bounded" {
						body += "MOVL $3,DX\n"
					}
					body += op + " AX,CX,BX\n"
					if scenario != "unbounded" {
						body += "ANDL $1,CX\n"
					}
					body += fmt.Sprintf("MOVL $23,AX\nMOVL AX,ret+%d(FP)\nMOVB CX,ret+%d(FP)\nRET\n", number, boolean)
					_, _, _, source := x86ResultInitializationFixture(t, arch, declaration, body)
					triple := x86AddressMemoryTargets(arch)[0]
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if scenario == "bounded" {
							if err != nil || ir == "" {
								t.Fatal("complete newly bounded bool/number result rejected", api, err)
							}
							x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{1, 23})
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("MULX result borrowed old canonicality or implementation NUM bytes", api, err)
						}
					}
				})
			}
		}
	}
}
