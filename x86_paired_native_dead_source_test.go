package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86PairedNativeDeadInputsNeedActualSourceClosure(t *testing.T) {
	rows := []struct{ name, instruction string }{
		{"ternary", "VPTERNLOGD.Z $0,(AX),X1,K7,X2"},
		{"integer-minmax", "VPMAXSD.Z (AX),X1,K7,X2"},
		{"horizontal-reduction", "VHADDPS (AX),X1,X2"},
		{"broadcast", "VPBROADCASTD.Z (AX),K7,X2"},
	}
	// A real mask value of zero still needs a source-bound address role.
	// The complete positive controls also retain an initialized pointer before
	// the jump, so a repair cannot simply reject branches or unreachable code.
	prefix := "MOVQ p+0(FP),AX\nMOVL $0,CX\nKMOVD CX,K7\n" +
		"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
	for _, row := range rows {
		for _, dead := range []bool{false, true} {
			body := row.instruction + "\nRET\n"
			if dead {
				body = "JMP finish\n" + row.instruction + "\nfinish:\nRET\n"
			}
			control := "TEXT ·Value(SB),4,$0-8\n" + prefix + body
			changed := strings.Replace(control, "MOVQ p+0(FP),AX", "MOVQ $0,AX", 1)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/dead=%t/%s", row.name, dead, api), func(t *testing.T) {
					if _, err := x86ScalarFPBitViewAPI(t, control, "func Value(p *byte)", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Fatal("genuine pointer/mask positive control failed before dead-source comparison", err)
					}
					if ir, err := x86ScalarFPBitViewAPI(t, changed, "func Value(p *byte)", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("shape-only all-known GP values supplied an unreachable native pointer", err)
					}
				})
			}
		}
	}
}

func TestX86DeadExternalSourceKeepsLoopsJoinsAndFutureStateSeparate(t *testing.T) {
	prefix := "MOVQ p+0(FP),AX\nMOVL $0,CX\nKMOVD CX,K7\nTESTL CX,CX\n"
	read := "VPTERNLOGD.Z $0,(AX),X1,K7,X2\n"
	rows := []struct {
		name, prefix, body string
		accept             bool
	}{
		{"initialized-loop", prefix, "JMP finish\ndead:\n" + read + "JMP dead\nfinish:\nRET\n", true},
		{"unknown-loop-address", strings.Replace(prefix, "MOVQ p+0(FP),AX", "MOVQ $0,AX", 1), "JMP finish\ndead:\n" + read + "JMP dead\nfinish:\nRET\n", false},
		{"separate-components", prefix, "JMP middle\n" + read + "middle:\nJMP finish\n" + read + "finish:\nRET\n", true},
		{"join-loses-pointer", prefix, "JMP finish\nJE keep\nMOVQ $0,AX\nJMP joined\nkeep:\nNOP\njoined:\n" + read + "finish:\nRET\n", false},
		{"join-retains-pointer", prefix, "JMP finish\nJE keep\nMOVQ p+0(FP),AX\nJMP joined\nkeep:\nMOVQ p+0(FP),AX\njoined:\n" + read + "finish:\nRET\n", true},
		{"future-pointer-is-not-entry", strings.Replace(prefix, "MOVQ p+0(FP),AX\n", "", 1), "JMP finish\n" + read + "finish:\nMOVQ p+0(FP),AX\nRET\n", false},
		{"future-mask-is-not-entry", strings.Replace(prefix, "KMOVD CX,K7\n", "", 1), "JMP finish\n" + read + "finish:\nKMOVD CX,K7\nRET\n", false},
		{"pure-dead-registers-stay-unknown", "", "JMP finish\nVPTERNLOGD $150,X0,X1,X2\nfinish:\nRET\n", true},
		{"unrelated-dead-register-component", prefix, "JMP middle\nADDQ $1,DX\nmiddle:\nJMP finish\n" + read + "finish:\nRET\n", true},
	}
	for _, row := range rows {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-8\n" + row.prefix + row.body
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte)", "amd64", "x86_64-unknown-linux-gnu", api)
				if row.accept {
					if err != nil || ir == "" {
						t.Fatal("source-bound dead proof lost its existing register domain", err)
					}
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("dead source borrowed a future or one-path external input", err)
				}
			})
		}
	}
}

func TestX86DeadExternalSourceBudgetIsSharedAcrossComponents(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+
		"JMP first\nVPTERNLOGD.Z $0,(AX),X1,K7,X2\nfirst:\n"+
		"JMP finish\nVPTERNLOGD.Z $0,(AX),X1,K7,X2\nfinish:\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	var instructions []Instr
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op != OpTEXT && ins.Op != OpLABEL {
			instructions = append(instructions, ins)
		}
	}
	if len(instructions) != 5 {
		t.Fatal("independent two-component fixture changed", len(instructions))
	}
	initial := x86ResultState{}
	ax, _, _ := x86ResultGP("AX", 8, "amd64")
	initial.pointerGP[ax], initial.masks[7] = true, true
	for _, row := range []struct {
		name         string
		visits, work int
		accept       bool
	}{
		{"closed", 0, 0, true},
		{"combined-visits", 16381, 0, false},
		{"combined-bytes", 0, (64 << 20) - 320 - 24, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			reached := map[int]x86ResultState{0: initial.clone(), 2: initial.clone(), 4: initial.clone()}
			before := map[int]x86ResultState{0: initial.clone(), 2: initial.clone(), 4: initial.clone()}
			transfer := func(_ int, ins Instr, state *x86ResultState, _ []bool, _ int64, arch string) bool {
				if state.shapeOnly {
					t.Fatal("dead closure used a fabricated all-known shape state")
				}
				if ins.Op == OpJMP {
					return true
				}
				accepted, known := x86ResultTernaryLogicContinuationStep(ins, state, nil, arch, true)
				return accepted && known
			}
			visits, work := row.visits, row.work
			// A unit byte envelope isolates the accounting rule; it is not a
			// claim about actual state size, which the caller independently owns.
			err := x86ResultCheckDeadExternalInputs(Func{}, instructions, []int{0, 1, 2, 3, 4},
				[][]int{{2}, {2}, {4}, {4}, nil}, reached, nil, 0, "amd64", transfer, &visits, &work, 1)
			if row.accept {
				if err != nil || visits != 4 || work != 352 {
					t.Fatal("two components did not share one bounded proof", visits, work, err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("per-component reset bypassed the combined function budget", err)
			}
			if !reflect.DeepEqual(before, reached) {
				t.Fatal("dead source facts flowed back into the actual reachable CFG")
			}
		})
	}
}

func TestX86DeadExternalDetectorUsesTypedAccessesNotAddressSyntax(t *testing.T) {
	for _, width := range []string{"W", "L", "Q"} {
		for _, address := range []string{"7(AX)", "7(AX)(CX*8)"} {
			body := "LEA" + width + " " + address + ",BX"
			t.Run(body, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, body)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				if !known || err != nil {
					t.Fatal("independent typed address-computation control is missing", known, err)
				}
				for _, operand := range effect.operands {
					if operand.operand.Kind == OpMem {
						t.Fatal("pure address computation acquired a real memory byte effect")
					}
				}
				if x86ResultDeadExternalInputs(ins, "amd64") {
					t.Fatal("address syntax was mistaken for an external memory access")
				}
			})
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(width+"/"+api, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-0\nJMP finish\nLEA" + width + " (AX),BX\nfinish:\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir == "" || err != nil {
					t.Fatal("unreachable pure address result lost its existing unknown-register domain", err)
				}
			})
		}
	}
}

func TestX86DeadExternalSourceRetainsOrdinaryUnknownScratch(t *testing.T) {
	// The existing lowering fallback, not a dead-source-specific exemption,
	// owns this operation. Its unknown low bytes must remain unavailable.
	state := x86ResultState{flags: x86ByteFlagsAll}
	ax, _, _ := x86ResultGP("AX", 8, "amd64")
	cx, _, _ := x86ResultGP("CX", 8, "amd64")
	state.pointerGP[ax] = true
	if !x86LoweredPureGPUnknownTransfer(x86PureGPUnknownInstruction(t, "ADDL $1,CX"), &state, "amd64") ||
		state.gp[cx] != 0xf0 || !state.pointerGP[ax] || state.flags != 0 {
		t.Fatal("existing nontrapping scratch domain changed or invented unknown low bytes", state)
	}
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"unused-scratch", "VPTERNLOGD $0,(AX),Z1,Z2", true},
		{"scratch-is-address-index", "VPTERNLOGD $0,(AX)(CX*1),Z1,Z2", false},
		{"scratch-is-mask", "KMOVD CX,K7\nVPTERNLOGD.Z $0,(AX),Z1,K7,Z2", false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-8\nMOVQ p+0(FP),AX\nJMP finish\n" +
					"ADDL $1,CX\n" + row.body + "\nfinish:\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte)", "amd64", "x86_64-unknown-linux-gnu", api)
				if row.accept {
					if err != nil || ir == "" {
						t.Fatal("unrelated dead scratch operation lost its old unknown-value domain", err)
					}
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unknown scratch bytes became an external address or mask input", err)
				}
			})
		}
	}
}

func TestX86TernaryDeadNamedRawMasksAndAddressesRemainObligations(t *testing.T) {
	for _, row := range x86TernaryCompleteOracleRows() {
		if !row.memory && row.mask < 0 {
			continue // A dead unmasked bitwise result may legitimately stay unknown.
		}
		for _, spelling := range []string{"named", "raw"} {
			instruction := strings.Replace(row.row, "$150", "$0", 1)
			if spelling == "raw" {
				code := x86TernaryIndependentFixtureBytes(row)
				code[len(code)-1] = 0
				instruction = x86RawDisplacementDirectives(code)
			}
			instruction = "JMP finish\n" + instruction + "\nfinish:"
			source, declaration := x86TernaryInitializedFixture("Value", "amd64", instruction)
			// Establish a real zero mask, not an assumed value in the source
			// shape state. The unknown base or K role remains independently
			// required even when no result or active lane consumes the read.
			source = strings.Replace(source, "MOVL $85,DX", "MOVL $0,DX", 1)
			changed := source
			if row.memory {
				changed = strings.Replace(changed, "MOVQ p+0(FP),AX", "MOVQ $0,AX", 1)
			} else {
				changed = strings.Replace(changed, "KMOVD DX,K7\n", "", 1)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(spelling+"/"+row.row+"/"+api, func(t *testing.T) {
					if _, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Fatal("complete initialized dead-source control lost a legitimate typed role", err)
					}
					if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("constant selector, zero mask or dead CFG hid an unbound native input", err)
					}
				})
			}
		}
	}
}
