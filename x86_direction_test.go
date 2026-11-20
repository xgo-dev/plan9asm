package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func TestX86DirectionControlBackendSeparation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, triple := range []string{
			"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu",
			"aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "wasm32-unknown-unknown", "",
		} {
			for _, direction := range []string{"CLD", "STD"} {
				t.Run(arch+"/"+triple+"/"+direction, func(t *testing.T) {
					var output strings.Builder
					context := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, arch, triple, false)
					context.directionSlot = "%direction"
					if known, err := context.lowerDirectionControl(x86ScalarLaneInstruction(t, direction)); !known || err != nil {
						t.Fatal("valid direction control rejected", err)
					}
					want := fmt.Sprintf("  store i1 %t, ptr %%direction\n", direction == "STD")
					// Independent exact mode/backend directory, not the production
					// target predicate. No status-FLAGS store is part of this effect.
					native := arch == "386" && triple == "i386-unknown-linux-gnu" ||
						arch == "amd64" && triple == "x86_64-unknown-linux-gnu"
					if native {
						want += fmt.Sprintf("  call void asm sideeffect %q, \"~{dirflag}\"()\n", strings.ToLower(direction))
					}
					if output.String() != want {
						t.Fatalf("virtual/native DF boundary changed: got=%q want=%q", output.String(), want)
					}
				})
			}
		}
	}
}

func TestX86DirectionControlNumericalAndCallerThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, typ := 8, "MOVQ", "uint64"
		if arch == "386" {
			word, move, typ = 4, "MOVL", "uint32"
		}
		for _, direction := range []string{"CLD", "STD"} {
			for _, role := range []string{"numeric", "caller-origin"} {
				t.Run(arch+"/"+direction+"/"+role, func(t *testing.T) {
					declaration := "func view(x, prior " + typ + ") " + typ + "\n"
					body := fmt.Sprintf("%s x+0(FP),AX\n%s prior+%d(FP),BX\n%s\nBSFL AX,BX\n%s BX,ret+RESULT(FP)", move, move, word, direction, move)
					if role == "caller-origin" {
						declaration = "func view(p *byte) " + typ + "\n"
						body = fmt.Sprintf("%s p+0(FP),SI\n%s SI,DI\n%s\nSUB%s SI,DI\n%s DI,ret+RESULT(FP)", move, move, direction, strings.TrimPrefix(move, "MOV"), move)
					}
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, true)
				})
			}
		}
	}
}

func TestX86DirectionControlCompleteGoGrammarAndRawSeparation(t *testing.T) {
	for _, arch := range []string{"amd64", "386", "arm64"} {
		for _, op := range []string{"CLD", "STD"} {
			for _, tail := range []string{"", " AX", " $1", " (AX)", ".Z"} {
				t.Run(arch+"/"+op+strings.ReplaceAll(tail, " ", "_"), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, op+tail)
					_, known, err := x86DirectionControlProperties(ins.Op, ins, arch)
					valid := arch != "arm64" && tail == ""
					if !known || (err == nil) != valid {
						t.Fatal("direction-control accepted a form outside its complete ynone rows", known, err)
					}
					state := x86ResultState{}
					accepted, recognized := x86ResultDirectionStep(ins, &state, arch)
					if !recognized || accepted != valid || !valid && state.direction != x86ResultDirectionUnknown {
						t.Fatal("grammar failure created direction knowledge", accepted, recognized, state.direction)
					}
				})
			}
		}
	}
	for _, mutate := range []struct {
		name  string
		apply func(*Instr)
	}{
		{"encoded", func(ins *Instr) { ins.x86Encoded = true }},
		{"source-raw", func(ins *Instr) { ins.x86SourceRaw = &x86SourceRawInstruction{} }},
		{"address-size", func(ins *Instr) { ins.x86AddressBits = 32 }},
		{"unbound-address", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
		{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 1 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, "CLD")
			mutate.apply(&ins)
			state := x86ResultState{}
			if accepted, known := x86ResultDirectionStep(ins, &state, "amd64"); accepted || !known || state.direction != x86ResultDirectionUnknown {
				t.Fatal("named DF rule lent a raw/native source role")
			}
		})
	}
}

func TestX86DirectionStateCloneJoinPreservationAndRevocation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"CLD", "STD"} {
			for flags := 0; flags <= int(x86ByteFlagsAll); flags++ {
				state := x86ResultState{flags: uint8(flags), fp: []bool{true}, canonicalFP: []bool{true}, auto: []bool{true}}
				state.gp[0], state.canonicalGP[0], state.xmm[0] = 0x51, 1, 0x1234
				state.pointerGP[6], state.callerAddressGP[6], state.callerAddressOrigin[6] = true, true, 1
				state.resultAddressGP[7] = x86ResultSlotAddress{start: 8, end: 16, offset: 8, valid: true}
				before := state.clone()
				ins := x86ScalarLaneInstruction(t, op)
				if accepted, known := x86ResultDirectionStep(ins, &state, arch); !accepted || !known {
					t.Fatal("complete direction setter rejected")
				}
				want := x86ResultDirectionForward
				if op == "STD" {
					want = x86ResultDirectionBackward
				}
				if state.direction != want {
					t.Fatal("direction value lost", state.direction)
				}
				state.direction = before.direction
				if !reflect.DeepEqual(before, state) || x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch) != before.callerAddressGP {
					t.Fatal("DF control changed independent numerical/canonical/status/address knowledge")
				}
			}
		}
	}
	for _, first := range []x86ResultDirection{0, 1, 2, 3} {
		for _, second := range []x86ResultDirection{0, 1, 2, 3} {
			want := first | second
			if first == 0 || second == 0 {
				want = 0
			}
			state := x86ResultState{direction: first}
			clone := state.clone()
			clone.direction = second
			if state.direction != first || state.intersect(clone).direction != want {
				t.Fatal("DF join invented a known direction or shared mutable state", first, second)
			}
		}
	}
	for _, op := range []Op{OpCALL, "POPFW", "POPFL", "POPFQ", "IRETW", "IRETL", "IRETQ"} {
		if got := x86ResultDirectionAfter(Instr{Op: op}, x86ResultDirectionEither); got != x86ResultDirectionUnknown {
			t.Fatal("callee/FLAGS restoration retained an unobserved direction", op, got)
		}
	}
	if x86ResultDirectionAfter(Instr{Op: "NOP", x86Encoded: true}, x86ResultDirectionForward) != x86ResultDirectionUnknown ||
		x86ResultDirectionAfter(Instr{Op: "MOVL"}, x86ResultDirectionBackward) != x86ResultDirectionBackward {
		t.Fatal("DF revocation was merged with ordinary NUM effects")
	}
}

func TestX86DirectionWholeSourceCFGJoinsAndFinalEffectRevocation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			name, first, second, last string
			want                      x86ResultDirection
		}{
			{"both-forward", "CLD", "CLD", "", x86ResultDirectionForward},
			{"mixed-defined", "CLD", "STD", "", x86ResultDirectionEither},
			{"missing-one-edge", "CLD", "NOP", "", x86ResultDirectionUnknown},
			{"missing-both", "NOP", "NOP", "", x86ResultDirectionUnknown},
			{"overwrite-join", "CLD", "STD", "CLD\n", x86ResultDirectionForward},
			{"accepted-call", "CLD", "STD", "CALL callee(SB)\n", x86ResultDirectionUnknown},
			{"accepted-flags-restore", "CLD", "STD", "POPFW\n", x86ResultDirectionUnknown},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				source := fmt.Sprintf("TEXT entry(SB),4,$0-0\nMOVL $1,AX\nCMPL AX,$0\nJZ right\n%s\nJMP joined\nright:\n%s\njoined:\n%sRET\n", row.first, row.second, row.last)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				checked := false
				err = checkX86ResultSourceFlow(file.Funcs[0], x86ResultState{}, nil, 0, arch,
					func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
						// Isolate the shared post-effect hook: an independent private
						// observer accepting CALL/POPF may not retain DF. This test
						// transfer is not installed in any production/public role.
						if ins.Op == OpCALL || ins.Op == "POPFW" {
							return true
						}
						return x86ResultTransfer(ins, state, owned, offset, arch)
					}, func(state x86ResultState, _ int) error {
						checked = true
						if state.direction != row.want {
							return fmt.Errorf("joined DF=%d, want %d", state.direction, row.want)
						}
						return nil
					})
				if err != nil || !checked {
					t.Fatal("complete source DF fact or final revocation lost", err)
				}
			})
		}
	}
}

func TestX86DirectionMalformedDeadSourceCannotBorrowNumericalProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, malformed := range []string{"CLD AX", "STD $1", "CLD.Z", "STD (AX)"} {
			t.Run(arch+"/"+strings.ReplaceAll(malformed, " ", "_"), func(t *testing.T) {
				declaration := "func view(x,prior uint32) uint32\n"
				body := "JMP good\n" + malformed + "\ngood:\nMOVL x+0(FP),AX\nMOVL prior+4(FP),BX\nBSFL AX,BX\nMOVL BX,ret+RESULT(FP)"
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, false)
			})
		}
	}
}

func TestX86DirectionLoweredStringCompleteFamilyConsumesDirection(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, kind := range []string{"MOVS", "STOS", "SCAS", "CMPS", "LODS"} {
			for _, width := range []string{"B", "W", "L", "Q"} {
				for _, prefix := range []string{"", "REP", "REPN"} {
					for _, direction := range []string{"CLD", "STD"} {
						op := Op(kind + width)
						t.Run(arch+"/"+string(op)+"/"+prefix+"/"+direction, func(t *testing.T) {
							// Existing emitter-only role: this verifies the virtual DF
							// handoff, not a repeated-memory or source-query grant.
							var output strings.Builder
							ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, arch, "", false)
							ctx.directionSlot = "%direction"
							if known, err := ctx.lowerDirectionControl(x86ScalarLaneInstruction(t, direction)); !known || err != nil {
								t.Fatal(err)
							}
							ctx.repeatPrefix = prefix
							known, _, err := ctx.lowerString(x86ScalarLaneInstruction(t, string(op)))
							if !known || arch == "386" && width == "Q" && err == nil || !(arch == "386" && width == "Q") && err != nil {
								t.Fatal("complete string grammar changed", err)
							}
							if arch == "386" && width == "Q" {
								return
							}
							ir := output.String()
							want := "store i1 false, ptr %direction"
							if direction == "STD" {
								want = "store i1 true, ptr %direction"
							}
							if !strings.Contains(ir, want) || !strings.Contains(ir, "load i1, ptr %direction") || !strings.Contains(ir, "i1 %") || ctx.repeatPrefix != "" {
								t.Fatal("string helper bypassed actual direction/prefix consumption", ir)
							}
							if prefix != "" && (kind == "SCAS" || kind == "CMPS") && strings.Count(ir, "select i1") < 6 {
								t.Fatal("zero-count repeat discarded incoming six-status flags", ir)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86DirectionControlPreservesSixStatusButGrantsNoEntryFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, direction := range []string{"CLD", "STD"} {
			for _, field := range []struct{ name, set string }{
				{"CF", "SETCS"}, {"PF", "SETPS"}, {"AF", ""},
				{"ZF", "SETEQ"}, {"SF", "SETMI"}, {"OF", "SETOS"},
			} {
				if field.set == "" {
					continue // AF has no SETcc encoding; the byte-state test covers it.
				}
				for _, initialized := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/producer=%t", arch, direction, field.name, initialized), func(t *testing.T) {
						body := direction + "\n" + field.set + " AL\nMOVB AL,ret+RESULT(FP)"
						if initialized {
							body = "MOVL $3,AX\nCMPL AX,$1\n" + body
						}
						decl := "func view() byte\n"
						source := x86ResultGPSIMDAdmissionSource(t, arch, decl, body)
						pkg := mustGoPackage(t, "bitview", "package bitview\n"+decl)
						sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
						if err != nil {
							t.Fatal(err)
						}
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						for _, query := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
							err := query(file.Funcs[0], sig, arch)
							if initialized && err != nil || !initialized && !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("DF was confused with incoming numerical/status facts", err)
							}
						}
					})
				}
			}
		}
	}
}
