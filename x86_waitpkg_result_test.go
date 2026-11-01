package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86WaitPKGCompleteGoRowsAndNUMInputs(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"var ywrfsbase = []ytab{\n\t{Zm_o, 2, argList{Yrl}},\n}",
		"{ATPAUSE, ywrfsbase, Pq, opBytes{0xae, 06}}",
		"{AUMWAIT, ywrfsbase, Pf2, opBytes{0xae, 06}}",
	} {
		if !strings.Contains(string(table), row) {
			t.Fatal("complete Go WAITPKG encoding changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		registers := []Reg{AX, CX, DX, BX, SP, BP, SI, DI}
		if arch == "amd64" {
			registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
		}
		for _, op := range []string{"UMWAIT", "TPAUSE"} {
			for _, register := range registers {
				t.Run(arch+"/"+op+"/"+string(register), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, op+" "+string(register))
					requireX86GoAssemblerResult(t, arch, "TEXT wait(SB),4,$0-0\n"+ins.Raw+"\nRET\n", true)
					before := x86ResultState{direction: x86ResultDirectionBackward}
					before.xmm[2], before.masks[1] = 0x1234, true
					before.valueStack = &x86ResultValueStack{bytes: []uint8{1, 2}, id: true}
					inputs := []int{0, 2}
					index, _, valid := x86ResultGP(register, 4, arch)
					if !valid {
						// AMD64 BP is a physical-frame role, not an ordinary NUM input.
						state := before.clone()
						if x86ResultTransfer(ins, &state, nil, 0, arch) {
							t.Fatal("physical frame acquired ordinary numerical inputs")
						}
						return
					}
					inputs = append(inputs, index)
					for _, input := range inputs {
						before.gp[input] = 0x0f
					}
					state, want := before.clone(), before.clone()
					want.flags = x86ByteFlagsAll
					if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
						t.Error("wait must read EDX:EAX/control, define status and preserve unrelated state")
					}
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if !known || err != nil || !effect.requiresResultProof {
						t.Error("missing mandatory wait input descriptor", err)
					}
					for _, input := range inputs {
						for missing := uint(0); missing < 4; missing++ {
							state := before.clone()
							state.gp[input] &^= 1 << missing
							unchanged := state.clone()
							if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, unchanged) {
								t.Error("wait accepted missing data or partially updated status", input, missing)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86WaitPKGRawIdentityAndStorageBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"UMWAIT", "TPAUSE"} {
			file, err := Parse(ArchAMD64, "TEXT wait(SB),4,$0-0\n"+x86WaitPKGBody(op, true)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			fn, err := decodeX86RawDirectives(file.Funcs[0], arch)
			if err != nil || len(fn.Instrs) != 3 {
				t.Fatal("wait lost its complete original source", err)
			}
			original := fn.Instrs[1]
			for _, mutation := range []string{"unchanged", "opcode", "operand", "origin-opcode", "origin-operand",
				"missing-origin", "address-size", "segment", "unbound-address", "raw-return", "constructed-operand"} {
				t.Run(arch+"/"+op+"/"+mutation, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					origin := *original.x86SourceRaw
					ins.x86SourceRaw = &origin
					switch mutation {
					case "opcode":
						ins.Op = "UMONITOR"
					case "operand":
						ins.Args[0].Reg = AX
					case "origin-opcode":
						origin.op = "NOP"
					case "origin-operand":
						origin.args = []Operand{{Kind: OpReg, Reg: AX}}
					case "missing-origin":
						ins.x86SourceRaw = nil
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
					if x86WaitPackagePreservesStorage(ins) != valid {
						t.Fatal("wait storage identity did not retain its exact source boundary")
					}
					state := x86ResultState{direction: x86ResultDirectionBackward,
						valueStack: &x86ResultValueStack{bytes: []uint8{1, 2, 3, 4}, id: true}}
					state.gp[0], state.gp[2], state.gp[3] = 0x0f, 0x0f, 0x0f
					state.callerAddressGP[7] = true
					if valid {
						if !x86ResultValueStackContinuation(ins, &state, arch) ||
							x86ResultDirectionAfter(ins, state.direction) != state.direction ||
							x86ResultCallerAddressesAfter(ins, state.callerAddressGP, nil, arch) != state.callerAddressGP {
							t.Fatal("wait destroyed unrelated private storage/DF/address identity")
						}
					}
					unchanged := state.clone()
					if x86ResultTransfer(ins, &state, nil, 0, arch) != valid || !valid && !reflect.DeepEqual(state, unchanged) {
						t.Fatal("mismatched raw wait acquired numerical state")
					}
				})
			}
		}
	}
}

func TestX86WaitPKGVoidInputsThreeAPIs(t *testing.T) {
	x86WaitPKGVoidInputsThreeAPIs(t, false)
}

func TestX86RawWaitPKGVoidInputsThreeAPIs(t *testing.T) {
	x86WaitPKGVoidInputsThreeAPIs(t, true)
}

func TestX86WaitPKGEntryAndJoinInputsThreeAPIs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, word, triple := "MOVL", 4, "i386-unknown-linux-gnu"
		if arch == "amd64" {
			move, word, triple = "MOVQ", 8, "x86_64-unknown-linux-gnu"
		}
		for _, op := range []string{"UMWAIT", "TPAUSE"} {
			for _, raw := range []bool{false, true} {
				for _, row := range []struct {
					name, declaration, setup string
					frame                    int
					valid                    bool
				}{
					{"pointer-control", "p *uint32", move + " p+0(FP),BX\nMOVL $0,AX\nMOVL $0,DX\n", word, false},
					{"unused-bool", "unused bool", "", 1, false},
					{"complete-unused-bool", "unused bool", "MOVL $0,AX\nMOVL $0,DX\nMOVL $0,BX\n", 1, true},
					{"missing-join", "selector uint32", "MOVL selector+0(FP),AX\nMOVL $0,DX\nCMPL AX,$0\nJE ready\nMOVL $0,BX\nready:\n", 4, false},
					{"complete-join", "selector uint32", "MOVL selector+0(FP),AX\nMOVL $0,DX\nMOVL $0,BX\nCMPL AX,$0\nJE ready\nMOVL $1,BX\nready:\n", 4, true},
				} {
					t.Run(fmt.Sprintf("%s/%s/raw=%t/%s", arch, op, raw, row.name), func(t *testing.T) {
						source := fmt.Sprintf("TEXT ·Wait(SB),4,$0-%d\n%s%sRET\n", row.frame, row.setup, x86WaitPKGBody(op, raw))
						x86LEAActualTargetGoObject(t, arch, triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Wait("+row.declaration+")", arch, triple, api)
							if row.valid {
								if err != nil || ir == "" {
									t.Error("complete wait lost entry/CFG inputs", api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Error("wait borrowed numerical inputs from pointer/bool/missing CFG path", api, err)
							}
						}
					})
				}
			}
		}
	}
}

func x86WaitPKGBody(op string, raw bool) string {
	if !raw {
		return op + " BX\n"
	}
	prefix := byte(0xf2)
	if op == "TPAUSE" {
		prefix = 0x66
	}
	return x86RawDisplacementDirectives([]byte{prefix, 0x0f, 0xae, 0xf3})
}

func x86WaitPKGVoidInputsThreeAPIs(t *testing.T, raw bool) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"UMWAIT", "TPAUSE"} {
			for _, setup := range []struct {
				name, source string
				valid        bool
			}{
				{"none", "", false},
				{"deadline-only", "MOVL $0,AX\nMOVL $0,DX\n", false},
				{"no-ax", "MOVL $0,DX\nMOVL $0,BX\n", false},
				{"no-dx", "MOVL $0,AX\nMOVL $0,BX\n", false},
				{"partial-control", "MOVL $0,AX\nMOVL $0,DX\nMOVB $0,BL\n", false},
				{"complete", "MOVL $0,AX\nMOVL $0,DX\nMOVL $0,BX\n", true},
			} {
				t.Run(target.triple+"/"+op+"/"+setup.name, func(t *testing.T) {
					source := "TEXT ·Wait(SB),4,$0-0\n" + setup.source + x86WaitPKGBody(op, raw) + "RET\n"
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Wait()", target.arch, target.triple, api)
						if setup.valid {
							if err != nil || !strings.Contains(ir, fmt.Sprintf("asm sideeffect %q", strings.ToLower(op)+" $1; setc $0")) {
								t.Error("initialized wait lost its native opcode", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("Void wait borrowed uninitialized inputs", api, err)
						}
					}
				})
			}
		}
	}
}

// Execute no WAITPKG instruction on the host: these objects retain actual
// native operations, their flags consumers and all original argument/result
// bytes. Native CPU availability and execution are separate requirements.
func TestX86WaitPKGInitializedStatusFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, value, offset := "L", "uint32", 12
		if target.arch == "amd64" {
			word, value, offset = "Q", "uint64", 16
		}
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				var source, declarations strings.Builder
				for _, op := range []string{"UMWAIT", "TPAUSE"} {
					fmt.Fprintf(&declarations, "func %s(control,low,high uint32) %s\n", op, value)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOVL control+0(FP),BX\nMOVL low+4(FP),AX\nMOVL high+8(FP),DX\nPUSH%s $0x8d7\nPOPF%s\n%sPUSHF%s\nPOP%s CX\nMOV%s CX,ret+%d(FP)\nRET\n",
						op, offset+int(x86ResultPointerWord(target.arch)), word, word, x86WaitPKGBody(op, raw), word, word, word, offset)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Error("initialized wait/status program rejected", api, err)
						continue
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			})
		}
	}
}
