package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestX86MoveHalfCompleteInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, base, destination := 8, "MOVQ", "X30", "X31"
			if target.arch == "386" {
				word, move, base, destination = 4, "MOVL", "X6", "X7"
			}
			var source, declarations strings.Builder
			for _, row := range x86MoveHalfOracle {
				load, store, merge, output := "MOVUPS", "MOVUPS", "X6", "X7"
				if target.arch == "amd64" {
					merge, output = "X14", "X15"
				}
				args := "(DX)," + output
				if row.vector {
					load, store, merge, output = "VMOVUPS", "VMOVUPS", base, destination
					args = "(DX)," + merge + "," + output
				}
				name := "Native" + row.op
				fmt.Fprintf(&declarations, "func %s(out *[32]byte,base *[16]byte,half *uint64)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),AX\n%s base+%d(FP),CX\n%s half+%d(FP),DX\n"+
					"%s (CX),%s\n%s %s,%s\nSTC\n%s %s\n%s %s,(AX)\n%s %s,16(AX)\nSETCS 24(AX)\nRET\n",
					name, 3*word, move, move, word, move, 2*word, load, merge, load, merge, output,
					row.op, args, store, output, row.op, output)
				name = "Logical" + row.op
				args = "value+0(FP),X2"
				if row.vector {
					args = "value+0(FP),X1,X2"
				}
				fmt.Fprintf(&declarations, "func %s(value,old uint64) uint64\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ old+8(FP),X1\nMOVUPS X1,X2\n%s %s\n%s X2,ret0+16(FP)\nRET\n",
					name, row.op, args, row.op)
			}
			if len(strings.Split(strings.TrimSpace(declarations.String()), "\n")) != 16 {
				t.Fatal("bounded sixteen-function complete half-move directory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete initialized native/logical half-move program rejected", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(body, "load volatile i64, ptr") != 8 || strings.Count(body, "store volatile i64 ") != 8 {
							t.Fatal("half-move native accesses lost their exact eight-byte tuple")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, body, level)
						}
					}
				})
			}
		})
	}
}

func TestX86MoveHalfNativeContinuationNeverCreatesMemoryFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86MoveHalfOracle {
			for _, store := range []bool{false, true} {
				t.Run(fmt.Sprint(arch, "/", row.op, "/store=", store), func(t *testing.T) {
					args := "(AX),X2"
					if row.vector {
						args = "(AX),X1,X2"
					}
					if store {
						args = "X1,(AX)"
					}
					ins := x86ScalarLaneInstruction(t, row.op+" "+args)
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.pointerGP[0], state.xmm[1], state.xmm[2] = true, 0xffff, 0xffff
					before := state.clone()
					if accepted, known := x86ResultMoveHalfStep(ins, &state, nil, 0, arch, false); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("declaration-only observer acquired a native access")
					}
					if accepted, known := x86ResultMoveHalfStep(ins, &state, nil, 0, arch, true); !known || !accepted {
						t.Fatal("paired exact-width native access could not continue")
					}
					if !store {
						before.xmm[2], before.vectorUpper[2] = state.xmm[2], state.vectorUpper[2]
					}
					if !reflect.DeepEqual(state, before) {
						t.Fatal("native half-move created storage, pointer, mask or flag knowledge")
					}
					for _, mutation := range []string{"pointer", "encoded", "raw", "segment", "address", "raw-return"} {
						changed, input := ins, before.clone()
						switch mutation {
						case "pointer":
							input.pointerGP[0] = false
						case "encoded":
							changed.x86Encoded = true
						case "raw":
							changed.x86SourceRaw = new(x86SourceRawInstruction)
						case "segment":
							changed.x86SegmentPrefix = 0x64
						case "address":
							changed.x86AddressBits = 32
						case "raw-return":
							changed.x86RawNearReturn = new(x86RawNearReturnForm)
						}
						original := input.clone()
						if accepted, _ := x86ResultMoveHalfStep(changed, &input, nil, 0, arch, true); accepted || !reflect.DeepEqual(input, original) {
							t.Fatal("native continuation borrowed a changed source or missing input", mutation)
						}
					}
				})
			}
		}
	}
}

func TestX86MoveHalfLegacyPDRegisterHasNoNumericalPermission(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required for independent encoding observation")
	}
	// Intel SDM Vol.2B MOVLPD/MOVHPD and Intel XED xed-isa.txt both
	// require a memory ModRM (MOD!=3). Go's broad yxmov is not an ISA proof.
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"MOVLPD", "MOVHPD"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+op+" X1,X2\nRET\n")
				opcode := byte(0x12)
				if op == "MOVHPD" {
					opcode = 0x16
				}
				if !reflect.DeepEqual(code, []byte{0x66, 0x0f, opcode, 0xd1, 0xc3}) {
					t.Fatal("actual Go's undocumented PD register bytes changed", code)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+sse2")
				command.Stdin = strings.NewReader(fmt.Sprintf("0x66 0x0f 0x%02x 0xd1\n", opcode))
				output, err := runtimeOracleCombinedOutput(ctx, command)
				alias := "movhlps"
				if op == "MOVHPD" {
					alias = "movlhps"
				}
				if err != nil || ctx.Err() != nil || !strings.Contains(string(output), alias) || strings.Contains(string(output), "warning:") {
					t.Fatal("LLVM22's actual ignored-66 PS-alias observation changed", err, string(output))
				}
				t.Logf("actual Go bytes=%x; LLVM22 decoder=%s; an ignored-prefix decoder observation is not documented PD register semantics or a #UD proof", code, strings.TrimSpace(string(output)))
				ins := x86ScalarLaneInstruction(t, op+" X1,X2")
				state := x86ResultState{}
				state.xmm[1], state.xmm[2] = 0xffff, 0xffff
				before := state.clone()
				if accepted, known := x86ResultMoveHalfStep(ins, &state, nil, 0, arch, true); !known || accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("undocumented 66-prefixed register bytes acquired assumed PS numerical semantics")
				}
				context := newX86Ctx(new(strings.Builder), Func{}, FuncSig{}, nil, nil, arch, triple, false)
				if known, _, err := context.lowerMOVHalf(ins.Op, ins); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("public lowering promised undocumented PD register semantics", known, err)
				}
			})
		}
	}
}

func TestX86MoveHalfExactRawSourceKeepsAllInputsAndIdentity(t *testing.T) {
	for _, row := range x86MoveHalfOracle[4:] {
		for _, store := range []bool{false, true} {
			t.Run(fmt.Sprint(row.op, "/store=", store), func(t *testing.T) {
				operation := row.op + " (DX),X1,X2"
				if store {
					operation = row.op + " X1,(DX)"
				}
				code := assembleX87ControlBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+operation+"\nRET\n")
				var source strings.Builder
				source.WriteString("TEXT ·Value(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ base+8(FP),CX\nMOVQ half+16(FP),DX\nMOVUPS (CX),X1\n")
				for _, value := range code[:len(code)-1] {
					fmt.Fprintf(&source, "BYTE $%#02x\n", value)
				}
				output := "X2"
				if store {
					output = "X1"
				}
				fmt.Fprintf(&source, "MOVUPS %s,(AX)\nRET\n", output)
				declaration := "func Value(out *[16]byte,base *[16]byte,half *uint64)\n"
				goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if _, err := x86ScalarFPBitViewAPI(t, source.String(), declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
							t.Fatal("complete initialized original raw half-move rejected", err)
						}
						missing := strings.Replace(source.String(), "MOVQ half+16(FP),DX\n", "", 1)
						if _, err := x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw bytes supplied their own native read/write pointer", err)
						}
					})
				}
				parsed, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				normalized, err := normalizeX86RawFile(parsed, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				var raw Instr
				for _, ins := range normalized.Funcs[0].Instrs {
					if ins.Op == Op(row.op) {
						raw = ins
					}
				}
				if !x86RawMoveHalfSource(raw, "amd64") {
					t.Fatal("complete physical decoder lost its exact sealed source")
				}
				for _, mutation := range []string{"args", "source", "address", "segment", "native-pointer"} {
					changed := raw
					changed.Args = append([]Operand(nil), raw.Args...)
					state := x86ResultState{}
					state.pointerGP[2], state.xmm[1] = true, 0xffff
					switch mutation {
					case "args":
						at := 0
						if store {
							at = 1
						}
						changed.Args[at].Mem.Off++
					case "source":
						changed.x86SourceRaw = nil
						changed.x86Encoded = true // Retain physical-origin evidence, not a new named instruction.
					case "address":
						changed.x86AddressBits = 32
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "native-pointer":
						state.pointerGP[2] = false
					}
					before := state.clone()
					if accepted, _ := x86ResultMoveHalfStep(changed, &state, nil, 0, "amd64", true); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("raw continuation widened a changed identity or missing input", mutation)
					}
				}
				// Removing every physical-origin field constructs an independent
				// valid named instruction. Its existing inputs still remain required.
				named := raw
				named.x86Encoded, named.x86SourceRaw = false, nil
				state := x86ResultState{}
				state.pointerGP[2], state.xmm[1] = true, 0xffff
				if accepted, known := x86ResultMoveHalfStep(named, &state, nil, 0, "amd64", true); !known || !accepted {
					t.Fatal("physical-origin negative accidentally rejected the separate legal named effect")
				}
			})
		}
	}
}

func x86MoveHalfFormatObjectUnit(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string) string {
	t.Helper()
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
		form, known, err := x86MoveHalfProperties(ins.Op, ins, arch)
		if !known {
			terminated, err := c.lowerInstr(0, 0, ins, nil, nil)
			return true, terminated, err
		}
		if err != nil {
			return true, false, err
		}
		if form.undocumentedPDRegister {
			code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n")
			var bytes []string
			for _, value := range code[:len(code)-1] {
				bytes = append(bytes, fmt.Sprintf("0x%02x", value))
			}
			// Preserve the original undocumented opcode, not an invented PS copy.
			// This carrier certifies object bytes only, never a public entry.
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", ".byte "+strings.Join(bytes, ","), "~{memory}")
			return true, false, nil
		}
		return true, false, c.emitMoveHalf(form, ins)
	})
}
