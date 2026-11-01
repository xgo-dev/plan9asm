package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86LEADispatchBindsCompleteWidths(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []Op{"LEAW", "LEAL", "LEAQ"} {
			for _, instructionOp := range []Op{"", op, Op(strings.ToLower(string(op)))} {
				t.Run(fmt.Sprintf("%s/%s/op=%q", arch, op, instructionOp), func(t *testing.T) {
					instruction := Instr{Op: instructionOp, Args: []Operand{
						{Kind: OpMem, Mem: MemRef{Base: BX, Index: CX, Scale: 2, Off: 8}},
						{Kind: OpReg, Reg: AX},
					}}
					registered := instruction
					registered.Op = op
					ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{registered}}, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before := output.String()
					ok, terminated, err := ctx.lowerArith(op, instruction)
					if arch == "386" && op == "LEAQ" {
						if !ok || terminated || err == nil || output.String() != before {
							t.Fatalf("386 LEAQ must reject before emission: (%v, %v, %v)", ok, terminated, err)
						}
						return
					}
					if !ok || terminated || err != nil {
						t.Fatalf("LEA dispatch = (%v, %v, %v)", ok, terminated, err)
					}
					if instruction.Op != instructionOp {
						t.Fatal("dispatch mutated the caller's original instruction identity")
					}
					if op == "LEAW" && !strings.Contains(output.String()[len(before):], "to i16") ||
						op == "LEAL" && !strings.Contains(output.String()[len(before):], "to i32") {
						t.Fatal("LEA used a different destination width than the dispatch")
					}
				})
			}
		}
	}
}

func TestX86LEADispatchRejectsContradictoryIdentityBeforeEmission(t *testing.T) {
	for _, dispatch := range []Op{"LEAW", "LEAL", "LEAQ"} {
		for _, source := range []Op{"LEAW", "LEAL", "LEAQ", "LEAL.Z", "MOVQ", "UNKNOWN"} {
			if source == dispatch {
				continue
			}
			t.Run(fmt.Sprintf("%s/source=%s", dispatch, source), func(t *testing.T) {
				instruction := Instr{Op: source, Args: []Operand{
					{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}},
					{Kind: OpReg, Reg: AX},
				}}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
				before := output.String()
				ok, terminated, err := ctx.lowerArith(dispatch, instruction)
				if !ok || terminated || err == nil {
					t.Fatalf("accepted an unknown/contradictory LEA identity: (%v, %v, %v)", ok, terminated, err)
				}
				if output.String() != before {
					t.Fatal("contradictory LEA emitted address loads/truncation/stores before rejection")
				}
			})
		}
	}
}

func TestX86LEADispatchUnknownOpcodeCannotConsumeKnownInstruction(t *testing.T) {
	for _, dispatch := range []Op{"UNKNOWN", "LEAL.Z", "leal"} {
		for _, source := range []Op{"", "LEAW", "LEAL", "LEAQ", "UNKNOWN"} {
			t.Run(fmt.Sprintf("%s/source=%q", dispatch, source), func(t *testing.T) {
				instruction := Instr{Op: source, Args: []Operand{
					{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}},
					{Kind: OpReg, Reg: AX},
				}}
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
				before := output.String()
				ok, terminated, _ := ctx.lowerArith(dispatch, instruction)
				if ok || terminated || output.String() != before {
					t.Fatal("unknown arithmetic dispatch was treated as an emitted LEA")
				}
			})
		}
	}
}
