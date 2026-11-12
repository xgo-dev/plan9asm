package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86ExplicitMaskMoveMalformedDispatchBeforeIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			for _, control := range []string{"dispatch", "suffix", "arity", "mask-bank", "mask-width", "data-width", "all-registers", "two-memories"} {
				t.Run(arch+"/"+row.name+"/"+control, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.instruction)
					op := ins.Op
					switch control {
					case "dispatch":
						ins.Op = "VMASKMOVPS"
						if ins.Op == op {
							ins.Op = "VMASKMOVPD"
						}
					case "suffix":
						op += ".Z"
						ins.Op = op
					case "arity":
						ins.Args = ins.Args[:2]
					case "mask-bank":
						ins.Args[1].Reg = "K1"
					case "mask-width":
						ins.Args[1].Reg = "Z1"
					case "data-width":
						ins.Args[2-row.memory].Reg = "Z0"
					case "all-registers":
						ins.Args[row.memory] = Operand{Kind: OpReg, Reg: Reg(row.bank + "3")}
					case "two-memories":
						ins.Args[2-row.memory] = Operand{Kind: OpMem, Mem: MemRef{Base: BX}}
					}
					var output strings.Builder
					ctx := amd64Ctx{b: &output, goarch: arch, targetTriple: "x86_64-unknown-linux-gnu"}
					known, terminated, err := ctx.lowerExplicitMaskMove(op, ins)
					if !known || terminated || err == nil || output.Len() != 0 {
						t.Fatal("malformed explicit-mask shape/dispatch emitted partial IR", control, err, output.String())
					}
				})
			}
		}
	}
}

func TestX86ExplicitMaskMoveRawNeverSuppliesMissingInputsOrEntry(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch]
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			for _, rawReturn := range []bool{false, true} {
				source := "TEXT ·Unbound(SB),4,$0-0\n" + x86RawDisplacementDirectives(x86ExplicitMaskMoveIndependentBytes(row))
				if rawReturn {
					source += "BYTE $0xc3\n"
				} else {
					source += "RET\n"
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+row.name+"/rawReturn="+map[bool]string{true: "true", false: "false"}[rawReturn]+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Unbound()", arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw vector-mask bytes supplied missing address/data/mask or return entry", err)
						}
					})
				}
			}
		}
	}
}
