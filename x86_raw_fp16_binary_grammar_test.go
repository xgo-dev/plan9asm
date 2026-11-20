package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86RawFP16BinaryMalformedBeforeIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, scalar := range []bool{false, true} {
			for opcode := range rawFP16BinaryOpcodes {
				for _, mutation := range []string{"dispatch", "mask", "destination", "source", "scale", "displacement", "extension", "suffix", "empty-suffix"} {
					t.Run(fmt.Sprintf("%s/%x/scalar%t/%s", arch, opcode, scalar, mutation), func(t *testing.T) {
						code := x86FP16BinaryResultEncoding(opcode, 0, scalar, true, false, 1)
						file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
						file, err := normalizeX86RawFile(file, arch)
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						dispatch := ins.Op
						switch mutation {
						case "dispatch":
							dispatch = "VADDPH"
							if ins.Op == dispatch {
								dispatch = "VSUBPH"
							}
						case "mask":
							ins.Args[2].Reg = "K0"
						case "destination":
							ins.Args[3] = Operand{Kind: OpReg, Reg: AX}
						case "source":
							ins.Args[0] = Operand{Kind: OpImm, ImmIsFloat: true}
						case "scale":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
						case "displacement":
							ins.Args[0].Mem.OffRaw = "unresolved"
						case "extension":
							ins.Args[0].Mem.IndexExt = "invalid"
						case "suffix":
							ins.Op += ".INVALID"
							dispatch = ins.Op
						case "empty-suffix":
							ins.Op += "."
							dispatch = ins.Op
						}
						ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
						ctx.goarch = arch
						before, temporary := output.String(), ctx.tmp
						known, terminated, err := ctx.lowerBinaryFloating(dispatch, ins)
						if !known || terminated || err == nil || output.String() != before || ctx.tmp != temporary {
							t.Fatal("malformed FP16 binary emitted IR", known, terminated, err)
						}
					})
				}
			}
		}
	}
}
