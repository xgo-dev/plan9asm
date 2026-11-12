package plan9asm

import (
	"strings"
	"testing"
)

func TestX86FP16ConversionMalformedDispatchBeforeIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for member, op := range x86FP16ConversionResultNames {
			for _, mutation := range []string{"dispatch", "mask", "destination", "source", "scale", "suffix"} {
				t.Run(arch+"/"+op+"/"+mutation, func(t *testing.T) {
					code := x86FP16ConversionResultEncoding(member, 0, true, false, false)
					file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
					file, err := normalizeX86RawFile(file, arch)
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					dispatch := ins.Op
					switch mutation {
					case "dispatch":
						dispatch = Op(x86FP16ConversionResultNames[(member+1)%6])
					case "mask":
						ins.Args[len(ins.Args)-2].Reg = "K0"
					case "destination":
						ins.Args[len(ins.Args)-1] = Operand{Kind: OpReg, Reg: AX}
					case "source":
						ins.Args[0] = Operand{Kind: OpImm, ImmIsFloat: true}
					case "scale":
						ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
					case "suffix":
						ins.Op += ".INVALID"
						dispatch = ins.Op
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before, temporary := output.String(), ctx.tmp
					known, terminated, err := ctx.lowerPackedHalfConversion(dispatch, ins)
					if !known || terminated || err == nil || output.String() != before || ctx.tmp != temporary {
						t.Fatal("invalid FP16 conversion emitted IR", known, terminated, err)
					}
					if mutation == "dispatch" && !strings.Contains(err.Error(), "mismatch") {
						t.Fatal("dispatch mismatch borrowed a different conversion shape", err)
					}
				})
			}
		}
	}
}
