package plan9asm

import "testing"

func TestX86EnqueueCompleteAddress16Forms(t *testing.T) {
	rows := []struct{ base, index Reg }{
		{BX, SI}, {BX, DI}, {BP, SI}, {BP, DI}, {SI, ""}, {DI, ""}, {BP, ""}, {BX, ""},
	}
	for _, prefix := range []byte{0xf2, 0xf3} {
		for mod := byte(0); mod < 3; mod++ {
			for rm, row := range rows {
				code := []byte{0x67, prefix, 0x0f, 0x38, 0xf8, mod<<6 | 7<<3 | byte(rm)}
				base, index, offset := row.base, row.index, uint16(0)
				if mod == 1 {
					code, offset = append(code, 0x80), 0xff80
				} else if mod == 2 || rm == 6 {
					code, offset = append(code, 0x00, 0x80), 0x8000
					if mod == 0 {
						base = "" // The absolute disp16 row replaces BP only for mod=00.
					}
				}
				ins, length, known, err := decodedX86EnqueueInstruction(code, 32)
				if err != nil || !known || length != len(code) || len(ins.Args) != 2 ||
					ins.x86AddressBits != 16 || ins.Args[1].Reg != DI ||
					ins.Args[0].Mem.Base != base || ins.Args[0].Mem.Index != index || uint16(ins.Args[0].Mem.Off) != offset {
					t.Fatalf("complete address16 physical row %x: %#v / %v", code, ins, err)
				}
				if _, known, err := x86EnqueueProperties(ins.Op, ins, "386"); !known || err != nil {
					t.Fatal("typed grammar lost a legal original address16 form", ins, err)
				}
			}
		}
	}
}

func TestX86EnqueueConstructedAddressGrammarBeforeIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{"ENQCMD", "ENQCMDS"} {
			for _, mutation := range []string{"offset-overflow", "offset-underflow", "orphan-scale", "invalid-scale",
				"stack-index", "foreign-extension", "constructed-memory", "invalid-segment", "invalid-16-bit-base"} {
				t.Run(arch+"/"+string(op)+"/"+mutation, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, string(op)+" (BX),DI")
					switch mutation {
					case "offset-overflow":
						ins.Args[0].Mem.Off = 1 << 32
					case "offset-underflow":
						ins.Args[0].Mem.Off = -1<<31 - 1
					case "orphan-scale":
						ins.Args[0].Mem.Scale = 4
					case "invalid-scale":
						ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
					case "stack-index":
						ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = SP, 1
					case "foreign-extension":
						ins.Args[0].Mem.IndexExt = ExtendSXTW
					case "constructed-memory":
						ins.Args[0].ImmRaw = "$unknown"
					case "invalid-segment":
						ins.Args[0].Mem.Segment = AX
					case "invalid-16-bit-base":
						ins.x86AddressBits, ins.Args[0].Mem.Base = 16, AX
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before, temporary := output.String(), ctx.tmp
					known, terminated, err := ctx.lowerEnqueue(op, ins)
					if !known || terminated || err == nil || output.String() != before || ctx.tmp != temporary {
						t.Fatal("unencodable enqueue address emitted IR", known, terminated, err)
					}
				})
			}
		}
	}
}
