package plan9asm

import "testing"

func TestX86X87WordUnknownShapeJoinKeepsOnlySharedLayout(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			name                    string
			leftCall, rightCall     bool
			foreign, missing, depth bool
			shared                  bool
		}{
			{name: "both-calls", leftCall: true, rightCall: true, shared: true},
			{name: "left-call", leftCall: true, shared: true},
			{name: "right-call", rightCall: true, shared: true},
			{name: "different-depth", depth: true, shared: true},
			{name: "foreign-layout", leftCall: true, foreign: true},
			{name: "missing-layout", leftCall: true, missing: true},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				layout := &x86X87WordLayout{parameters: map[int64]bool{0: true}}
				left := x86ResultState{x87: &x86ResultX87State{
					slots: 1, depth: 1, status: 0xffff,
					word: &x86ResultX87WordState{control: 0xffff, layout: layout},
				}}
				left.x87.gp[0] = 0xffff
				right := left.clone()
				if row.foreign {
					right.x87.word.layout = &x86X87WordLayout{parameters: map[int64]bool{0: true}}
				}
				if row.missing {
					right.x87.word = nil
				}
				if row.depth {
					right.x87.depth = 2
				}
				if row.leftCall {
					x86ResultX87After(Instr{Op: OpCALL}, &left, arch)
				}
				if row.rightCall {
					x86ResultX87After(Instr{Op: OpCALL}, &right, arch)
				}
				joined := left.intersect(right)
				if !joined.x87.invalid || joined.x87.slots != 0 || joined.x87.depth != 0 ||
					joined.x87.status != 0 || joined.x87.gp != [16]uint16{} {
					t.Fatal("unknown shape join retained mutable x87 facts")
				}
				if !row.shared {
					if joined.x87.word != nil {
						t.Fatal("foreign or one-sided layout acquired shared source metadata")
					}
					return
				}
				if joined.x87.word == nil || joined.x87.word.layout != layout || joined.x87.word.control != 0 {
					t.Fatal("unknown shape join erased immutable layout or retained control knownness")
				}
				accepted, known := x86ResultX87WordStep(x86X87ValueInstruction(t, "FINIT"), &joined, nil, 0, arch)
				if !known || !accepted || joined.x87.invalid || joined.x87.slots != 0 || joined.x87.depth != 0 ||
					joined.x87.status != 0xffff || joined.x87.word.control != 0xffff || joined.x87.word.layout != layout {
					t.Fatal("FINIT did not restore only its empty shape and known words")
				}
				if joined.x87.read(Operand{Kind: OpReg, Reg: "F0"}) {
					t.Fatal("FINIT created a value in the empty x87 stack")
				}
			})
		}
	}
}

func TestX86X87WordFPAccessWidthAndDirectionOnly(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			source string
			write  bool
		}{
			{"FSTCW value+0(FP)", true},
			{"FSTSW value+0(FP)", true},
			{"FLDCW value+0(FP)", false},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				ins := x86X87ValueInstruction(t, row.source)
				width, write, known := X86FPAccessBytes(ins, 0, arch)
				if !known || width != 2 || write != row.write {
					t.Fatal("complete Go Ym word row lost its exact m16 direction", width, write, known)
				}
				for _, invalid := range []Instr{
					{Op: ins.Op, Args: append(ins.Args, Operand{Kind: OpReg, Reg: AX})},
					{Op: Op(string(ins.Op) + ".Z"), Args: ins.Args},
				} {
					if width, _, known := X86FPAccessBytes(invalid, 0, arch); known || width != 0 {
						t.Fatal("malformed row gained an FP access width")
					}
				}
				for _, foreign := range []string{"", "arm", "arm64", "wasm"} {
					if width, _, known := X86FPAccessBytes(ins, 0, foreign); known || width != 0 {
						t.Fatal("missing or foreign mode inferred an x86 width")
					}
				}
				for _, index := range []int{-1, 1} {
					if width, _, known := X86FPAccessBytes(ins, index, arch); known || width != 0 {
						t.Fatal("unbound operand index gained a width")
					}
				}
			})
		}
		for _, source := range []string{"FINIT", "FCLEX", "FSTSW AX", "FSTCW (AX)", "FLDCW (AX)"} {
			if width, _, known := X86FPAccessBytes(x86X87ValueInstruction(t, source), 0, arch); known || width != 0 {
				t.Fatal("non-FP row acquired a logical FP access", arch, source)
			}
		}
	}
}
