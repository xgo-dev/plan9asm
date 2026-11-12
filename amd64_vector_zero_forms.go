package plan9asm

import (
	"fmt"
	"strings"
)

type x86VectorZeroSpec struct {
	firstByte int
	vexLength byte
}

// Go's complete _yvzeroall table has no operands or suffixes. VEX.L selects
// the semantic operation, not the register width. Intel SDM Vol. 2C specifies
// only registers 0-15 in 64-bit mode and 0-7 otherwise; Z16-Z31 are unchanged.
var x86VectorZeroSpecs = map[Op]x86VectorZeroSpec{
	"VZEROUPPER": {firstByte: 16, vexLength: 0},
	"VZEROALL":   {firstByte: 0, vexLength: 1},
}

type x86VectorZeroForm struct {
	spec      x86VectorZeroSpec
	registers int
}

func x86VectorZeroProperties(ins Instr, arch string) (x86VectorZeroForm, bool, error) {
	opcode := strings.ToUpper(string(ins.Op))
	base, _, suffix := strings.Cut(opcode, ".")
	spec, recognized := x86VectorZeroSpecs[Op(base)]
	if !recognized {
		return x86VectorZeroForm{}, false, nil
	}
	if suffix || len(ins.Args) != 0 {
		return x86VectorZeroForm{}, true, fmt.Errorf("%s requires zero operands and no suffix: %q", base, ins.Raw)
	}
	registers := 16
	if arch == "386" {
		registers = 8
	} else if arch != "amd64" && arch != "" {
		return x86VectorZeroForm{}, true, fmt.Errorf("%s requires amd64 or 386, got %q", base, arch)
	}
	return x86VectorZeroForm{spec: spec, registers: registers}, true, nil
}

func (c *amd64Ctx) lowerVectorZero(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, recognized := x86VectorZeroSpecs[Op(base)]; !recognized {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("vector zero dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, recognized, err := x86VectorZeroProperties(ins, c.goarch)
	if err != nil || !recognized {
		return recognized, false, err
	}
	for register := 0; register < form.registers; register++ {
		for _, view := range []struct {
			bytes int
			slots map[int]string
		}{{16, c.xRegSlot}, {32, c.yRegSlot}, {64, c.zRegSlot}} {
			slot, live := view.slots[register]
			if !live || view.bytes <= form.spec.firstByte {
				continue
			}
			pointer := slot
			alignment := view.bytes
			if form.spec.firstByte != 0 {
				tail := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", tail, slot, form.spec.firstByte)
				pointer = "%" + tail
				alignment = form.spec.firstByte
			}
			// A narrow tail store preserves the low X bytes independently in
			// every live alias. No initial SIMD value or native memory is read.
			// Omitting align lets LLVM infer 64 for the 48-byte Z tail,
			// although slot+16 is only 16-aligned. That can produce a
			// faulting aligned YMM store even to our own stack allocation.
			fmt.Fprintf(c.b, "  store <%d x i8> zeroinitializer, ptr %s, align %d\n",
				view.bytes-form.spec.firstByte, pointer, alignment)
		}
	}
	return true, false, nil
}

func x86CallerVectorZeroStep(form x86VectorZeroForm, state *x86SourceStackState) bool {
	x86VectorZeroDefinedBytes(form, state.vectors)
	return true
}

// Numerical register facts only. Source permissions and executable lowering
// remain with each consumer; neither an input nor a memory byte is supplied.
func x86VectorZeroDefinedBytes(form x86VectorZeroForm, vectors map[Reg]uint64) {
	zeroed := ^x86CallerVectorByteMask(int64(form.spec.firstByte))
	for register := 0; register < form.registers; register++ {
		root := Reg(fmt.Sprintf("Z%d", register))
		vectors[root] |= zeroed
	}
}
