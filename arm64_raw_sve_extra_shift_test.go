package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawSVEExtraShiftCase struct {
	op         string
	predicated bool
	left       bool
	reverse    bool
}

func arm64RawSVEExtraShiftCases() []arm64RawSVEExtraShiftCase {
	return []arm64RawSVEExtraShiftCase{
		{op: "asrd", predicated: true},
		{op: "sli", left: true},
		{op: "sqshlu", predicated: true, left: true},
		{op: "sri"},
		{op: "srshr", predicated: true},
		{op: "srsra"},
		{op: "ssra"},
		{op: "urshr", predicated: true},
		{op: "ursra"},
		{op: "usra"},
		{op: "asrr", predicated: true, reverse: true},
		{op: "lslr", predicated: true, reverse: true},
		{op: "lsrr", predicated: true, reverse: true},
	}
}

func (form arm64RawSVEExtraShiftCase) assembly(size, dst, src, pred, shift int) string {
	width := "bhsd"[size]
	if form.reverse {
		return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, z%d.%c", form.op, dst, width, pred, dst, width, src, width)
	}
	if form.predicated {
		return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, #%d", form.op, dst, width, pred, dst, width, shift)
	}
	return fmt.Sprintf("%s z%d.%c, z%d.%c, #%d", form.op, dst, width, src, width, shift)
}

func TestARM64RawSVEExtraShiftCompleteFormats(t *testing.T) {
	var lines []string
	for _, form := range arm64RawSVEExtraShiftCases() {
		for size := 0; size < 4; size++ {
			minimum, maximum := 1, 8<<size
			if form.left {
				minimum, maximum = 0, maximum-1
			}
			if form.reverse {
				maximum = minimum
			}
			for shift := minimum; shift <= maximum; shift++ {
				lines = append(lines, form.assembly(size, 31, 30, 7, shift))
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawextrashift(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawextrashift": {Name: "rawextrashift", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawextrashift.ll", "rawextrashift.o", ir)
		})
	}
}

func TestARM64RawSVEExtraShiftOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, form := range arm64RawSVEExtraShiftCases() {
		for size := 0; size < 4; size++ {
			limits := []int{32, 32, 8, 8 << size}
			if !form.predicated {
				limits[2] = 1
			}
			if form.predicated && !form.reverse {
				limits[1] = 1
			}
			if form.reverse {
				limits[3] = 1
			}
			for field, limit := range limits {
				for value := 0; value < limit; value++ {
					fields := [4]int{31, 30, limits[2] - 1, 0}
					fields[field] = value
					dst, src, pred, shift := fields[0], fields[1], fields[2], fields[3]
					if !form.left {
						shift++
					}
					lines = append(lines, form.assembly(size, dst, src, pred, shift))
					reg := func(n int) Operand {
						return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", n, "BHSD"[size]))}
					}
					first := Operand{Kind: OpImm, Imm: int64(shift)}
					if form.reverse {
						first = reg(src)
					}
					args := []Operand{first}
					if form.predicated {
						args = append(args, reg(dst), Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", pred))})
					} else {
						args = append(args, reg(src))
					}
					args = append(args, reg(dst))
					wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(form.op)), Args: args})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		got, ok := decodeARM64RawSVEExtraShift(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, form := range arm64RawSVEExtraShiftCases() {
		if form.reverse {
			continue
		}
		spec := arm64SVEImmediateShiftSpecs[Op("Z"+strings.ToUpper(form.op))]
		lowBit := 16
		if form.predicated {
			lowBit = 5
		}
		for immediate := uint32(0); immediate < 8; immediate++ {
			word := spec.rawBase | immediate<<lowBit
			if got, ok := decodeARM64RawSVEExtraShift(word); ok {
				t.Errorf("unallocated tsize in %#08x decoded as %+v", word, got)
			}
		}
	}
	for _, word := range []uint32{0, 0x04008000, 0x04108000, 0x4500fc00} {
		if got, ok := decodeARM64RawSVEExtraShift(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
