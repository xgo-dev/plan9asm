package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64SVESaturatingAddSubCase struct {
	op        string
	size      int
	mode      arm64SVEAddMode
	immediate int
}

func arm64SVESaturatingAddSubCases() []arm64SVESaturatingAddSubCase {
	var cases []arm64SVESaturatingAddSubCase
	for _, op := range []string{"sqadd", "sqsub", "sqsubr", "uqadd", "uqsub", "uqsubr"} {
		for size := 0; size < 4; size++ {
			cases = append(cases, arm64SVESaturatingAddSubCase{op: op, size: size, mode: arm64SVEAddPredicated})
			if strings.HasSuffix(op, "r") {
				continue
			}
			cases = append(cases, arm64SVESaturatingAddSubCase{op: op, size: size, mode: arm64SVEAddUnpredicated})
			for _, immediate := range []int{0, 1, 127, 128, 255, 256, 32768, 65280} {
				if size == 0 && immediate > 255 {
					continue
				}
				cases = append(cases, arm64SVESaturatingAddSubCase{op, size, arm64SVEAddImmediate, immediate})
			}
		}
	}
	return cases
}

func (form arm64SVESaturatingAddSubCase) assembly(dst, first, second, predicate int) string {
	width := "bhsd"[form.size]
	switch form.mode {
	case arm64SVEAddUnpredicated:
		return fmt.Sprintf("%s z%d.%c, z%d.%c, z%d.%c", form.op, dst, width, first, width, second, width)
	case arm64SVEAddPredicated:
		return fmt.Sprintf("%s z%d.%c, p%d/m, z%d.%c, z%d.%c", form.op, dst, width, predicate, dst, width, second, width)
	default:
		return fmt.Sprintf("%s z%d.%c, z%d.%c, #%d", form.op, dst, width, dst, width, form.immediate)
	}
}

func TestARM64RawSVESaturatingAddSubCompleteFormats(t *testing.T) {
	var lines []string
	for _, form := range arm64SVESaturatingAddSubCases() {
		lines = append(lines, form.assembly(31, 30, 29, 7))
	}
	var source strings.Builder
	source.WriteString("TEXT rawsaturating(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawsaturating": {Name: "rawsaturating", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawsaturating.ll", "rawsaturating.o", ir)
		})
	}
}

func TestARM64RawSVESaturatingAddSubOperandFields(t *testing.T) {
	var lines []string
	var wants []arm64RawSVEAdd
	var ops []Op
	appendCase := func(form arm64SVESaturatingAddSubCase, dst, first, second, pred int) {
		lines = append(lines, form.assembly(dst, first, second, pred))
		want := arm64RawSVEAdd{mode: form.mode, elementBits: 8 << form.size, destination: dst, first: first}
		switch form.mode {
		case arm64SVEAddUnpredicated:
			want.second = second
		case arm64SVEAddPredicated:
			want.first, want.second, want.predicate = dst, second, pred
		case arm64SVEAddImmediate:
			want.first, want.immediate = dst, form.immediate
		}
		wants = append(wants, want)
		ops = append(ops, Op("Z"+strings.ToUpper(form.op)))
	}
	for _, form := range arm64SVESaturatingAddSubCases() {
		if form.mode == arm64SVEAddImmediate && form.immediate != 0 {
			continue
		}
		limits := [4]int{32, 32, 32, 1}
		if form.mode == arm64SVEAddPredicated {
			limits[1], limits[3] = 1, 8
		} else if form.mode == arm64SVEAddImmediate {
			limits[1], limits[2] = 1, 1
		}
		for field, limit := range limits {
			for value := 0; value < limit; value++ {
				fields := [4]int{31, 30, 29, 7}
				fields[field] = value
				appendCase(form, fields[0], fields[1], fields[2], fields[3])
			}
		}
		if form.mode == arm64SVEAddImmediate {
			for _, shift := range []int{0, 8} {
				if form.size == 0 && shift != 0 {
					continue
				}
				for imm := 0; imm < 256; imm++ {
					form.immediate = imm << shift
					appendCase(form, 31, 31, 0, 0)
					// Preserve shifted zero as a distinct physical encoding.
					lines[len(lines)-1] = fmt.Sprintf("%s z31.%c, z31.%c, #%d, lsl #%d",
						form.op, "bhsd"[form.size], "bhsd"[form.size], imm, shift)
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2") {
		op, got, ok := decodeARM64RawSVEAddSub(word)
		if !ok || op != ops[i] || got != wants[i] {
			t.Fatalf("%s: %#08x = %s %+v, %v; want %s %+v", lines[i], word, op, got, ok, ops[i], wants[i])
		}
	}
	for _, word := range []uint32{
		0x2524e000, 0x2525e000, 0x2526e000, 0x2527e000, // Reserved shifted byte immediates.
		0x441c8000, 0x441d8000, 0x04200c00, 0x2528c000, // Adjacent operations, not this family.
	} {
		if op, form, ok := decodeARM64RawSVEAddSub(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %s %+v", word, op, form)
		}
	}
}
