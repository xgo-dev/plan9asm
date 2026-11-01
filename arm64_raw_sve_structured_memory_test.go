package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawSVEStructuredCase struct {
	op, width string
	count     int
	shift     int
	load      bool
}

func arm64RawSVEStructuredCases() []arm64RawSVEStructuredCase {
	var cases []arm64RawSVEStructuredCase
	for _, load := range []bool{true, false} {
		prefix := "st"
		if load {
			prefix = "ld"
		}
		for _, count := range []int{2, 3, 4} {
			for shift, suffix := range "bhwdq" {
				cases = append(cases, arm64RawSVEStructuredCase{
					fmt.Sprintf("%s%d%c", prefix, count, suffix), string("bhsdq"[shift]), count, shift, load,
				})
			}
		}
	}
	return cases
}

func (form arm64RawSVEStructuredCase) assembly(start, predicate int, address string) string {
	var registers []string
	for i := 0; i < form.count; i++ {
		registers = append(registers, fmt.Sprintf("z%d.%s", (start+i)%32, form.width))
	}
	mode := ""
	if form.load {
		mode = "/z"
	}
	return fmt.Sprintf("%s { %s }, p%d%s, %s", form.op, strings.Join(registers, ", "), predicate, mode, address)
}

func TestARM64RawSVEStructuredMemoryCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, form := range arm64RawSVEStructuredCases() {
		for _, base := range []string{"x0", "sp"} {
			for _, offset := range []int{-8, 0, 7} {
				lines = append(lines, form.assembly(31, 7, fmt.Sprintf("[%s, #%d, mul vl]", base, offset*form.count)))
			}
			lines = append(lines, form.assembly(31, 7, fmt.Sprintf("[%s, x30, lsl #%d]", base, form.shift)))
		}
	}
	source.WriteString("TEXT rawstructure(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
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
				Sigs: map[string]FuncSig{"rawstructure": {Name: "rawstructure", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawstructure.ll", "rawstructure.o", ir)
		})
	}
}

func TestARM64RawSVEStructuredMemoryOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, form := range arm64RawSVEStructuredCases() {
		for _, indexed := range []bool{false, true} {
			limits := []int{32, 8, 32, 16}
			if indexed {
				limits[3] = 31
			}
			for field, limit := range limits {
				for value := 0; value < limit; value++ {
					fields := [4]int{31, 7, 31, 3}
					fields[field] = value
					base, baseReg := fmt.Sprintf("x%d", fields[0]), Reg(fmt.Sprintf("R%d", fields[0]))
					if fields[0] == 31 {
						base, baseReg = "sp", "RSP"
					}
					memory := MemRef{Base: baseReg}
					var address string
					if indexed {
						address = fmt.Sprintf("[%s, x%d, lsl #%d]", base, fields[3], form.shift)
						memory.Index, memory.Scale = Reg(fmt.Sprintf("R%d", fields[3])), int64(1<<form.shift)
						if form.shift == 0 {
							memory.Base, memory.Index = memory.Index, memory.Base
						}
					} else {
						offset := (fields[3] - 8) * form.count
						address = fmt.Sprintf("[%s, #%d, mul vl]", base, offset)
						if offset < 0 {
							memory.OffRaw = fmt.Sprintf("-VL*%d", -offset)
						} else if offset > 0 {
							memory.OffRaw = fmt.Sprintf("VL*%d", offset)
						}
					}
					lines = append(lines, form.assembly(fields[2], fields[1], address))
					list := Operand{Kind: OpRegList}
					for i := 0; i < form.count; i++ {
						list.RegList = append(list.RegList, Reg(fmt.Sprintf("Z%d.%s", (fields[2]+i)%32, strings.ToUpper(form.width))))
					}
					mode := ""
					if form.load {
						mode = ".Z"
					}
					predicate := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d%s", fields[1], mode))}
					args := []Operand{list, predicate, {Kind: OpMem, Mem: memory}}
					if form.load {
						args[0], args[2] = args[2], args[0]
					}
					wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(form.op)), Args: args})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		got, ok := decodeARM64RawSVEStructuredMemory(word)
		want := wants[i]
		if !ok || got.Op != want.Op || fmt.Sprint(got.Args) != fmt.Sprint(want.Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, want)
		}
	}
	for _, form := range arm64RawSVEStructuredCases() {
		word := assembleARM64LLVMWords(t, []string{form.assembly(0, 0, fmt.Sprintf("[x0, x30, lsl #%d]", form.shift))}, "+sve2p1")[0]
		word |= 31 << 16
		if got, ok := decodeARM64RawSVEStructuredMemory(word); ok {
			t.Errorf("reserved Rm=31 word %#08x decoded as %+v", word, got)
		}
	}
	for _, word := range []uint32{0xa400c000, 0xe410e000, 0xa410e000} {
		if got, ok := decodeARM64RawSVEStructuredMemory(word); ok {
			t.Errorf("neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
