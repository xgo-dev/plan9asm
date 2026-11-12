package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Classic SVE unsigned loads share the signed-load address axes but also
// accept natural-width destinations. Newer Q and PN forms are tested below.
func arm64RawSVEUnsignedLoadCases() []arm64RawSVELoadCase {
	var forms []arm64RawSVELoadCase
	for memory := 0; memory < 4; memory++ {
		for element := memory; element < 4; element++ {
			for _, kind := range []string{"immediate", "register", "offset", "base"} {
				if element < 2 && (kind == "offset" || kind == "base") {
					continue
				}
				form := arm64RawSVELoadCase{memorySize: memory, elementSize: element, kind: kind}
				if kind != "offset" {
					forms = append(forms, form)
					continue
				}
				for _, extension := range []string{"", "uxtw", "sxtw"} {
					if element == 2 && extension == "" {
						continue
					}
					form.extension = extension
					for _, scaled := range []bool{false, true} {
						if memory == 0 && scaled {
							continue
						}
						form.scaled = scaled
						forms = append(forms, form)
					}
				}
			}
		}
	}
	return forms
}

func (form arm64RawSVELoadCase) unsignedAssembly(dst, pred, base, index, offset int) string {
	return form.loadAssembly(false, dst, pred, base, index, offset)
}

func arm64RawSVEUnsignedExtendedLoadAssembly() []string {
	var lines []string
	for memory := 0; memory < 4; memory++ {
		for _, count := range []int{2, 4} {
			width := "bhsd"[memory]
			registers := fmt.Sprintf("{ z28.%c-z%d.%c }", width, 28+count-1, width)
			lines = append(lines,
				fmt.Sprintf("ld1%c %s, pn15/z, [sp, x30, lsl #%d]", "bhwd"[memory], registers, memory),
				fmt.Sprintf("ld1%c %s, pn15/z, [sp, #%d, mul vl]", "bhwd"[memory], registers, -8*count))
		}
	}
	for memory := 2; memory < 4; memory++ {
		lines = append(lines,
			fmt.Sprintf("ld1%c { z31.q }, p7/z, [sp, x30, lsl #%d]", "bhwd"[memory], memory),
			fmt.Sprintf("ld1%c { z31.q }, p7/z, [sp, #-8, mul vl]", "bhwd"[memory]))
	}
	return append(lines, "ld1q { z31.q }, p7/z, [z30.d, x29]")
}

func TestARM64RawSVEUnsignedLoadCompleteFormats(t *testing.T) {
	forms := arm64RawSVEUnsignedLoadCases()
	if len(forms) != 58 {
		t.Fatalf("unsigned-load grammar has %d classic forms, want 58", len(forms))
	}
	var lines []string
	for _, form := range forms {
		lines = append(lines, form.unsignedAssembly(31, 7, 31, 30, 7))
	}
	lines = append(lines, arm64RawSVEUnsignedExtendedLoadAssembly()...)
	var source strings.Builder
	source.WriteString("TEXT rawunsignedload(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawunsignedload": {Name: "rawunsignedload", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawunsignedload.ll", "rawunsignedload.o", ir)
		})
	}
}

func TestARM64RawSVEUnsignedLoadOperandFields(t *testing.T) {
	testARM64RawSVELoadOperandFields(t, arm64RawSVEUnsignedLoadCases(), false, decodeARM64RawSVEUnsignedLoad)
	for _, word := range []uint32{0xa4006000, 0xc4008000, 0x84000000, 0xc440e000, 0x8420a000} {
		if got, ok := decodeARM64RawSVEUnsignedLoad(word); ok {
			t.Errorf("signed/first-fault/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}

func TestARM64RawSVEUnsignedLoadReservedDoesNotFallThrough(t *testing.T) {
	var lines []string
	for _, form := range arm64RawSVEUnsignedLoadCases() {
		if form.kind != "immediate" && form.kind != "register" {
			continue
		}
		lines = append(lines, form.unsignedAssembly(0, 0, 0, 0, 0))
	}
	for _, validWord := range assembleARM64LLVMWords(t, lines, "+sve") {
		word := validWord | 31<<16
		file, err := Parse(ArchARM64, fmt.Sprintf("TEXT reservedload(SB),$0-0\nWORD $%#08x\nRET\n", word))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"reservedload": {Name: "reservedload", Ret: Void}}})
		if err == nil {
			t.Errorf("reserved load %#08x fell through to a legacy decoder", word)
		}
	}
}

func TestARM64RawSVEUnsignedExtendedLoadFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for size := 0; size < 4; size++ {
		for _, count := range []int{2, 4} {
			for _, immediate := range []bool{false, true} {
				limits := [4]int{32 / count, 8, 32, 32}
				if immediate {
					limits[3] = 16
				}
				for field, limit := range limits {
					for value := 0; value < limit; value++ {
						fields := [4]int{0, 7, 31, 0}
						fields[field] = value
						dst, predicate, base, index := fields[0]*count, fields[1]+8, fields[2], fields[3]
						baseName, goBase := fmt.Sprintf("x%d", base), Reg(fmt.Sprintf("R%d", base))
						if base == 31 {
							baseName, goBase = "sp", "RSP"
						}
						memory := MemRef{Base: goBase}
						address := ""
						if immediate {
							offset := (index - 8) * count
							address = fmt.Sprintf("[%s, #%d, mul vl]", baseName, offset)
							if offset < 0 {
								memory.OffRaw = fmt.Sprintf("-VL*%d", -offset)
							} else if offset > 0 {
								memory.OffRaw = fmt.Sprintf("VL*%d", offset)
							}
						} else {
							indexName := fmt.Sprintf("x%d", index)
							if index == 31 {
								indexName = "xzr"
							} else {
								memory.Index, memory.Scale = Reg(fmt.Sprintf("R%d", index)), 1<<size
								if size == 0 {
									memory.Base, memory.Index = memory.Index, memory.Base
								}
							}
							address = fmt.Sprintf("[%s, %s, lsl #%d]", baseName, indexName, size)
						}
						lines = append(lines, fmt.Sprintf("ld1%c {z%d.%c-z%d.%c}, pn%d/z, %s",
							"bhwd"[size], dst, "bhsd"[size], dst+count-1, "bhsd"[size], predicate, address))
						registers := make([]Reg, count)
						for i := range registers {
							registers[i] = Reg(fmt.Sprintf("Z%d.%c", dst+i, "BHSD"[size]))
						}
						wants = append(wants, Instr{Op: Op("ZLD1" + string("BHWD"[size])), Args: []Operand{
							{Kind: OpMem, Mem: memory}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("PN%d.Z", predicate))},
							{Kind: OpRegList, RegList: registers},
						}})
					}
				}
			}
		}
	}
	for size := 2; size < 4; size++ {
		for _, immediate := range []bool{false, true} {
			limits := [4]int{32, 8, 32, 31}
			if immediate {
				limits[3] = 16
			}
			for field, limit := range limits {
				for value := 0; value < limit; value++ {
					fields := [4]int{31, 7, 31, 0}
					fields[field] = value
					dst, predicate, base, index := fields[0], fields[1], fields[2], fields[3]
					baseName := fmt.Sprintf("x%d", base)
					memory := MemRef{Base: Reg(fmt.Sprintf("R%d", base))}
					if base == 31 {
						baseName, memory.Base = "sp", "RSP"
					}
					address := ""
					if immediate {
						offset := index - 8
						address = fmt.Sprintf("[%s, #%d, mul vl]", baseName, offset)
						if offset < 0 {
							memory.OffRaw = fmt.Sprintf("-VL*%d", -offset)
						} else if offset > 0 {
							memory.OffRaw = fmt.Sprintf("VL*%d", offset)
						}
					} else {
						address = fmt.Sprintf("[%s, x%d, lsl #%d]", baseName, index, size)
						memory.Index, memory.Scale = Reg(fmt.Sprintf("R%d", index)), 1<<size
					}
					lines = append(lines, fmt.Sprintf("ld1%c {z%d.q}, p%d/z, %s", "bhwd"[size], dst, predicate, address))
					wants = append(wants, Instr{Op: Op("ZLD1" + string("BHWD"[size])), Args: []Operand{
						{Kind: OpMem, Mem: memory}, {Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", predicate))},
						{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.Q", dst))}},
					}})
				}
			}
		}
	}
	for field, limit := range [4]int{32, 8, 32, 32} {
		for value := 0; value < limit; value++ {
			fields := [4]int{31, 7, 31, 0}
			fields[field] = value
			dst, predicate, base, index := fields[0], fields[1], fields[2], fields[3]
			indexName, goIndex := fmt.Sprintf("x%d", index), Reg(fmt.Sprintf("R%d", index))
			if index == 31 {
				indexName, goIndex = "xzr", ZR
			}
			lines = append(lines, fmt.Sprintf("ld1q {z%d.q}, p%d/z, [z%d.d, %s]", dst, predicate, base, indexName))
			wants = append(wants, Instr{Op: "ZLD1Q", Args: []Operand{
				{Kind: OpMem, Mem: MemRef{Base: goIndex, Index: Reg(fmt.Sprintf("Z%d.D", base)), Scale: 1}},
				{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", predicate))},
				{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.Q", dst))}},
			}})
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		got, ok := decodeARM64RawSVEUnsignedLoad(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0xa0000001, 0xa0008002, 0xa0500000, 0xa500a000, 0xa59f8000} {
		if got, ok := decodeARM64RawSVEUnsignedLoad(word); ok {
			t.Errorf("neighboring/reserved extended load %#08x decoded as %+v", word, got)
		}
	}
}
