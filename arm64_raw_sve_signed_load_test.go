package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawSVELoadCase struct {
	memorySize  int
	elementSize int
	kind        string
	extension   string
	scaled      bool
}

func arm64RawSVESignedLoadCases() []arm64RawSVELoadCase {
	var forms []arm64RawSVELoadCase
	for memory := 0; memory < 3; memory++ {
		for element := memory + 1; element < 4; element++ {
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

func (form arm64RawSVELoadCase) assembly(dst, pred, base, index, offset int) string {
	return form.loadAssembly(true, dst, pred, base, index, offset)
}

func (form arm64RawSVELoadCase) loadAssembly(signed bool, dst, pred, base, index, offset int) string {
	baseName := fmt.Sprintf("x%d", base)
	if base == 31 {
		baseName = "sp"
	}
	width := "bhsd"[form.elementSize]
	address := ""
	switch form.kind {
	case "immediate":
		address = fmt.Sprintf("[%s, #%d, mul vl]", baseName, offset)
	case "register":
		shift := ""
		if form.memorySize > 0 {
			shift = fmt.Sprintf(", lsl #%d", form.memorySize)
		}
		address = fmt.Sprintf("[%s, x%d%s]", baseName, index, shift)
	case "offset":
		extension := form.extension
		if form.scaled {
			if extension == "" {
				extension = "lsl"
			}
			extension += fmt.Sprintf(" #%d", form.memorySize)
		}
		if extension != "" {
			extension = ", " + extension
		}
		address = fmt.Sprintf("[%s, z%d.%c%s]", baseName, index, width, extension)
	case "base":
		address = fmt.Sprintf("[z%d.%c, #%d]", base, width, offset<<form.memorySize)
	}
	op := "ld1"
	if signed {
		op += "s"
	}
	return fmt.Sprintf("%s%c { z%d.%c }, p%d/z, %s", op, "bhwd"[form.memorySize], dst, width, pred, address)
}

func TestARM64RawSVESignedLoadCompleteFormats(t *testing.T) {
	forms := arm64RawSVESignedLoadCases()
	if len(forms) != 38 {
		t.Fatalf("signed-load grammar has %d forms, want 38", len(forms))
	}
	var lines []string
	for _, form := range forms {
		offset := 7
		if form.kind == "base" {
			offset = 31
		}
		lines = append(lines, form.assembly(31, 7, 31, 30, offset))
	}
	var source strings.Builder
	source.WriteString("TEXT rawsignedload(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
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
				Sigs: map[string]FuncSig{"rawsignedload": {Name: "rawsignedload", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawsignedload.ll", "rawsignedload.o", ir)
		})
	}
}

func TestARM64RawSVESignedLoadOperandFields(t *testing.T) {
	testARM64RawSVELoadOperandFields(t, arm64RawSVESignedLoadCases(), true, decodeARM64RawSVESignedLoad)
	for _, word := range []uint32{0xa4a0a000, 0xc4a0c000, 0xc440a000, 0x8420a000, 0x84a02000} {
		if got, ok := decodeARM64RawSVESignedLoad(word); ok {
			t.Errorf("unsigned/first-fault/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}

func testARM64RawSVELoadOperandFields(t *testing.T, forms []arm64RawSVELoadCase, signed bool, decode func(uint32) (Instr, bool)) {
	t.Helper()
	var lines []string
	var wants []Instr
	var reserved []int
	for _, form := range forms {
		limits := []int{32, 8, 32, 32, 1}
		if form.kind == "register" {
			limits[3] = 31
		} else if form.kind == "immediate" {
			limits[3], limits[4] = 1, 16
		} else if form.kind == "base" {
			limits[3], limits[4] = 1, 32
		}
		for field, limit := range limits {
			for value := 0; value < limit; value++ {
				fields := [5]int{31, 7, 31, limits[3] - 1, limits[4] - 1}
				fields[field] = value
				dst, pred, base, index, offset := fields[0], fields[1], fields[2], fields[3], fields[4]
				if form.kind == "immediate" {
					offset -= 8
				}
				lines = append(lines, form.loadAssembly(signed, dst, pred, base, index, offset))
				memory := MemRef{Base: Reg(fmt.Sprintf("R%d", base))}
				if base == 31 {
					memory.Base = "RSP"
				}
				width := "BHSD"[form.elementSize]
				switch form.kind {
				case "immediate":
					if offset < 0 {
						memory.OffRaw = fmt.Sprintf("-VL*%d", -offset)
					} else if offset > 0 {
						memory.OffRaw = fmt.Sprintf("VL*%d", offset)
					}
					reserved = append(reserved, len(lines)-1)
				case "register":
					memory.Index, memory.Scale = Reg(fmt.Sprintf("R%d", index)), 1<<form.memorySize
					if form.memorySize == 0 {
						memory.Base, memory.Index = memory.Index, memory.Base
					}
					reserved = append(reserved, len(lines)-1)
				case "offset":
					memory.Index = Reg(fmt.Sprintf("Z%d.%c", index, width))
					memory.IndexExt = ExtendOp(strings.ToUpper(form.extension))
					memory.Scale = 1
					if form.scaled {
						memory.Scale <<= form.memorySize
					}
				case "base":
					memory.Base = Reg(fmt.Sprintf("Z%d.%c", base, width))
					memory.Off = int64(offset) << form.memorySize
				}
				op := "ZLD1"
				if signed {
					op += "S"
				}
				wants = append(wants, Instr{Op: Op(op + string("BHWD"[form.memorySize])), Args: []Operand{
					{Kind: OpMem, Mem: memory},
					{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.Z", pred))},
					{Kind: OpRegList, RegList: []Reg{Reg(fmt.Sprintf("Z%d.%c", dst, width))}},
				}})
			}
		}
	}
	words := assembleARM64LLVMWords(t, lines, "+sve")
	for i, word := range words {
		got, ok := decode(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, i := range reserved {
		word := words[i] | 31<<16
		if got, ok := decode(word); ok {
			t.Errorf("reserved scalar-index/immediate bits in %#08x decoded as %+v", word, got)
		}
	}
}
