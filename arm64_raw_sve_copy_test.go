package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func arm64RawSVECopyForms() []string {
	var lines []string
	for _, width := range []string{"b", "h", "s", "d"} {
		for _, mode := range []string{"m", "z"} {
			for _, value := range []int{-128, -1, 0, 127} {
				lines = append(lines, fmt.Sprintf("cpy z31.%s, p15/%s, #%d", width, mode, value))
				if width != "b" {
					lines = append(lines, fmt.Sprintf("cpy z31.%s, p15/%s, #%d, lsl #8", width, mode, value))
				}
			}
		}
		gp, sp := "w30", "wsp"
		if width == "d" {
			gp, sp = "x30", "sp"
		}
		lines = append(lines, fmt.Sprintf("cpy z31.%s, p7/m, %s", width, gp),
			fmt.Sprintf("cpy z31.%s, p7/m, %s", width, sp),
			fmt.Sprintf("cpy z31.%s, p7/m, %s30", width, width))
	}
	return lines
}

func TestARM64RawSVECopyOperandFields(t *testing.T) {
	lines := arm64RawSVECopyForms()
	for register := 0; register < 32; register++ {
		gp := fmt.Sprintf("x%d", register)
		if register == 31 {
			gp = "sp"
		}
		lines = append(lines, fmt.Sprintf("cpy z%d.d, p%d/m, %s", register, register%8, gp),
			fmt.Sprintf("cpy z%d.s, p%d/m, s%d", register, register%8, register),
			fmt.Sprintf("cpy z%d.h, p%d/z, #-128, lsl #8", register, register%16))
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVECopy(word)
		if !ok || len(got.Args) != 3 {
			t.Fatalf("%s: decoded %#08x as %+v, %v", lines[i], word, got, ok)
		}
		fields := strings.Fields(strings.ReplaceAll(strings.ToUpper(lines[i]), ",", ""))
		predicate := strings.ReplaceAll(fields[2], "/", ".")
		if got.Args[1].Reg != Reg(predicate) || got.Args[2].Reg != Reg(fields[1]) {
			t.Errorf("%s: wrong predicate/destination: %+v", lines[i], got)
		}
		value := fields[3]
		wantOp := Op("ZCPY")
		if value[0] == '#' {
			immediate, err := strconv.ParseInt(value[1:], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if len(fields) > 4 {
				immediate <<= 8
			}
			if got.Args[0].Kind != OpImm || got.Args[0].Imm != immediate {
				t.Errorf("%s: wrong immediate: %+v", lines[i], got)
			}
		} else {
			register := "R" + value[1:]
			if strings.Contains("BHSD", value[:1]) && value != "SP" {
				wantOp = Op("ZCPY" + value[:1])
				register = "V" + value[1:]
			} else {
				if value[0] == 'W' {
					wantOp = "ZCPYW"
				}
				if value == "SP" || value == "WSP" {
					register = "RSP"
				}
			}
			if got.Args[0].Kind != OpReg || got.Args[0].Reg != Reg(register) {
				t.Errorf("%s: wrong scalar: %+v", lines[i], got)
			}
		}
		if got.Op != wantOp {
			t.Errorf("%s: opcode %s, want %s", lines[i], got.Op, wantOp)
		}
	}
	for _, word := range []uint32{0x05102000, 0x05106000, 0x05108000, 0x05280000, 0x0520a000} {
		if got, ok := decodeARM64RawSVECopy(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}

func TestARM64RawSVECopyCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawcopy(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, arm64RawSVECopyForms(), "+sve") {
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
				Sigs: map[string]FuncSig{"rawcopy": {Name: "rawcopy", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawcopy.ll", "rawcopy.o", ir)
		})
	}
}
