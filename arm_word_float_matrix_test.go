package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// These independent fixtures use the eight encodings in Arm DDI0406C.c
// A8.8.306, not the translator's decoder or its typed conversion specification.
type armConversionMatrixForm struct {
	instruction string
	toFloat     bool
	double      bool
	sourceD     int
	targetD     int
	sourceHalf  int
	coreSource  bool
}

func armConversionRawMatrixWord(toFloat, double, unsigned bool, word, floating int) uint32 {
	encoding := uint32(0xeeb80ac0) // VCVT.F32.S32 Sd,Sm.
	source, destination := word, floating
	if !toFloat {
		encoding = 0xeebd0ac0 // VCVT.S32.F32 Sd,Sm.
		source, destination = floating, word
		if unsigned {
			encoding &^= 1 << 16
		}
	} else if unsigned {
		encoding &^= 1 << 7
	}
	if double {
		encoding |= 1 << 8
	}
	if double && !toFloat {
		encoding |= uint32(source)
	} else {
		encoding |= uint32(source/2) | uint32(source%2)<<5
	}
	if double && toFloat {
		encoding |= uint32(destination) << 12
	} else {
		encoding |= uint32(destination/2)<<12 | uint32(destination%2)<<22
	}
	return encoding
}

func armConversionRawMatrixForms() []armConversionMatrixForm {
	var forms []armConversionMatrixForm
	for _, toFloat := range []bool{false, true} {
		for _, double := range []bool{false, true} {
			for _, unsigned := range []bool{false, true} {
				for word := 0; word < 32; word++ {
					// Same physical register (both S halves for F64), and a
					// disjoint register. Every word S and every float S/D occurs.
					for _, disjoint := range []bool{false, true} {
						floating := word
						if double {
							floating /= 2
						}
						if disjoint {
							if double {
								floating = (floating + 7) % 16
							} else {
								floating = (floating + 15) % 32
							}
						}
						form := armConversionMatrixForm{toFloat: toFloat, double: double}
						floatD, floatHalf := floating/2, floating%2
						if double {
							floatD, floatHalf = floating, 0
						}
						form.sourceD, form.sourceHalf, form.targetD = floatD, floatHalf, word/2
						if toFloat {
							form.sourceD, form.sourceHalf, form.targetD = word/2, word%2, floatD
						}
						encoding := armConversionRawMatrixWord(toFloat, double, unsigned, word, floating)
						form.instruction = fmt.Sprintf("WORD $%#x", encoding)
						forms = append(forms, form)
					}
				}
			}
		}
	}
	return forms
}

func armConversionStatusMatrixForms() []armConversionMatrixForm {
	var forms []armConversionMatrixForm
	for _, op := range []string{"MOVFW", "MOVDW", "MOVWF", "MOVWD"} {
		for _, unsigned := range []bool{false, true} {
			for _, core := range []bool{false, true} {
				for _, condition := range []string{"", ".EQ", ".NE"} {
					form := armConversionMatrixForm{
						toFloat: strings.HasPrefix(op, "MOVW"), double: strings.Contains(op, "D"),
						sourceD: 0, targetD: 1,
					}
					source, target, suffix := "F0", "F1", condition
					if unsigned {
						suffix = ".U" + suffix
					}
					if core && form.toFloat {
						source, form.coreSource = "R2", true
					} else if core {
						target = "R2"
					}
					form.instruction = fmt.Sprintf("%s%s %s,%s", op, suffix, source, target)
					forms = append(forms, form)
				}
			}
			// Odd raw S word and F32 endpoints: the word and float widths
			// must be interpreted separately even for a double conversion.
			form := armConversionMatrixForm{
				toFloat: strings.HasPrefix(op, "MOVW"), double: strings.Contains(op, "D"),
				sourceD: 0, targetD: 1, sourceHalf: 1,
			}
			word, floating := 3, 1
			if form.toFloat {
				word, floating = 1, 3
				if form.double {
					floating = 1
				}
			} else if form.double {
				floating, form.sourceHalf = 0, 0
			}
			form.instruction = fmt.Sprintf("WORD $%#x", armConversionRawMatrixWord(form.toFloat, form.double, unsigned, word, floating))
			forms = append(forms, form)
		}
	}
	return forms
}

func armConversionMatrixSource(forms []armConversionMatrixForm) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig, len(forms))
	for index, form := range forms {
		name := fmt.Sprintf("matrix%d", index)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-8
MOVW input+0(FP),R0
MOVW output+4(FP),R1
MOVD 16(R0),F15
MOVD 8(R0),F%d
MOVD 0(R0),F%d
MOVW 24(R0),R2
WORD $0xeef14a10 // VMRS R4,FPSCR: preserve the actual caller state.
MOVW 28(R0),R3
WORD $0xeee13a10 // VMSR FPSCR,R3.
CMP R2,R2
%s
WORD $0xeef13a10 // VMRS R3,FPSCR: observe before restoring it.
WORD $0xeee14a10 // VMSR FPSCR,R4.
MOVD F%d,0(R1)
MOVD F%d,8(R1)
MOVD F15,16(R1)
MOVW R2,24(R1)
MOVW R3,28(R1)
RET
`, name, form.targetD, form.sourceD, form.instruction, form.sourceD, form.targetD)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	return source.String(), sigs
}

func armConversionMatrixInput(form armConversionMatrixForm, bits uint64, control uint32) [8]uint32 {
	input := [8]uint32{0x12345678, 0x87654321, 0x10203040, 0x50607080, 0x11223344, 0x55667788, 0xfedcba98, control}
	if form.coreSource {
		input[6] = uint32(bits)
	} else if form.double && !form.toFloat {
		input[0], input[1] = uint32(bits), uint32(bits>>32)
	} else {
		input[form.sourceHalf] = uint32(bits)
	}
	return input
}

func armConversionStatusMatrixValues(form armConversionMatrixForm) []uint64 {
	if form.toFloat {
		return []uint64{0, 1, 0xffffffff, 0x80000000, 0x7fffffff, 0x00ffffff,
			0x01000000, 0x01000001, 0xfeffffff, 0x80000001, 0xffffff00}
	}
	if !form.double {
		return []uint64{0, 0x80000000, 0x3fc00000, 0xbfc00000, 0x3f000000, 0xbf000000,
			0x4effffff, 0x4f000000, 0xcf000000, 0xcf000001, 0x4f7fffff, 0x4f800000,
			0x7f800000, 0xff800000, 0x7fc12345, 0xffc12345, 0x7f812345, 0xff812345,
			1, 0x80000001, 0x007fffff, 0x807fffff, 0x00800000, 0x80800000}
	}
	return []uint64{0, 0x8000000000000000, 0x3ff8000000000000, 0xbff8000000000000,
		0x3fe0000000000000, 0xbfe0000000000000, 0x41dfffffffc00000, 0x41e0000000000000,
		0xc1e0000000000000, 0xc1e0000000200000, 0x41efffffffe00000, 0x41f0000000000000,
		0x7ff0000000000000, 0xfff0000000000000, 0x7ff8123456789abc, 0xfff8123456789abc,
		0x7ff0123456789abc, 0xfff0123456789abc, 1, 0x8000000000000001,
		0x000fffffffffffff, 0x800fffffffffffff, 0x0010000000000000, 0x8010000000000000}
}

func TestARMWordFloatRawPhysicalEndpointMatrix(t *testing.T) {
	forms := armConversionRawMatrixForms()
	if len(forms) != 8*32*2 {
		t.Fatalf("incomplete eight-opcode / full-S-bank / alias matrix: %d", len(forms))
	}
	seen := make(map[string]bool, len(forms))
	for _, form := range forms {
		if seen[form.instruction] {
			t.Fatalf("duplicate encoding: %s", form.instruction)
		}
		seen[form.instruction] = true
	}
	source, sigs := armConversionMatrixSource(forms)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm-conversion-endpoints.ll", "arm-conversion-endpoints.o", ir)
		})
	}
}

func TestARMWordFloatRawPhysicalMatrixDoesNotGrantSourceSingles(t *testing.T) {
	for single := 0; single < 32; single++ {
		for _, op := range []string{"MOVFW", "MOVDW", "MOVWF", "MOVWD"} {
			for _, pair := range [][2]string{
				{fmt.Sprintf("S%d", single), "F0"}, {"F0", fmt.Sprintf("S%d", single)},
			} {
				body := fmt.Sprintf("%s %s,%s", op, pair[0], pair[1])
				file, err := Parse(ArchARM, "TEXT conversion(SB),4,$0-0\n"+body+"\nRET\n")
				if err != nil {
					continue
				}
				if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf"}); err == nil {
					t.Fatalf("decoder-only S endpoint leaked to named source: %s", body)
				}
			}
		}
	}
}
