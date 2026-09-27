package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawRORXReportedEncoding(t *testing.T) {
	const source = `
TEXT rawRORX(SB),$0-0
	BYTE $0xc4
	BYTE $0xe3
	BYTE $0x7b
	BYTE $0xf0
	BYTE $0xe8
	BYTE $0x19
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "386", triple: "i686-pc-windows-msvc"},
		{goarch: "amd64", triple: "x86_64-apple-darwin"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawRORX": {Name: "rawRORX", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, `"target-features"="+bmi2"`) {
				t.Fatalf("raw RORX did not infer BMI2 target feature:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-rorx.ll", "raw-rorx.o", ir)
		})
	}
}

func TestX86RORXGo127CompleteNamedForms(t *testing.T) {
	const source = `
TEXT rorxforms(SB),$0-0
	RORXL $7, (BX), DX
	RORXL $31, R11, R12
	RORXQ $7, 16(BX)(SI*2), DX
	RORXQ $63, R11, R12
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rorxforms": {Name: "rorxforms", Ret: Void}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestX86RORXCompleteGo127FormsAcrossTargets(t *testing.T) {
	registers386 := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
	registersAMD64 := append(append([]string{}, registers386...), "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
	targets := []struct {
		name      string
		goarch    string
		triple    string
		registers []string
	}{
		{name: "386-linux", goarch: "386", triple: "i386-unknown-linux-gnu", registers: registers386},
		{name: "386-windows", goarch: "386", triple: "i686-pc-windows-msvc", registers: registers386},
		{name: "amd64-darwin", goarch: "amd64", triple: "x86_64-apple-darwin", registers: registersAMD64},
		{name: "amd64-linux", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", registers: registersAMD64},
		{name: "amd64-windows", goarch: "amd64", triple: "x86_64-pc-windows-msvc", registers: registersAMD64},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rorxall(SB),$0-0\n")
			for _, width := range []string{"L", "Q"} {
				for index, sourceRegister := range target.registers {
					destination := target.registers[(index+3)%len(target.registers)]
					fmt.Fprintf(&source, "\tRORX%s $%d, %s, %s\n", width, index*17&255, sourceRegister, destination)
				}
				fmt.Fprintf(&source, "\tRORX%s $-1, 8(AX), DX\n", width)
				fmt.Fprintf(&source, "\tRORX%s $63, 16(AX)(CX*4), BX\n", width)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rorxall": {Name: "rorxall", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, `"target-features"="+bmi2"`) {
				t.Fatalf("RORX family did not infer BMI2 target feature:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "rorx-family.ll", "rorx-family.o", ir)
		})
	}
}

func TestX86RawRORXCompleteRegisterFields(t *testing.T) {
	for _, mode := range []int{32, 64} {
		registerCount := 8
		if mode == 64 {
			registerCount = 16
		}
		for _, width64 := range []bool{false, true} {
			for source := 0; source < registerCount; source++ {
				for destination := 0; destination < registerCount; destination++ {
					for _, immediate := range []byte{0, 1, 31, 32, 63, 255} {
						p0 := byte((^destination>>3)&1)<<7 | 1<<6 | byte((^source>>3)&1)<<5 | 3
						p1 := byte(0x7b)
						if width64 {
							p1 |= 0x80
						}
						modRM := byte(0xc0 | destination&7<<3 | source&7)
						encoding := []byte{0xc4, p0, p1, 0xf0, modRM, immediate}
						instruction, length, ok, err := decodedX86RORXInstruction(encoding, mode)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("mode=%d width64=%v source=%d destination=%d immediate=%d: ok=%v length=%d err=%v", mode, width64, source, destination, immediate, ok, length, err)
						}
						wantOp := Op("RORXL")
						if width64 && mode == 64 {
							wantOp = "RORXQ"
						}
						wantSource, _ := decodedX86GeneralRegister(source)
						wantDestination, _ := decodedX86GeneralRegister(destination)
						if instruction.Op != wantOp || len(instruction.Args) != 3 || instruction.Args[0].Imm != int64(immediate) || instruction.Args[1].Reg != wantSource || instruction.Args[2].Reg != wantDestination {
							t.Fatalf("encoding %x decoded as %#v", encoding, instruction)
						}
					}
				}
			}
		}
	}
}

func TestX86RawRORXMemoryForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding []byte
	}{
		{name: "direct", encoding: []byte{0xc4, 0xe3, 0x7b, 0xf0, 0x13, 0x07}},
		{name: "extended base", encoding: []byte{0xc4, 0xc3, 0x7b, 0xf0, 0x13, 0x07}},
		{name: "sib disp8", encoding: []byte{0xc4, 0x83, 0xfb, 0xf0, 0x54, 0x88, 0x10, 0xff}},
		{name: "base less", encoding: []byte{0xc4, 0xe3, 0x7b, 0xf0, 0x14, 0x25, 0x78, 0x56, 0x34, 0x12, 0x1f}},
		{name: "segment", encoding: []byte{0x64, 0xc4, 0xe3, 0x7b, 0xf0, 0x54, 0x48, 0x08, 0x1f}},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86RORXInstruction(test.encoding, 64)
			if !ok || err != nil || length != len(test.encoding) || len(instruction.Args) != 3 || instruction.Args[1].Kind != OpMem {
				t.Fatalf("encoding %x: instruction=%#v ok=%v length=%d err=%v", test.encoding, instruction, ok, length, err)
			}
		})
	}
}

func TestX86RawRORXRejectsReservedAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
	}{
		{name: "vex l", mode: 64, encoding: []byte{0xc4, 0xe3, 0x7f, 0xf0, 0xd2, 0x07}},
		{name: "vex pp", mode: 64, encoding: []byte{0xc4, 0xe3, 0x79, 0xf0, 0xd2, 0x07}},
		{name: "vex vvvv", mode: 64, encoding: []byte{0xc4, 0xe3, 0x73, 0xf0, 0xd2, 0x07}},
		{name: "missing modrm", mode: 64, encoding: []byte{0xc4, 0xe3, 0x7b, 0xf0}},
		{name: "missing immediate", mode: 64, encoding: []byte{0xc4, 0xe3, 0x7b, 0xf0, 0xd2}},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0xc4, 0xe3, 0x7b, 0xf0, 0xd2, 0x07}},
		{name: "rip relative", mode: 64, encoding: []byte{0xc4, 0xe3, 0x7b, 0xf0, 0x15, 0, 0, 0, 0, 0x07}},
		{name: "extended source 386", mode: 32, encoding: []byte{0xc4, 0xc3, 0x7b, 0xf0, 0xc0, 0x07}},
		{name: "extended destination 386", mode: 32, encoding: []byte{0xc4, 0x63, 0x7b, 0xf0, 0xc0, 0x07}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86RORXInstruction(test.encoding, test.mode)
			if !ok || err == nil {
				t.Fatalf("encoding %x: ok=%v err=%v, want recognized rejection", test.encoding, ok, err)
			}
		})
	}
}

func TestX86RORXGo127ModeOracle(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
		want        bool
	}{
		{goarch: "386", instruction: "RORXL $7, (BX), DX", want: true},
		{goarch: "386", instruction: "RORXQ $7, (BX), DX", want: true},
		{goarch: "386", instruction: "RORXL $7, R8, DX", want: false},
		{goarch: "amd64", instruction: "RORXQ $7, R8, R15", want: true},
	} {
		t.Run(fmt.Sprintf("%s/%s", test.goarch, test.instruction), func(t *testing.T) {
			requireX86GoAssemblerResult(t, test.goarch, "TEXT oracle(SB),$0-0\n\t"+test.instruction+"\n\tRET\n", test.want)
		})
	}
}
