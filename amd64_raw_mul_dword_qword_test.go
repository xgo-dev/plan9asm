package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86RawDwordToQwordMultiplyReportedEncoding(t *testing.T) {
	const source = `
TEXT rawVPMULUDQ(SB),$0-0
	BYTE $0xc5
	BYTE $0xfd
	BYTE $0xf4
	BYTE $0xc2
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
		{goarch: "386", triple: "i686-unknown-linux-gnu"},
		{goarch: "386", triple: "i686-pc-windows-msvc"},
		{goarch: "amd64", triple: "x86_64-apple-darwin"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawVPMULUDQ": {Name: "rawVPMULUDQ", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-vpmuludq.ll", "raw-vpmuludq.o", ir)
		})
	}
}

func TestX86RawDwordToQwordMultiplyCompleteVEXRegisterFields(t *testing.T) {
	for _, family := range []struct {
		name   string
		mapID  byte
		opcode byte
	}{
		{name: "VPMULUDQ", mapID: 1, opcode: 0xf4},
		{name: "VPMULDQ", mapID: 2, opcode: 0x28},
	} {
		for _, width := range []struct {
			prefix string
			l      byte
		}{
			{prefix: "X", l: 0},
			{prefix: "Y", l: 1},
		} {
			for first := 0; first < 16; first++ {
				for second := 0; second < 16; second++ {
					for destination := 0; destination < 16; destination++ {
						p0 := byte((^destination>>3)&1)<<7 | 1<<6 | byte((^first>>3)&1)<<5 | family.mapID
						p1 := byte((^second)&15)<<3 | width.l<<2 | 1
						modRM := byte(0xc0 | destination&7<<3 | first&7)
						encoding := []byte{0xc4, p0, p1, family.opcode, modRM}
						instruction, length, ok, err := decodedX86DwordToQwordMultiplyInstruction(encoding, 64)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("%s %s registers %d,%d,%d: ok=%v length=%d err=%v", family.name, width.prefix, first, second, destination, ok, length, err)
						}
						want := []Reg{
							Reg(fmt.Sprintf("%s%d", width.prefix, first)),
							Reg(fmt.Sprintf("%s%d", width.prefix, second)),
							Reg(fmt.Sprintf("%s%d", width.prefix, destination)),
						}
						if instruction.Op != Op(family.name) || len(instruction.Args) != len(want) {
							t.Fatalf("encoding %x decoded as %#v", encoding, instruction)
						}
						for index := range want {
							if instruction.Args[index].Kind != OpReg || instruction.Args[index].Reg != want[index] {
								t.Fatalf("encoding %x arg %d = %#v, want %s", encoding, index, instruction.Args[index], want[index])
							}
						}
					}
				}
			}
		}
	}
}

func TestX86RawDwordToQwordMultiplyCompleteEVEXRegisterFields(t *testing.T) {
	for _, family := range []struct {
		name   string
		mapID  byte
		opcode byte
	}{
		{name: "VPMULUDQ", mapID: 1, opcode: 0xf4},
		{name: "VPMULDQ", mapID: 2, opcode: 0x28},
	} {
		for _, width := range []struct {
			prefix string
			ll     byte
		}{
			{prefix: "X", ll: 0},
			{prefix: "Y", ll: 1},
			{prefix: "Z", ll: 2},
		} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						p0 := byte((^destination>>3)&1)<<7 | byte((^first>>4)&1)<<6 | byte((^first>>3)&1)<<5 | byte((^destination>>4)&1)<<4 | family.mapID
						p1 := byte(0x85 | ((^second)&15)<<3)
						p2 := width.ll<<5 | byte((^second>>4)&1)<<3 | 1
						modRM := byte(0xc0 | destination&7<<3 | first&7)
						encoding := []byte{0x62, p0, p1, p2, family.opcode, modRM}
						instruction, length, ok, err := decodedX86DwordToQwordMultiplyInstruction(encoding, 64)
						if !ok || err != nil || length != len(encoding) {
							t.Fatalf("%s %s registers %d,%d,%d: ok=%v length=%d err=%v", family.name, width.prefix, first, second, destination, ok, length, err)
						}
						want := []Reg{
							Reg(fmt.Sprintf("%s%d", width.prefix, first)),
							Reg(fmt.Sprintf("%s%d", width.prefix, second)),
							"K1",
							Reg(fmt.Sprintf("%s%d", width.prefix, destination)),
						}
						if instruction.Op != Op(family.name) || len(instruction.Args) != len(want) {
							t.Fatalf("encoding %x decoded as %#v", encoding, instruction)
						}
						for index := range want {
							if instruction.Args[index].Kind != OpReg || instruction.Args[index].Reg != want[index] {
								t.Fatalf("encoding %x arg %d = %#v, want %s", encoding, index, instruction.Args[index], want[index])
							}
						}
					}
				}
			}
		}
	}
}

func TestX86RawDwordToQwordMultiplyMemoryMaskAndBroadcastForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding []byte
		wantOp   Op
		wantArgs int
		wantMem  bool
	}{
		{name: "vex signed base", encoding: []byte{0xc4, 0xe2, 0x31, 0x28, 0x13}, wantOp: "VPMULDQ", wantArgs: 3, wantMem: true},
		{name: "vex unsigned extended base", encoding: []byte{0xc4, 0xc1, 0x31, 0xf4, 0x13}, wantOp: "VPMULUDQ", wantArgs: 3, wantMem: true},
		{name: "evex masked memory", encoding: []byte{0x62, 0x71, 0xfd, 0x0e, 0xf4, 0xbc, 0x75, 0xef, 0xff, 0xff, 0xff}, wantOp: "VPMULUDQ", wantArgs: 4, wantMem: true},
		{name: "evex broadcast", encoding: []byte{0x62, 0x71, 0xfd, 0x1e, 0xf4, 0xbc, 0x75, 0xef, 0xff, 0xff, 0xff}, wantOp: "VPMULUDQ.BCST", wantArgs: 4, wantMem: true},
		{name: "evex broadcast zero", encoding: []byte{0x62, 0x71, 0xfd, 0x9e, 0xf4, 0xbc, 0x75, 0xef, 0xff, 0xff, 0xff}, wantOp: "VPMULUDQ.BCST.Z", wantArgs: 4, wantMem: true},
		{name: "evex unmasked", encoding: []byte{0x62, 0x31, 0xfd, 0x08, 0xf4, 0xf8}, wantOp: "VPMULUDQ", wantArgs: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86DwordToQwordMultiplyInstruction(test.encoding, 64)
			if !ok || err != nil || length != len(test.encoding) {
				t.Fatalf("encoding %x: ok=%v length=%d err=%v", test.encoding, ok, length, err)
			}
			if instruction.Op != test.wantOp || len(instruction.Args) != test.wantArgs || (instruction.Args[0].Kind == OpMem) != test.wantMem {
				t.Fatalf("encoding %x decoded as %#v", test.encoding, instruction)
			}
		})
	}
}

func TestX86RawDwordToQwordMultiplyRejectsReservedAndUnsafeForms(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     int
		encoding []byte
	}{
		{name: "vex w", mode: 64, encoding: []byte{0xc4, 0xe1, 0xfd, 0xf4, 0xc2}},
		{name: "evex w", mode: 64, encoding: []byte{0x62, 0x31, 0x7d, 0x0e, 0xf4, 0xf8}},
		{name: "evex reserved length", mode: 64, encoding: []byte{0x62, 0x31, 0xfd, 0x6e, 0xf4, 0xf8}},
		{name: "zero without mask", mode: 64, encoding: []byte{0x62, 0x31, 0xfd, 0x88, 0xf4, 0xf8}},
		{name: "broadcast register", mode: 64, encoding: []byte{0x62, 0x31, 0xfd, 0x1e, 0xf4, 0xf8}},
		{name: "address override", mode: 64, encoding: []byte{0x67, 0xc5, 0xfd, 0xf4, 0xc2}},
		{name: "rip relative", mode: 64, encoding: []byte{0xc5, 0xfd, 0xf4, 0x05, 0, 0, 0, 0}},
		{name: "extended 386", mode: 32, encoding: []byte{0xc4, 0x61, 0x79, 0xf4, 0xc0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86DwordToQwordMultiplyInstruction(test.encoding, test.mode)
			if !ok || err == nil {
				t.Fatalf("encoding %x: ok=%v err=%v, want recognized rejection", test.encoding, ok, err)
			}
		})
	}
}
