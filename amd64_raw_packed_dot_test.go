package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

type x86RawDotOracleShape struct {
	op    Op
	code  byte
	bank  string
	width int
}

var x86RawDotOracleShapes = []x86RawDotOracleShape{
	{"VDPPD", 0x41, "X", 16},
	{"VDPPS", 0x40, "X", 16},
	{"VDPPS", 0x40, "Y", 32},
}

func x86RawDotOracleHeader(shape x86RawDotOracleShape, destination, second, bExt, xExt int, widthIgnored bool) []byte {
	p0 := byte((1-destination/8)<<7 | (1-xExt)<<6 | (1-bExt)<<5 | 3)
	p1 := byte((^second&15)<<3 | 1)
	if shape.width == 32 {
		p1 |= 4
	}
	if widthIgnored {
		p1 |= 0x80
	}
	return []byte{0xc4, p0, p1, shape.code}
}

func x86RawDotOracleInstruction(shape x86RawDotOracleShape, first Operand, second, destination int, immediate byte) Instr {
	return Instr{Op: shape.op, Args: []Operand{
		{Kind: OpImm, Imm: int64(immediate)}, first,
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", shape.bank, second))},
		{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", shape.bank, destination))},
	}}
}

func x86RawDotRequireDecode(t *testing.T, code []byte, mode int, shape x86RawDotOracleShape, want Instr) {
	t.Helper()
	got, length, known, err := decodedX86VEXPackedDotInstruction(code, mode)
	if err != nil || !known || length != len(code) || got.Op != want.Op ||
		!reflect.DeepEqual(got.Args, want.Args) || !got.x86Encoded || got.x86VectorBytes != shape.width {
		t.Fatalf("complete original packed dot %x mode%d: got=%+v length=%d known=%v err=%v want=%+v", code, mode, got, length, known, err, want)
	}
	arch := "amd64"
	if mode == 32 {
		arch = "386"
	}
	if _, known, err := x86PackedReductionProperties(got, arch); !known || err != nil {
		t.Fatalf("exact physical dot did not share complete typed grammar: %+v: %v", got, err)
	}
}

func TestDecodedX86VEXPackedDotCompleteRegistersAndSelectors(t *testing.T) {
	count := 0
	for _, mode := range []int{32, 64} {
		limit := 16
		if mode == 32 {
			limit = 8
		}
		for _, shape := range x86RawDotOracleShapes {
			t.Run(fmt.Sprintf("mode%d/%s/%s", mode, shape.op, shape.bank), func(t *testing.T) {
				for _, widthIgnored := range []bool{false, true} {
					for destination := 0; destination < limit; destination++ {
						for second := 0; second < limit; second++ {
							for first := 0; first < limit; first++ {
								code := x86RawDotOracleHeader(shape, destination, second, first/8, 0, widthIgnored)
								code = append(code, byte(0xc0|(destination&7)<<3|first&7), 0xa5)
								input := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", shape.bank, first))}
								x86RawDotRequireDecode(t, code, mode, shape, x86RawDotOracleInstruction(shape, input, second, destination, 0xa5))
								count++
							}
						}
					}
					// Every imm8 is independent of the register-bank axis. Keep
					// all ignored and meaningful selector bits for both sources.
					for immediate := 0; immediate < 256; immediate++ {
						for _, memory := range []bool{false, true} {
							code := x86RawDotOracleHeader(shape, 2, 1, 0, 0, widthIgnored)
							input := Operand{Kind: OpReg, Reg: Reg(shape.bank + "0")}
							modRM := byte(0xd0)
							if memory {
								input = Operand{Kind: OpMem, Mem: MemRef{Base: BX}}
								modRM = 0x13
							}
							code = append(code, modRM, byte(immediate))
							x86RawDotRequireDecode(t, code, mode, shape, x86RawDotOracleInstruction(shape, input, 1, 2, byte(immediate)))
						}
					}
				}
			})
		}
	}
	if count != 27648 {
		t.Fatal("complete two-mode physical register matrix lost rows", count)
	}
}

func TestDecodedX86VEXPackedDotMemoryPrefixesAndInvalidBoundaries(t *testing.T) {
	registers := []Reg{AX, CX, DX, BX, SP, BP, SI, DI}
	for _, mode := range []int{32, 64} {
		for _, shape := range x86RawDotOracleShapes {
			t.Run(fmt.Sprintf("mode%d/%s/%s", mode, shape.op, shape.bank), func(t *testing.T) {
				for mod := 0; mod < 3; mod++ {
					for rm := 0; rm < 8; rm++ {
						sibLimit := 1
						if rm == 4 {
							sibLimit = 256
						}
						for sib := 0; sib < sibLimit; sib++ {
							if mod == 0 && rm == 5 && mode == 64 {
								continue // Original RIP layout has its separate negative below.
							}
							code := x86RawDotOracleHeader(shape, 2, 1, 0, 0, false)
							code = append(code, byte(mod<<6|2<<3|rm))
							mem := MemRef{Base: registers[rm]}
							absolute := mod == 0 && rm == 5
							if rm == 4 {
								code = append(code, byte(sib))
								mem.Base = registers[sib&7]
								if sib>>3&7 != 4 {
									mem.Index, mem.Scale = registers[sib>>3&7], int64(1<<uint(sib>>6))
								}
								absolute = mod == 0 && sib&7 == 5
							}
							if absolute {
								mem.Base = ""
							}
							switch {
							case mod == 1:
								code = append(code, 0xf9)
								mem.Off = -7
							case mod == 2 || absolute:
								var displacement [4]byte
								binary.LittleEndian.PutUint32(displacement[:], 0x89abcdef)
								code = append(code, displacement[:]...)
								mem.Off = -0x76543211
							}
							code = append(code, 0x5a)
							x86RawDotRequireDecode(t, code, mode, shape,
								x86RawDotOracleInstruction(shape, Operand{Kind: OpMem, Mem: mem}, 1, 2, 0x5a))
						}
					}
				}
			})
		}
	}
	shape := x86RawDotOracleShapes[2]
	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		code := []byte{segment.prefix, 0xc4, 0x03, 0xe5, 0x40, 0x64, 0x88, 0x20, 0xa5}
		input := Operand{Kind: OpMem, Mem: MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: 32}}
		x86RawDotRequireDecode(t, code, 64, shape, x86RawDotOracleInstruction(shape, input, 3, 12, 0xa5))
		if _, _, known, err := decodedX86VEXPackedDotInstruction(code, 32); !known || err == nil {
			t.Fatal("physical mode32 borrowed extended GP/vector banks")
		}
	}
	x86RawDotInvalidBoundaryOracle(t)
}

func x86RawDotInvalidBoundaryOracle(t *testing.T) {
	t.Helper()
	valid := []byte{0xc4, 0xe3, 0x71, 0x41, 0xd0, 0xff}
	for name, code := range map[string][]byte{
		"missing ModRM":  valid[:4],
		"missing imm8":   valid[:5],
		"VDPPD Y":        {0xc4, 0xe3, 0x75, 0x41, 0xd0, 0xff},
		"wrong pp":       {0xc4, 0xe3, 0x70, 0x41, 0xd0, 0xff},
		"missing SIB":    {0xc4, 0xe3, 0x71, 0x41, 0x14},
		"partial disp8":  {0xc4, 0xe3, 0x71, 0x41, 0x53},
		"partial disp32": {0xc4, 0xe3, 0x71, 0x41, 0x93, 1, 2, 3},
		"illegal EVEX":   {0x62, 0xf3, 0x75, 0x08, 0x41, 0xd0, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if got, _, known, err := decodedX86VEXPackedDotInstruction(code, 64); !known || err == nil {
				t.Fatalf("invalid/truncated original bytes %x decoded as %+v known=%v err=%v", code, got, known, err)
			}
		})
	}
	for _, mode := range []int{32, 64} {
		for _, prefix := range []byte{0x66, 0xf2, 0xf3, 0xf0} {
			code := append([]byte{prefix}, valid...)
			if _, _, known, err := decodedX86VEXPackedDotInstruction(code, mode); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("invalid prefix %x mode%d was erased or called Context: known=%v err=%v", code, mode, known, err)
			}
		}
		for _, prefix := range []byte{0x26, 0x2e, 0x36, 0x3e, 0x67} {
			code := append([]byte{prefix}, valid...)
			if _, _, known, err := decodedX86VEXPackedDotInstruction(code, mode); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unbound original physical prefix %x mode%d gained source authority: known=%v err=%v", code, mode, known, err)
			}
		}
	}
	for _, code := range [][]byte{
		{0xc4, 0x63, 0x71, 0x41, 0xd0, 0xff},       // R extension.
		{0xc4, 0xa3, 0x71, 0x41, 0x14, 0x0b, 0xff}, // X extension.
		{0xc4, 0xc3, 0x71, 0x41, 0xd0, 0xff},       // B extension.
		{0xc4, 0xe3, 0x39, 0x41, 0xd0, 0xff},       // vvvv source8.
	} {
		if _, _, known, err := decodedX86VEXPackedDotInstruction(code, 32); !known || err == nil {
			t.Fatalf("mode32 high-bank original bytes %x gained authority", code)
		}
	}
	for rex := byte(0x40); rex <= 0x4f; rex++ {
		if _, _, known, err := decodedX86VEXPackedDotInstruction(append([]byte{rex}, valid...), 64); !known || err == nil {
			t.Fatal("machine-invalid REX+VEX prefix was discarded", rex)
		}
	}
	tooLong := append([]byte{0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64}, valid...)
	if _, _, known, err := decodedX86VEXPackedDotInstruction(tooLong, 64); !known || err == nil {
		t.Fatal("overlong original instruction accepted")
	}
	rip := []byte{0xc4, 0xe3, 0x71, 0x41, 0x15, 1, 2, 3, 4, 0xff}
	if _, _, known, err := decodedX86VEXPackedDotInstruction(rip, 64); !known || err == nil {
		t.Fatal("unbound RIP input gained source-local storage")
	}
	physical, length, known, err := decodedX86VEXPackedDotInstructionWithMemory(rip, 64, x86RawMemoryDecoder{physicalPC: true})
	if !known || err != nil || length != len(rip) || physical.Args[1].Mem.Base != "RIP" {
		t.Fatal("physical native boundary observer lost the complete RIP instruction", physical, length, known, err)
	}
	for _, code := range [][]byte{{0xc4}, {0xc4, 0xe2, 0x71, 0x41, 0xd0, 0xff}, {0xc4, 0xe3, 0x71, 0x42, 0xd0, 0xff}} {
		if _, _, known, err := decodedX86VEXPackedDotInstruction(code, 64); known || err != nil {
			t.Fatalf("unrelated opcode/map %x was claimed by dot family", code)
		}
	}
}
