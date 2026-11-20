package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeRawFP16ScalarMove(opcode, low, upper, dst, mask int, zero bool, length byte) []byte {
	code := encodeRawScalarMove(true, 2, opcode, low, upper, dst, mask, zero)
	code[1] = code[1]&^byte(15) | 5
	code[3] = code[3]&^byte(0x60) | length<<5
	return code
}

func TestDecodeRawFP16ScalarMoveGoATReproduction(t *testing.T) {
	for _, code := range [][]byte{
		// VMOVSH (DI)(CX*2), X0 and VMOVSH X0, (DX)(CX*2)
		// from go-highway's GoAT output.
		{0x62, 0xf5, 0x7e, 0x08, 0x10, 0x04, 0x4f},
		{0x62, 0xf5, 0x7e, 0x08, 0x11, 0x04, 0x4a},
		// A complete add/store group, not just a standalone move.
		{0x62, 0xf5, 0x7e, 0x08, 0x58, 0x04, 0x4e,
			0x62, 0xf5, 0x7e, 0x08, 0x11, 0x04, 0x4a},
	} {
		decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "GoAT VMOVSH", map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		move := decoded[len(decoded)-1]
		if move.Op != "VMOVSH" || !move.x86Encoded {
			t.Fatalf("decoded %#v, want final raw VMOVSH", decoded)
		}
	}
}

func TestDecodeRawFP16ScalarMoveCompleteForms(t *testing.T) {
	for _, opcode := range []int{0x10, 0x11} {
		for length := byte(0); length < 4; length++ {
			for _, registers := range [][3]int{{0, 1, 2}, {7, 8, 15}, {16, 23, 31}} {
				for _, mask := range []int{0, 1, 7} {
					for _, zero := range []bool{false, true} {
						if mask == 0 && zero {
							continue
						}
						low, upper, dst := registers[0], registers[1], registers[2]
						code := encodeRawFP16ScalarMove(opcode, low, upper, dst, mask, zero, length)
						got, size, ok, err := decodedX86ScalarMoveInstruction(code, 64)
						wantOp := Op("VMOVSH")
						if zero {
							wantOp += ".Z"
						}
						want := []Operand{
							{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", low))},
							{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", upper))},
						}
						if mask != 0 {
							want = append(want, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
						}
						want = append(want, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", dst))})
						if err != nil || !ok || size != len(code) || got.Op != wantOp ||
							!got.x86Encoded || !reflect.DeepEqual(got.Args, want) {
							t.Fatalf("%x: got %+v, size=%d, ok=%v, err=%v; want %s %+v", code, got, size, ok, err, wantOp, want)
						}
					}
				}
			}
		}
	}
	for _, opcode := range []byte{0x10, 0x11} {
		for length := byte(0); length < 4; length++ {
			for _, mask := range []byte{0, 1, 7} {
				for _, zero := range []bool{false, true} {
					if opcode == 0x11 && zero || mask == 0 && zero {
						continue
					}
					code := []byte{0x62, 0xf5, 0x7e, 0x08 | length<<5 | mask, opcode, 0x04, 0x4f}
					if zero {
						code[3] |= 0x80
					}
					got, size, ok, err := decodedX86ScalarMoveInstruction(code, 64)
					if err != nil || !ok || size != len(code) || got.Op != "VMOVSH" && got.Op != "VMOVSH.Z" {
						t.Fatalf("%x: got %+v, size=%d, ok=%v, err=%v", code, got, size, ok, err)
					}
					if opcode == 0x10 && (got.Args[0].Kind != OpMem || got.Args[len(got.Args)-1].Reg != "X0") {
						t.Fatalf("%x: wrong memory load %+v", code, got)
					}
					if opcode == 0x11 && (got.Args[0].Reg != "X0" || got.Args[len(got.Args)-1].Kind != OpMem) {
						t.Fatalf("%x: wrong memory store %+v", code, got)
					}
				}
			}
		}
	}
}

func TestDecodeRawFP16ScalarMoveInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"missing-modrm", []byte{0x62, 0xf5, 0x7e, 0x08, 0x10}, 64},
		{"address-override", []byte{0x67, 0x62, 0xf5, 0x7e, 0x08, 0x10, 0xc0}, 64},
		{"wrong-width", []byte{0x62, 0xf5, 0xfe, 0x08, 0x10, 0xc0}, 64},
		{"missing-fixed", []byte{0x62, 0xf5, 0x7a, 0x08, 0x10, 0xc0}, 64},
		{"broadcast", []byte{0x62, 0xf5, 0x7e, 0x18, 0x10, 0xc0}, 64},
		{"zero-k0", []byte{0x62, 0xf5, 0x7e, 0x88, 0x10, 0xc0}, 64},
		{"zero-store", []byte{0x62, 0xf5, 0x7e, 0x89, 0x11, 0x00}, 64},
		{"memory-vvvv", []byte{0x62, 0xf5, 0x76, 0x08, 0x10, 0x00}, 64},
		{"memory-vprime", []byte{0x62, 0xf5, 0x7e, 0x00, 0x10, 0x00}, 64},
		{"386-high-register", []byte{0x62, 0x75, 0x7e, 0x08, 0x10, 0xc0}, 32},
		{"wrong-mode", []byte{0x62, 0xf5, 0x7e, 0x08, 0x10, 0xc0}, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok, err := decodedX86ScalarMoveInstruction(tc.code, tc.mode); !ok || err == nil {
				t.Fatalf("invalid %x: matched=%v, err=%v", tc.code, ok, err)
			}
		})
	}
}

func TestDecodeRawFP16ScalarMoveRIPLiteral(t *testing.T) {
	code := []byte{0x62, 0xf5, 0x7e, 0x08, 0x10, 0x05, 1, 0, 0, 0, 0xc3, 0x00, 0x3c}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VMOVSH RIP literal", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VMOVSH" ||
		decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
		decoded[1].Op != OpRET {
		t.Fatalf("decoded %x as %#v, want source-local FP16 literal", code, decoded)
	}
}

func TestTranslateRawFP16ScalarMoveLLVM22Targets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawFP16ScalarMove(SB),4,$0-0\n")
	for _, code := range [][]byte{
		{0x62, 0xf5, 0x7e, 0x08, 0x10, 0x04, 0x4f},
		{0x62, 0xf5, 0x7e, 0x08, 0x11, 0x04, 0x4f},
		encodeRawFP16ScalarMove(0x10, 1, 2, 3, 7, true, 3),
		encodeRawFP16ScalarMove(0x11, 4, 5, 6, 1, false, 1),
	} {
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
		}
	}
	source.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawFP16ScalarMove": {Name: "rawFP16ScalarMove", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "load i16") || !strings.Contains(ir, "store i16") {
				t.Fatalf("missing scalar FP16 memory operation:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "raw-fp16-scalar-move.ll", "raw-fp16-scalar-move.o", ir)
		})
	}
}

func TestTranslateRawFP16ScalarMove386LLVM22Targets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawFP16ScalarMove386(SB),4,$0-0\n")
	for _, code := range [][]byte{
		{0x62, 0xf5, 0x7e, 0x08, 0x10, 0x04, 0x4f},
		{0x62, 0xf5, 0x7e, 0x09, 0x11, 0x04, 0x4f},
		encodeRawFP16ScalarMove(0x10, 1, 2, 3, 1, true, 2),
	} {
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
		}
	}
	source.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "386", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "386", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawFP16ScalarMove386": {Name: "rawFP16ScalarMove386", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-fp16-scalar-move386.ll", "raw-fp16-scalar-move386.o", ir)
		})
	}
}
