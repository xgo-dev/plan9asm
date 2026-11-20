package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func x86RawLEADisplacementEncoding(mode, width, addressBits, shape, scale int, displacement int32) []byte {
	var encoding []byte
	if width == 16 {
		encoding = append(encoding, 0x66)
	}
	if addressBits != mode {
		encoding = append(encoding, 0x67)
	}
	if width == 64 {
		encoding = append(encoding, 0x48)
	}
	encoding = append(encoding, 0x8d)
	if addressBits == 16 {
		// mod=10, reg=CX, r/m=BX+SI; the displacement is physical disp16.
		encoding = append(encoding, 0x88)
		return binary.LittleEndian.AppendUint16(encoding, uint16(displacement))
	}
	switch shape {
	case 0: // AX + disp32
		encoding = append(encoding, 0x88)
	case 1: // AX + BX*scale + disp32
		encoding = append(encoding, 0x8c, byte(scale<<6|3<<3))
	case 2: // AX*scale + disp32; no base is encoded.
		encoding = append(encoding, 0x0c, byte(scale<<6|5))
	case 3: // disp32; SIB has neither a base nor an index.
		encoding = append(encoding, 0x0c, 0x25)
	default:
		panic("unknown raw LEA displacement fixture shape")
	}
	return binary.LittleEndian.AppendUint32(encoding, uint32(displacement))
}

func x86RawDisplacementDirectives(encoding []byte) string {
	var source strings.Builder
	for _, value := range encoding {
		fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
	}
	return source.String()
}

func TestX86RawDisplacementRetainsPhysicalSignedField(t *testing.T) {
	// Intel SDM Vol. 2, section 2.2.1: ModR/M/SIB disp32 is sign-extended
	// in a 64-bit effective address. x/arch v0.14 exposes it as uint32.
	for _, mode := range []int{32, 64} {
		for _, shape := range []int{0, 1, 2, 3} {
			for _, displacement := range []int32{-1 << 31, -129, -128, -64, -1, 0, 127, 128, 1<<31 - 1} {
				t.Run(fmt.Sprintf("mode%d/shape%d/%d", mode, shape, displacement), func(t *testing.T) {
					encoding := x86RawLEADisplacementEncoding(mode, mode, mode, shape, 2, displacement)
					inst, err := x86asm.Decode(encoding, mode)
					if err != nil || inst.Len != len(encoding) || inst.Op != x86asm.LEA {
						t.Fatalf("physical LEA decode: %+v, %v", inst, err)
					}
					syntax, err := decodedX86GoSyntax(inst, encoding)
					if err != nil {
						t.Fatal(err)
					}
					instruction := x86RawDisplacementDecodedLEA(t, mode, encoding)
					if got := instruction.Args[0].Mem.Off; got != int64(displacement) {
						t.Fatalf("physical signed disp32 became %d, want %d: %q", got, displacement, syntax)
					}
				})
			}
		}
	}
	// The independently discovered go-cv-simd bytes use REX.R/X and no base.
	encoding := []byte{0x4e, 0x8d, 0x04, 0x9d, 0xc0, 0xff, 0xff, 0xff}
	inst, err := x86asm.Decode(encoding, 64)
	if err != nil {
		t.Fatal(err)
	}
	if syntax, err := decodedX86GoSyntax(inst, encoding); err != nil || syntax != "LEAQ -0x40(R11*4), R8" {
		t.Fatalf("original no-base extended-index LEA: %q, %v", syntax, err)
	}
}

func x86RawDisplacementDecodedLEA(t *testing.T, mode int, encoding []byte) Instr {
	t.Helper()
	arch := "amd64"
	if mode == 32 {
		arch = "386"
	}
	file, err := Parse(ArchAMD64, "TEXT raw(SB),4,$0-0\n"+x86RawDisplacementDirectives(encoding)+"RET\n")
	if err != nil {
		t.Fatal(err)
	}
	function, err := decodeX86RawDirectives(file.Funcs[0], arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, instruction := range function.Instrs {
		if strings.HasPrefix(string(instruction.Op), "LEA") {
			if len(instruction.Args) != 2 || instruction.Args[0].Kind != OpMem {
				t.Fatalf("lost physical LEA memory operand: %+v", instruction)
			}
			return instruction
		}
	}
	t.Fatal("decoded raw source lost its LEA instruction")
	return Instr{}
}

func TestX86RawDisplacementDoesNotSignExtendMOVAbsoluteOffset(t *testing.T) {
	for _, opcode := range []byte{0xa0, 0xa1, 0xa2, 0xa3} {
		for _, offset := range []uint64{0x80000000, 0xffffffc0, 0x1122334480000000} {
			t.Run(fmt.Sprintf("%x/%x", opcode, offset), func(t *testing.T) {
				encoding := binary.LittleEndian.AppendUint64([]byte{0x48, opcode}, offset)
				inst, err := x86asm.Decode(encoding, 64)
				if err != nil || inst.Len != len(encoding) {
					t.Fatalf("physical MOV moffs decode: %+v, %v", inst, err)
				}
				syntax, err := decodedX86GoSyntax(inst, encoding)
				if err != nil {
					t.Fatal(err)
				}
				if syntax != x86asm.GoSyntax(inst, 0, nil) {
					t.Fatalf("absolute MOV spelling changed: %q", syntax)
				}
				found := false
				normalized := normalizeDecodedX86MemoryDisplacements(inst)
				for _, operand := range normalized.Args {
					if memory, ok := operand.(x86asm.Mem); ok {
						found = true
						if uint64(memory.Disp) != offset {
							t.Fatalf("absolute native offset narrowed: %q", syntax)
						}
					}
				}
				if !found {
					t.Fatalf("missing absolute memory operand: %q", syntax)
				}
			})
		}
	}
}

func TestX86RawDisplacementLEAAllWidthsAndFiveObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		mode := 64
		if target.arch == "386" {
			mode = 32
		}
		for _, width := range []int{16, 32, 64} {
			if width > mode {
				continue
			}
			for _, shape := range []int{0, 1, 2, 3} {
				t.Run(fmt.Sprintf("%s/width%d/shape%d", target.triple, width, shape), func(t *testing.T) {
					encoding := x86RawLEADisplacementEncoding(mode, width, mode, shape, 2, -64)
					body := "@MOV x+0(FP),AX\n@MOV $3,BX\n@MOV $0,CX\n" + x86RawDisplacementDirectives(encoding) + "@MOV CX,ret+@WORD(FP)\nRET"
					source, sig, _ := x86SourceStackNumericalFixture(target.arch, body)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ir, err := Translate(file, x86SourceStackOptions(target.arch, target.triple, sig))
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "raw-disp.ll", "raw-disp.o", ir)
				})
			}
		}
	}
}
