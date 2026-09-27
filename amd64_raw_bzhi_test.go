package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86RawBZHI(wide bool, source, index, destination int) []byte {
	code := encodeRawScalarMove(false, 0, 0xf5, source, index, destination, 0, false)
	code[1] = code[1]&0xe0 | 2
	if wide {
		code[2] |= 0x80
	}
	return code
}

func TestDecodedX86RawBZHICompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, wide := range []bool{false, true} {
		for source := 0; source < 16; source++ {
			for index := 0; index < 16; index++ {
				for destination := 0; destination < 16; destination++ {
					code := encodeX86RawBZHI(wide, source, index, destination)
					got, length, ok, err := decodedX86RawBZHIInstruction(code, 64)
					wantOp := Op("BZHIL")
					if wide {
						wantOp = "BZHIQ"
					}
					sr, _ := decodedX86GeneralRegister(source)
					ir, _ := decodedX86GeneralRegister(index)
					dr, _ := decodedX86GeneralRegister(destination)
					want := []Operand{
						{Kind: OpReg, Reg: ir},
						{Kind: OpReg, Reg: sr},
						{Kind: OpReg, Reg: dr},
					}
					if err != nil || !ok || length != len(code) || got.Op != wantOp || !reflect.DeepEqual(got.Args, want) {
						t.Fatalf("decode %x = %+v length=%d ok=%t err=%v, want %s %+v", code, got, length, ok, err, wantOp, want)
					}
					count++
				}
			}
		}
	}
	if count != 8192 {
		t.Fatalf("covered %d BZHI register forms, want 8192", count)
	}
}

func TestDecodedX86RawBZHIRealMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0xc4, 0x62, 0xf0, 0xf5, 0x04, 0xc6}
	got, length, ok, err := decodedX86RawBZHIInstruction(code, 64)
	if err != nil || !ok || length != len(code) || got.Op != "BZHIQ" ||
		len(got.Args) != 3 || got.Args[0].String() != "CX" ||
		got.Args[1].String() != "0(SI)(AX*8)" || got.Args[2].String() != "R8" {
		t.Fatalf("decode real simd BZHI %x = %+v length=%d ok=%t err=%v", code, got, length, ok, err)
	}
	for name, edit := range map[string]func([]byte) []byte{
		"L1":               func(b []byte) []byte { b[2] |= 4; return b },
		"address override": func(b []byte) []byte { return append([]byte{0x67}, b...) },
		"truncated ModRM":  func(b []byte) []byte { return b[:4] },
	} {
		t.Run(name, func(t *testing.T) {
			bad := edit(append([]byte(nil), code...))
			if _, _, matched, err := decodedX86RawBZHIInstruction(bad, 64); !matched || err == nil {
				t.Fatalf("accepted invalid BZHI %x, matched=%t err=%v", bad, matched, err)
			}
		})
	}
	badPP := append([]byte(nil), code...)
	badPP[2] |= 1
	if _, _, matched, _ := decodedX86RawBZHIInstruction(badPP, 64); matched {
		t.Fatalf("accepted non-BZHI pp encoding %x", badPP)
	}
}

func TestTranslateX86RawBZHIRealMemoryObjects(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawBZHI(SB),$0-0\n")
	for _, value := range []byte{0xc4, 0x62, 0xf0, 0xf5, 0x04, 0xc6, 0xc3} {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawBZHI": {Name: "rawBZHI", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-bzhi.ll", "raw-bzhi.o", ir)
		})
	}
}
