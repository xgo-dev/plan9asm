package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawBF16Convert(vectorBits, source, destination, mask int, zeroing, broadcast, memory bool) []byte {
	if memory {
		source = 0
	}
	p0 := byte((1-destination/8&1)<<7 | (1-source/16)<<6 |
		(1-source/8&1)<<5 | (1-destination/16)<<4 | 2)
	p2 := byte(vectorBits<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | destination&7<<3 | source&7)
	if memory {
		modRM = byte(0x40 | destination&7<<3)
	}
	code := []byte{0x62, p0, 0x7e, p2, 0x72, modRM}
	if memory {
		code = append(code, 7)
	}
	return code
}

func TestDecodedX86RawBF16ConvertCompleteLLVM22Forms(t *testing.T) {
	for vectorBits, names := range []struct {
		op     Op
		source string
		dest   string
	}{
		{"VCVTNEPS2BF16X", "X", "X"},
		{"VCVTNEPS2BF16Y", "Y", "X"},
		{"VCVTNEPS2BF16", "Z", "Y"},
	} {
		for _, memory := range []bool{false, true} {
			for _, masked := range []bool{false, true} {
				mask := 0
				if masked {
					mask = 3
				}
				for _, zeroing := range []bool{false, true} {
					if zeroing && !masked {
						continue
					}
					for _, broadcast := range []bool{false, true} {
						if broadcast && !memory {
							continue
						}
						code := encodeX86RawBF16Convert(vectorBits, 20, 21, mask, zeroing, broadcast, memory)
						got, length, ok, err := decodedX86RawBF16Instruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantOp := names.op
						if broadcast {
							wantOp += ".BCST"
						}
						if zeroing {
							wantOp += ".Z"
						}
						if got.Op != wantOp || got.Args[len(got.Args)-1].String() != fmt.Sprintf("%s21", names.dest) {
							t.Fatalf("decode %x = %+v, want %s -> %s21", code, got, wantOp, names.dest)
						}
						if !memory && got.Args[0].String() != fmt.Sprintf("%s20", names.source) {
							t.Fatalf("decode %x source = %s, want %s20", code, got.Args[0], names.source)
						}
						if masked && (len(got.Args) != 3 || got.Args[1].String() != "K3") {
							t.Fatalf("decode %x lost K3: %+v", code, got)
						}
					}
				}
			}
		}
	}
}

func TestDecodedX86RawBF16ConvertRejectsReservedFields(t *testing.T) {
	valid := encodeX86RawBF16Convert(2, 1, 2, 0, false, false, false)
	for _, change := range []struct {
		index int
		bits  byte
	}{
		{2, 0x80}, // EVEX.W
		{2, 0x08}, // reserved vvvv
		{3, 0x20}, // reserved LL
		{3, 0x80}, // zeroing without a K mask
		{3, 0x10}, // broadcast with register source
	} {
		bad := append([]byte(nil), valid...)
		bad[change.index] ^= change.bits
		if _, _, ok, err := decodedX86RawBF16Instruction(bad, 64); !ok || err == nil {
			t.Fatalf("accepted reserved BF16 conversion %x: ok=%v err=%v", bad, ok, err)
		}
	}
	if _, _, ok, err := decodedX86RawBF16Instruction(valid[:5], 64); ok && err == nil {
		t.Fatal("accepted truncated BF16 conversion")
	}
}

func TestTranslateRawBF16ConvertMaskAndBroadcastTargets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawBF16ConvertForms(SB),$0-0\n")
	for vectorBits := 0; vectorBits < 3; vectorBits++ {
		for _, memory := range []bool{false, true} {
			code := encodeX86RawBF16Convert(vectorBits, 1, 2, 3, true, memory, memory)
			for _, value := range code {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
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
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"rawBF16ConvertForms": {Name: "rawBF16ConvertForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"llvm.x86.vcvtneps2bf16128",
				"llvm.x86.vcvtneps2bf16256",
				"llvm.x86.avx512bf16.cvtneps2bf16.512",
				"llvm.masked.load.v16i32",
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("BF16 lowering omitted %q", want)
				}
			}
			compileLLVMToObject(t, llc, triple, "amd64-raw-bf16-convert-forms.ll", "amd64-raw-bf16-convert-forms.o", ir)
		})
	}
}

func TestTranslateRawBF16Convert386Targets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawBF16Convert386(SB),$0-0\n")
	for vectorBits := 0; vectorBits < 3; vectorBits++ {
		code := encodeX86RawBF16Convert(vectorBits, 1, 2, 0, false, false, false)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
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
				TargetTriple: triple,
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"rawBF16Convert386": {Name: "rawBF16Convert386", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "386-raw-bf16-convert.ll", "386-raw-bf16-convert.o", ir)
		})
	}
}

func TestTranslateRawBF16ConvertGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawBF16Convert(SB),$0-0
	LONG $0x487ef262; WORD $0x0472; BYTE $0x97 // VCVTNEPS2BF16 (DI)(DX*4), Y0
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		triple string
		goos   string
	}{
		{"x86_64-apple-darwin", "darwin"},
		{"x86_64-unknown-linux-gnu", "linux"},
		{"x86_64-pc-windows-msvc", "windows"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"rawBF16Convert": {Name: "rawBF16Convert", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "amd64-raw-bf16-convert.ll", "amd64-raw-bf16-convert.o", ir)
		})
	}
}
