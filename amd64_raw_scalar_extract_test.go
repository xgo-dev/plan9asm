package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type rawPackedScalarExtractSpec struct {
	op        Op
	mapNumber byte
	opcode    byte
	width64   bool
}

var rawPackedScalarExtractSpecs = []rawPackedScalarExtractSpec{
	{op: "VPEXTRB", mapNumber: 3, opcode: 0x14},
	{op: "VPEXTRW", mapNumber: 3, opcode: 0x15},
	{op: "VPEXTRW", mapNumber: 1, opcode: 0xc5},
	{op: "VPEXTRD", mapNumber: 3, opcode: 0x16},
	{op: "VPEXTRQ", mapNumber: 3, opcode: 0x16, width64: true},
	{op: "VEXTRACTPS", mapNumber: 3, opcode: 0x17},
}

func encodeX86RawVEXPackedScalarExtract(spec rawPackedScalarExtractSpec, source, destination int, immediate byte) []byte {
	p0 := byte((^source>>3)&1)<<7 | 0x40 | byte((^destination>>3)&1)<<5 | spec.mapNumber
	p1 := byte(0x79)
	if spec.width64 {
		p1 |= 0x80
	}
	modRM := byte(0xc0 | source&7<<3 | destination&7)
	return []byte{0xc4, p0, p1, spec.opcode, modRM, immediate}
}

func encodeX86RawEVEXPackedScalarExtract(spec rawPackedScalarExtractSpec, source, destination int, immediate byte) []byte {
	p0 := byte((^source>>3)&1)<<7 |
		0x40 |
		byte((^destination>>3)&1)<<5 |
		byte((^source>>4)&1)<<4 |
		spec.mapNumber
	p1 := byte(0x7d)
	if spec.width64 {
		p1 |= 0x80
	}
	modRM := byte(0xc0 | source&7<<3 | destination&7)
	return []byte{0x62, p0, p1, 0x08, spec.opcode, modRM, immediate}
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVEXTRACTPS(t *testing.T) {
	// vmovss %xmm0, (%rdi); vextractps $1, %xmm0, 4(%rdi)
	code := []byte{0xc5, 0xfa, 0x11, 0x07, 0xc4, 0xe3, 0x79, 0x17, 0x47, 0x04, 0x01}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VEXTRACTPS sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VMOVSS X0, 0(DI) ") || !strings.HasPrefix(decoded[1].Raw, "VEXTRACTPS $1, X0, 4(DI) ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawPackedScalarExtractCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawPackedScalarExtractSpecs {
		for source := 0; source < 16; source++ {
			for destination := 0; destination < 16; destination++ {
				immediate := byte(source*16 + destination)
				code := encodeX86RawVEXPackedScalarExtract(spec, source, destination, immediate)
				got, length, ok, err := decodedX86PackedScalarExtractInstruction(code, 64)
				want := fmt.Sprintf("%s $%d, X%d, %s", spec.op, immediate, source, mustDecodedX86GeneralRegister(t, destination))
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
		for source := 0; source < 32; source++ {
			for destination := 0; destination < 16; destination++ {
				immediate := byte(source*16 + destination)
				code := encodeX86RawEVEXPackedScalarExtract(spec, source, destination, immediate)
				got, length, ok, err := decodedX86PackedScalarExtractInstruction(code, 64)
				want := fmt.Sprintf("%s $%d, X%d, %s", spec.op, immediate, source, mustDecodedX86GeneralRegister(t, destination))
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
	}
	if count != 4608 {
		t.Fatalf("covered %d packed scalar-extract register encodings, want 4608", count)
	}
}

func TestDecodedX86RawPackedScalarExtractMemoryAndInvalidForms(t *testing.T) {
	vexMemory := []byte{0xc4, 0x03, 0x79, 0x17, 0x7c, 0x8b, 0x01, 0xff}
	got, length, ok, err := decodedX86PackedScalarExtractInstruction(vexMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 1}
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VEXTRACTPS" || len(got.Args) != 3 || got.Args[1].String() != "X15" || got.Args[2].Kind != OpMem || !reflect.DeepEqual(got.Args[2].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}

	evexMemory := []byte{0x62, 0x03, 0xfd, 0x08, 0x16, 0x7c, 0x8b, 0x02, 0x01}
	got, length, ok, err = decodedX86PackedScalarExtractInstruction(evexMemory, 64)
	wantMemory.Off = 16
	if err != nil || !ok || length != len(evexMemory) || got.Op != "VPEXTRQ" || len(got.Args) != 3 || got.Args[1].String() != "X31" || got.Args[2].Kind != OpMem || !reflect.DeepEqual(got.Args[2].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexMemory, got, length, ok, err)
	}

	twoByteVEX := []byte{0xc5, 0xf9, 0xc5, 0xc1, 0x01}
	got, length, ok, err = decodedX86PackedScalarExtractInstruction(twoByteVEX, 64)
	if err != nil || !ok || length != len(twoByteVEX) || got.Raw != "VPEXTRW $1, X0, CX" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", twoByteVEX, got, length, ok, err)
	}

	validVEX := encodeX86RawVEXPackedScalarExtract(rawPackedScalarExtractSpecs[0], 7, 7, 1)
	validEVEX := encodeX86RawEVEXPackedScalarExtract(rawPackedScalarExtractSpecs[0], 31, 15, 1)
	for name, invalid := range map[string][]byte{
		"vex reserved vvvv":        {validVEX[0], validVEX[1], validVEX[2] &^ 0x08, validVEX[3], validVEX[4], validVEX[5]},
		"vex vector length":        {validVEX[0], validVEX[1], validVEX[2] | 0x04, validVEX[3], validVEX[4], validVEX[5]},
		"evex mask":                {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 1, validEVEX[4], validEVEX[5], validEVEX[6]},
		"evex vector length":       {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x20, validEVEX[4], validEVEX[5], validEVEX[6]},
		"evex missing fixed bit":   {validEVEX[0], validEVEX[1], validEVEX[2] &^ 0x04, validEVEX[3], validEVEX[4], validEVEX[5], validEVEX[6]},
		"truncated vex immediate":  validVEX[:len(validVEX)-1],
		"truncated evex immediate": validEVEX[:len(validEVEX)-1],
		"address override":         append([]byte{0x67}, validVEX...),
	} {
		if instruction, _, matched, decodeErr := decodedX86PackedScalarExtractInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	if instruction, _, matched, decodeErr := decodedX86PackedScalarExtractInstruction(validEVEX, 32); !matched || decodeErr == nil {
		t.Fatalf("386 EVEX encoding %x decoded as %+v, ok=%v, err=%v", validEVEX, instruction, matched, decodeErr)
	}
	extended386 := encodeX86RawVEXPackedScalarExtract(rawPackedScalarExtractSpecs[0], 8, 0, 1)
	if instruction, _, matched, decodeErr := decodedX86PackedScalarExtractInstruction(extended386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 extended encoding %x decoded as %+v, ok=%v, err=%v", extended386, instruction, matched, decodeErr)
	}
}

func TestTranslateX86RawPackedScalarExtractTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name        string
		goarch      string
		triple      string
		registerMax int
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin", registerMax: 15},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", registerMax: 15},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc", registerMax: 15},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu", registerMax: 7},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc", registerMax: 7},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT raw_packed_scalar_extract(SB),NOSPLIT,$0-0\n")
			for _, spec := range rawPackedScalarExtractSpecs {
				code := encodeX86RawVEXPackedScalarExtract(spec, target.registerMax, target.registerMax, 1)
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
				}
				if target.goarch == "amd64" {
					code = encodeX86RawEVEXPackedScalarExtract(spec, 31, 15, 1)
					for _, value := range code {
						fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"raw_packed_scalar_extract": {Name: "raw_packed_scalar_extract", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-packed-scalar-extract-"+target.name+".ll", "raw-packed-scalar-extract-"+target.name+".o", ir)
		})
	}
}

func mustDecodedX86GeneralRegister(t *testing.T, number int) Reg {
	t.Helper()
	reg, ok := decodedX86GeneralRegister(number)
	if !ok {
		t.Fatalf("missing general register %d", number)
	}
	return reg
}
