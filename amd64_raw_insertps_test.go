package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86RawLegacyINSERTPS(source, destination int, immediate byte) []byte {
	rex := byte(0x40 | source>>3&1 | destination>>3&1<<2)
	code := []byte{0x66}
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, 0x3a, 0x21, byte(0xc0|destination&7<<3|source&7), immediate)
}

func encodeX86RawVEXINSERTPS(source, base, destination int, immediate byte) []byte {
	p0 := byte((^destination>>3)&1)<<7 | 0x40 | byte((^source>>3)&1)<<5 | 3
	p1 := byte(^base&15)<<3 | 1
	return []byte{0xc4, p0, p1, 0x21, byte(0xc0 | destination&7<<3 | source&7), immediate}
}

func encodeX86RawEVEXINSERTPS(source, base, destination int, immediate byte) []byte {
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^source>>4)&1)<<6 |
		byte((^source>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 3
	p1 := byte(^base&15)<<3 | 5
	p2 := byte((^base>>4)&1) << 3
	return []byte{0x62, p0, p1, p2, 0x21, byte(0xc0 | destination&7<<3 | source&7), immediate}
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVINSERTPS(t *testing.T) {
	// vinsertps $0x1c, %xmm10, %xmm8, %xmm1;
	// vshufps $0x24, %xmm0, %xmm1, %xmm0
	code := []byte{0xc4, 0xc3, 0x39, 0x21, 0xca, 0x1c, 0xc5, 0xf0, 0xc6, 0xc0, 0x24}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VINSERTPS sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VINSERTPS $28, X10, X8, X1 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawINSERTPSCompleteRegisterFamily(t *testing.T) {
	count := 0
	for source := 0; source < 16; source++ {
		for destination := 0; destination < 16; destination++ {
			immediate := byte(source*16 + destination)
			code := encodeX86RawLegacyINSERTPS(source, destination, immediate)
			got, length, ok, err := decodedX86InsertPSInstruction(code, 64)
			want := fmt.Sprintf("INSERTPS $%d, X%d, X%d", immediate, source, destination)
			if err != nil || !ok || length != len(code) || got.Raw != want {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
			}
			count++
		}
	}
	for source := 0; source < 16; source++ {
		for base := 0; base < 16; base++ {
			for destination := 0; destination < 16; destination++ {
				immediate := byte(source*16 + destination)
				code := encodeX86RawVEXINSERTPS(source, base, destination, immediate)
				got, length, ok, err := decodedX86InsertPSInstruction(code, 64)
				want := fmt.Sprintf("VINSERTPS $%d, X%d, X%d, X%d", immediate, source, base, destination)
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
	}
	for source := 0; source < 32; source++ {
		for base := 0; base < 32; base++ {
			for destination := 0; destination < 32; destination++ {
				immediate := byte(source*8 + destination)
				code := encodeX86RawEVEXINSERTPS(source, base, destination, immediate)
				got, length, ok, err := decodedX86InsertPSInstruction(code, 64)
				want := fmt.Sprintf("VINSERTPS $%d, X%d, X%d, X%d", immediate, source, base, destination)
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
	}
	if count != 37120 {
		t.Fatalf("covered %d INSERTPS/VINSERTPS register encodings, want 37120", count)
	}
}

func TestDecodedX86RawINSERTPSMemoryAndInvalidForms(t *testing.T) {
	legacyMemory := []byte{0x66, 0x47, 0x0f, 0x3a, 0x21, 0x7c, 0x8b, 0x01, 0xff}
	got, length, ok, err := decodedX86InsertPSInstruction(legacyMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 1}
	if err != nil || !ok || length != len(legacyMemory) || got.Op != "INSERTPS" || got.Args[2].String() != "X15" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", legacyMemory, got, length, ok, err)
	}
	vexMemory := []byte{0xc4, 0x03, 0x01, 0x21, 0x7c, 0x8b, 0x02, 0x80}
	got, length, ok, err = decodedX86InsertPSInstruction(vexMemory, 64)
	wantMemory.Off = 2
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VINSERTPS" || got.Args[2].String() != "X15" || got.Args[3].String() != "X15" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}
	evexMemory := []byte{0x62, 0x03, 0x05, 0x00, 0x21, 0x7c, 0x8b, 0x02, 0x40}
	got, length, ok, err = decodedX86InsertPSInstruction(evexMemory, 64)
	wantMemory.Off = 8
	if err != nil || !ok || length != len(evexMemory) || got.Op != "VINSERTPS" || got.Args[2].String() != "X31" || got.Args[3].String() != "X31" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexMemory, got, length, ok, err)
	}

	validVEX := encodeX86RawVEXINSERTPS(7, 7, 7, 1)
	validEVEX := encodeX86RawEVEXINSERTPS(31, 31, 31, 1)
	for name, invalid := range map[string][]byte{
		"vex W":                    {validVEX[0], validVEX[1], validVEX[2] | 0x80, validVEX[3], validVEX[4], validVEX[5]},
		"vex vector length":        {validVEX[0], validVEX[1], validVEX[2] | 0x04, validVEX[3], validVEX[4], validVEX[5]},
		"evex W":                   {validEVEX[0], validEVEX[1], validEVEX[2] | 0x80, validEVEX[3], validEVEX[4], validEVEX[5], validEVEX[6]},
		"evex mask":                {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 1, validEVEX[4], validEVEX[5], validEVEX[6]},
		"evex zero":                {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x80, validEVEX[4], validEVEX[5], validEVEX[6]},
		"evex broadcast":           {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x10, validEVEX[4], validEVEX[5], validEVEX[6]},
		"truncated vex immediate":  validVEX[:len(validVEX)-1],
		"truncated evex immediate": validEVEX[:len(validEVEX)-1],
		"address override":         append([]byte{0x67}, validVEX...),
	} {
		if instruction, _, matched, decodeErr := decodedX86InsertPSInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	if instruction, _, matched, decodeErr := decodedX86InsertPSInstruction(validEVEX, 32); !matched || decodeErr == nil {
		t.Fatalf("386 EVEX encoding %x decoded as %+v, ok=%v, err=%v", validEVEX, instruction, matched, decodeErr)
	}
	extended386 := encodeX86RawVEXINSERTPS(8, 0, 0, 1)
	if instruction, _, matched, decodeErr := decodedX86InsertPSInstruction(extended386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 extended encoding %x decoded as %+v, ok=%v, err=%v", extended386, instruction, matched, decodeErr)
	}
}

func TestTranslateX86RawINSERTPSTargets(t *testing.T) {
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
			code := [][]byte{
				encodeX86RawLegacyINSERTPS(target.registerMax, target.registerMax, 0xff),
				encodeX86RawVEXINSERTPS(target.registerMax, target.registerMax, target.registerMax, 0x1c),
			}
			if target.goarch == "amd64" {
				code = append(code, encodeX86RawEVEXINSERTPS(31, 30, 29, 0x80))
			}
			var source strings.Builder
			source.WriteString("TEXT raw_insertps(SB),NOSPLIT,$0-0\n")
			for _, instruction := range code {
				for _, value := range instruction {
					fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"raw_insertps": {Name: "raw_insertps", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-insertps-"+target.name+".ll", "raw-insertps-"+target.name+".o", ir)
		})
	}
}
