package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type rawFloatingUnpackSpec struct {
	opcode byte
	double bool
	high   bool
}

var rawFloatingUnpackSpecs = []rawFloatingUnpackSpec{
	{opcode: 0x14},
	{opcode: 0x15, high: true},
	{opcode: 0x14, double: true},
	{opcode: 0x15, double: true, high: true},
}

func (spec rawFloatingUnpackSpec) op(vector bool) Op {
	name := "UNPCKL"
	if spec.high {
		name = "UNPCKH"
	}
	if vector {
		name = "V" + name
	}
	if spec.double {
		name += "PD"
	} else {
		name += "PS"
	}
	return Op(name)
}

func encodeX86RawLegacyFloatingUnpack(spec rawFloatingUnpackSpec, source, destination int) []byte {
	code := []byte{}
	if spec.double {
		code = append(code, 0x66)
	}
	rex := byte(0x40 | source>>3&1 | destination>>3&1<<2)
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, spec.opcode, byte(0xc0|destination&7<<3|source&7))
}

func encodeX86RawVEXFloatingUnpack(spec rawFloatingUnpackSpec, vectorBits byte, first, second, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 | 0x40 | byte((^first>>3)&1)<<5 | 1
	p1 := byte(^second&15)<<3 | vectorBits<<2
	if spec.double {
		p1 |= 1
	}
	return []byte{0xc4, p0, p1, spec.opcode, byte(0xc0 | destination&7<<3 | first&7)}
}

func encodeX86RawEVEXFloatingUnpack(spec rawFloatingUnpackSpec, vectorBits byte, mask int, zeroing, broadcast bool, first, second, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^first>>4)&1)<<6 |
		byte((^first>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 1
	p1 := byte(^second&15)<<3 | 4
	if spec.double {
		p1 |= 0x81
	}
	p2 := vectorBits<<5 | byte((^second>>4)&1)<<3 | byte(mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	return []byte{0x62, p0, p1, p2, spec.opcode, byte(0xc0 | destination&7<<3 | first&7)}
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVUNPCKLPS(t *testing.T) {
	// vunpcklps %xmm3, %xmm5, %xmm0;
	// vinsertf128 $1, %xmm0, %ymm0, %ymm0
	code := []byte{0xc5, 0xd0, 0x14, 0xc3, 0xc4, 0xe3, 0x7d, 0x18, 0xc0, 0x01}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VUNPCKLPS sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VUNPCKLPS X3, X5, X0 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawFloatingUnpackCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawFloatingUnpackSpecs {
		for first := 0; first < 16; first++ {
			for destination := 0; destination < 16; destination++ {
				code := encodeX86RawLegacyFloatingUnpack(spec, first, destination)
				got, length, ok, err := decodedX86FloatingUnpackInstruction(code, 64)
				want := fmt.Sprintf("%s X%d, X%d", spec.op(false), first, destination)
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
		for vectorBits := byte(0); vectorBits < 2; vectorBits++ {
			vectorName := [...]string{"X", "Y"}[vectorBits]
			for first := 0; first < 16; first++ {
				for second := 0; second < 16; second++ {
					for destination := 0; destination < 16; destination++ {
						code := encodeX86RawVEXFloatingUnpack(spec, vectorBits, first, second, destination)
						got, length, ok, err := decodedX86FloatingUnpackInstruction(code, 64)
						want := fmt.Sprintf("%s %s%d, %s%d, %s%d", spec.op(true), vectorName, first, vectorName, second, vectorName, destination)
						if err != nil || !ok || length != len(code) || got.Raw != want {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
						}
						count++
					}
				}
			}
		}
		for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
			vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
			for _, masking := range []struct {
				mask    int
				zeroing bool
				suffix  string
			}{{}, {mask: 3}, {mask: 7, zeroing: true, suffix: ".Z"}} {
				for first := 0; first < 32; first++ {
					for second := 0; second < 32; second++ {
						for destination := 0; destination < 32; destination++ {
							code := encodeX86RawEVEXFloatingUnpack(spec, vectorBits, masking.mask, masking.zeroing, false, first, second, destination)
							got, length, ok, err := decodedX86FloatingUnpackInstruction(code, 64)
							args := []string{fmt.Sprintf("%s%d", vectorName, first), fmt.Sprintf("%s%d", vectorName, second)}
							if masking.mask != 0 {
								args = append(args, fmt.Sprintf("K%d", masking.mask))
							}
							args = append(args, fmt.Sprintf("%s%d", vectorName, destination))
							want := string(spec.op(true)) + masking.suffix + " " + strings.Join(args, ", ")
							if err != nil || !ok || length != len(code) || got.Raw != want {
								t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 1213440 {
		t.Fatalf("covered %d floating-unpack register encodings, want 1213440", count)
	}
}

func TestDecodedX86RawFloatingUnpackMemoryAndInvalidForms(t *testing.T) {
	legacyMemory := []byte{0x66, 0x47, 0x0f, 0x15, 0x7c, 0x8b, 0x01}
	got, length, ok, err := decodedX86FloatingUnpackInstruction(legacyMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 1}
	if err != nil || !ok || length != len(legacyMemory) || got.Op != "UNPCKHPD" || got.Args[1].String() != "X15" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", legacyMemory, got, length, ok, err)
	}
	vexMemory := []byte{0xc4, 0x01, 0x75, 0x14, 0x7c, 0x8b, 0x02}
	got, length, ok, err = decodedX86FloatingUnpackInstruction(vexMemory, 64)
	wantMemory.Off = 2
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VUNPCKLPD" || got.Args[1].String() != "Y1" || got.Args[2].String() != "Y15" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}
	evexMemory := []byte{0x62, 0x01, 0x85, 0xdf, 0x15, 0x7c, 0x8b, 0x02}
	got, length, ok, err = decodedX86FloatingUnpackInstruction(evexMemory, 64)
	wantMemory.Off = 16
	if err != nil || !ok || length != len(evexMemory) || got.Op != "VUNPCKHPD.BCST.Z" || got.Args[1].String() != "Z15" || got.Args[2].String() != "K7" || got.Args[3].String() != "Z31" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexMemory, got, length, ok, err)
	}

	validVEX := encodeX86RawVEXFloatingUnpack(rawFloatingUnpackSpecs[0], 0, 7, 7, 7)
	validEVEX := encodeX86RawEVEXFloatingUnpack(rawFloatingUnpackSpecs[0], 2, 0, false, false, 7, 7, 7)
	for name, invalid := range map[string][]byte{
		"vex W":                  {validVEX[0], validVEX[1], validVEX[2] | 0x80, validVEX[3], validVEX[4]},
		"vex prefix":             {validVEX[0], validVEX[1], validVEX[2] | 0x02, validVEX[3], validVEX[4]},
		"evex missing fixed bit": {validEVEX[0], validEVEX[1], validEVEX[2] &^ 0x04, validEVEX[3], validEVEX[4], validEVEX[5]},
		"evex prefix":            {validEVEX[0], validEVEX[1], validEVEX[2] | 0x02, validEVEX[3], validEVEX[4], validEVEX[5]},
		"evex reserved length":   {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x60, validEVEX[4], validEVEX[5]},
		"zero without mask":      {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x80, validEVEX[4], validEVEX[5]},
		"register broadcast":     {validEVEX[0], validEVEX[1], validEVEX[2], validEVEX[3] | 0x10, validEVEX[4], validEVEX[5]},
		"address override":       append([]byte{0x67}, validVEX...),
	} {
		if instruction, _, matched, decodeErr := decodedX86FloatingUnpackInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	masked386 := encodeX86RawEVEXFloatingUnpack(rawFloatingUnpackSpecs[0], 2, 1, false, false, 0, 1, 2)
	if instruction, _, matched, decodeErr := decodedX86FloatingUnpackInstruction(masked386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 masked encoding %x decoded as %+v, ok=%v, err=%v", masked386, instruction, matched, decodeErr)
	}
	highZ386 := encodeX86RawEVEXFloatingUnpack(rawFloatingUnpackSpecs[0], 2, 0, false, false, 8, 1, 2)
	if instruction, _, matched, decodeErr := decodedX86FloatingUnpackInstruction(highZ386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 high-Z encoding %x decoded as %+v, ok=%v, err=%v", highZ386, instruction, matched, decodeErr)
	}
}

func TestX86FloatingUnpackGo127ArchitectureOracle(t *testing.T) {
	const accepted386 = `TEXT ok(SB),$0-0
	VUNPCKLPS X20, X21, X22
	VUNPCKLPD Y20, Y21, Y22
	VUNPCKHPS Z5, Z6, Z7
	VUNPCKHPD.BCST 8(AX), X20, X21
	RET
`
	requireX86GoAssemblerResult(t, "386", accepted386, true)
	for _, instruction := range []string{
		"VUNPCKLPS Z8, Z1, Z2",
		"VUNPCKHPS Z0, Z1, K1, Z2",
	} {
		requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
	}
}

func TestTranslateX86RawFloatingUnpackTargets(t *testing.T) {
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
			source.WriteString("TEXT raw_floating_unpack(SB),NOSPLIT,$0-0\n")
			for _, spec := range rawFloatingUnpackSpecs {
				code := [][]byte{
					encodeX86RawLegacyFloatingUnpack(spec, target.registerMax, target.registerMax),
					encodeX86RawVEXFloatingUnpack(spec, 1, target.registerMax, target.registerMax, target.registerMax),
				}
				if target.goarch == "amd64" {
					code = append(code, encodeX86RawEVEXFloatingUnpack(spec, 2, 7, true, false, 31, 30, 29))
				} else {
					code = append(code, encodeX86RawEVEXFloatingUnpack(spec, 2, 0, false, false, 7, 6, 5))
				}
				for _, instruction := range code {
					for _, value := range instruction {
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
				Sigs: map[string]FuncSig{"raw_floating_unpack": {Name: "raw_floating_unpack", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-floating-unpack-"+target.name+".ll", "raw-floating-unpack-"+target.name+".o", ir)
		})
	}
}
