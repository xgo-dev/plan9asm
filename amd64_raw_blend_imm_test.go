package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type rawImmediatePackedBlendSpec struct {
	opcode byte
	legacy Op
	vector Op
}

var rawImmediatePackedBlendSpecs = []rawImmediatePackedBlendSpec{
	{opcode: 0x0e, legacy: "PBLENDW", vector: "VPBLENDW"},
	{opcode: 0x0c, legacy: "BLENDPS", vector: "VBLENDPS"},
	{opcode: 0x0d, legacy: "BLENDPD", vector: "VBLENDPD"},
	{opcode: 0x02, vector: "VPBLENDD"},
}

func encodeX86RawLegacyImmediatePackedBlend(spec rawImmediatePackedBlendSpec, source, destination int, immediate byte) []byte {
	rex := byte(0x40 | source>>3&1 | destination>>3&1<<2)
	code := []byte{0x66}
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, 0x3a, spec.opcode, byte(0xc0|destination&7<<3|source&7), immediate)
}

func encodeX86RawVEXImmediatePackedBlend(spec rawImmediatePackedBlendSpec, vectorBits byte, first, second, destination int, immediate byte) []byte {
	p0 := byte((^destination>>3)&1)<<7 | 0x40 | byte((^first>>3)&1)<<5 | 3
	p1 := byte(^second&15)<<3 | vectorBits<<2 | 1
	return []byte{0xc4, p0, p1, spec.opcode, byte(0xc0 | destination&7<<3 | first&7), immediate}
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVBLENDPD(t *testing.T) {
	// vblendpd $12, %ymm1, %ymm0, %ymm0;
	// vunpcklps %xmm3, %xmm5, %xmm0
	code := []byte{0xc4, 0xe3, 0x7d, 0x0d, 0xc1, 0x0c, 0xc5, 0xd0, 0x14, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VBLENDPD sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VBLENDPD $12, Y1, Y0, Y0 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawImmediatePackedBlendCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawImmediatePackedBlendSpecs {
		if spec.legacy != "" {
			for source := 0; source < 16; source++ {
				for destination := 0; destination < 16; destination++ {
					code := encodeX86RawLegacyImmediatePackedBlend(spec, source, destination, 0xa5)
					got, length, ok, err := decodedX86ImmediatePackedBlendInstruction(code, 64)
					want := fmt.Sprintf("%s $165, X%d, X%d", spec.legacy, source, destination)
					if err != nil || !ok || length != len(code) || got.Raw != want {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
					}
					count++
				}
			}
		}
		for vectorBits := byte(0); vectorBits < 2; vectorBits++ {
			vectorName := [...]string{"X", "Y"}[vectorBits]
			for first := 0; first < 16; first++ {
				for second := 0; second < 16; second++ {
					for destination := 0; destination < 16; destination++ {
						code := encodeX86RawVEXImmediatePackedBlend(spec, vectorBits, first, second, destination, 0x5a)
						got, length, ok, err := decodedX86ImmediatePackedBlendInstruction(code, 64)
						want := fmt.Sprintf("%s $90, %s%d, %s%d, %s%d", spec.vector, vectorName, first, vectorName, second, vectorName, destination)
						if err != nil || !ok || length != len(code) || got.Raw != want {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
						}
						count++
					}
				}
			}
		}
	}
	if count != 33536 {
		t.Fatalf("covered %d immediate packed-blend register encodings, want 33536", count)
	}
}

func TestDecodedX86RawImmediatePackedBlendMemoryAndInvalidForms(t *testing.T) {
	legacyMemory := []byte{0x66, 0x47, 0x0f, 0x3a, 0x0e, 0x7c, 0x8b, 0x01, 0x7f}
	got, length, ok, err := decodedX86ImmediatePackedBlendInstruction(legacyMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 1}
	if err != nil || !ok || length != len(legacyMemory) || got.Op != "PBLENDW" || got.Args[0].Imm != 127 || got.Args[2].String() != "X15" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", legacyMemory, got, length, ok, err)
	}
	vexMemory := []byte{0xc4, 0x03, 0x75, 0x0d, 0x7c, 0x8b, 0x02, 0xfe}
	got, length, ok, err = decodedX86ImmediatePackedBlendInstruction(vexMemory, 64)
	wantMemory.Off = 2
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VBLENDPD" || got.Args[0].Imm != 254 || got.Args[2].String() != "Y1" || got.Args[3].String() != "Y15" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}

	validLegacy := encodeX86RawLegacyImmediatePackedBlend(rawImmediatePackedBlendSpecs[0], 7, 7, 1)
	validVEX := encodeX86RawVEXImmediatePackedBlend(rawImmediatePackedBlendSpecs[0], 0, 7, 7, 7, 1)
	for name, invalid := range map[string][]byte{
		"legacy missing immediate": validLegacy[:len(validLegacy)-1],
		"vex missing immediate":    validVEX[:len(validVEX)-1],
		"vex W":                    {validVEX[0], validVEX[1], validVEX[2] | 0x80, validVEX[3], validVEX[4], validVEX[5]},
		"vex prefix":               {validVEX[0], validVEX[1], validVEX[2] &^ 0x01, validVEX[3], validVEX[4], validVEX[5]},
		"address override":         append([]byte{0x67}, validVEX...),
	} {
		if instruction, _, matched, decodeErr := decodedX86ImmediatePackedBlendInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	if instruction, _, matched, decodeErr := decodedX86ImmediatePackedBlendInstruction(validVEX, 32); !matched || decodeErr == nil {
		t.Fatalf("386 VEX encoding %x decoded as %+v, ok=%v, err=%v", validVEX, instruction, matched, decodeErr)
	}
}

func TestX86ImmediatePackedBlendGo127ArchitectureOracle(t *testing.T) {
	const accepted386 = `TEXT ok(SB),$0-0
	PBLENDW $7, X6, X7
	BLENDPS $7, X6, X7
	BLENDPD $7, X6, X7
	RET
`
	requireX86GoAssemblerResult(t, "386", accepted386, true)
	for _, instruction := range []string{
		"VPBLENDW $7, X0, X1, X2",
		"VPBLENDD $7, Y0, Y1, Y2",
		"VBLENDPS $7, X0, X1, X2",
		"VBLENDPD $7, Y0, Y1, Y2",
	} {
		requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
	}
}

func TestTranslateX86RawImmediatePackedBlendTargets(t *testing.T) {
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
			source.WriteString("TEXT raw_immediate_packed_blend(SB),NOSPLIT,$0-0\n")
			for _, spec := range rawImmediatePackedBlendSpecs {
				var encodings [][]byte
				if spec.legacy != "" {
					encodings = append(encodings, encodeX86RawLegacyImmediatePackedBlend(spec, target.registerMax, target.registerMax, 0xa5))
				}
				if target.goarch == "amd64" {
					encodings = append(encodings, encodeX86RawVEXImmediatePackedBlend(spec, 1, target.registerMax, target.registerMax, target.registerMax, 0x5a))
				}
				for _, encoding := range encodings {
					for _, value := range encoding {
						fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"raw_immediate_packed_blend": {Name: "raw_immediate_packed_blend", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-immediate-packed-blend-"+target.name+".ll", "raw-immediate-packed-blend-"+target.name+".o", ll)
		})
	}
}
