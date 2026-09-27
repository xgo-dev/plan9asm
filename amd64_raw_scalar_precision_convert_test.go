package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type rawScalarPrecisionConvertSpec struct {
	legacyPrefix byte
	legacy       Op
	vector       Op
	inputBytes   int
}

var rawScalarPrecisionConvertSpecs = []rawScalarPrecisionConvertSpec{
	{legacyPrefix: 0xf3, legacy: "CVTSS2SD", vector: "VCVTSS2SD", inputBytes: 4},
	{legacyPrefix: 0xf2, legacy: "CVTSD2SS", vector: "VCVTSD2SS", inputBytes: 8},
}

func encodeX86RawLegacyScalarPrecisionConvert(spec rawScalarPrecisionConvertSpec, source, destination int) []byte {
	rex := byte(0x40 | source>>3&1 | destination>>3&1<<2)
	code := []byte{spec.legacyPrefix}
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, 0x5a, byte(0xc0|destination&7<<3|source&7))
}

func encodeX86RawVEXScalarPrecisionConvert(spec rawScalarPrecisionConvertSpec, first, second, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 | 0x40 | byte((^first>>3)&1)<<5 | 1
	pp := byte(3)
	if spec.inputBytes == 4 {
		pp = 2
	}
	p1 := byte(^second&15)<<3 | pp
	return []byte{0xc4, p0, p1, 0x5a, byte(0xc0 | destination&7<<3 | first&7)}
}

func encodeX86RawEVEXScalarPrecisionConvert(spec rawScalarPrecisionConvertSpec, control int, mask int, zeroing bool, first, second, destination int) []byte {
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^first>>4)&1)<<6 |
		byte((^first>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 1
	pp := byte(3)
	if spec.inputBytes == 4 {
		pp = 2
	}
	p1 := byte(^second&15)<<3 | 4 | pp
	if spec.inputBytes == 8 {
		p1 |= 0x80
	}
	p2 := byte((^second>>4)&1)<<3 | byte(mask)
	if control >= 0 {
		p2 |= 0x10 | byte(control)<<5
	}
	if zeroing {
		p2 |= 0x80
	}
	return []byte{0x62, p0, p1, p2, 0x5a, byte(0xc0 | destination&7<<3 | first&7)}
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVCVTSD2SS(t *testing.T) {
	// vcvtsd2ss %xmm0, %xmm0, %xmm0;
	// vmovsd (%rcx), %xmm1
	code := []byte{0xc5, 0xfb, 0x5a, 0xc0, 0xc5, 0xfb, 0x10, 0x09}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VCVTSD2SS sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VCVTSD2SS X0, X0, X0 ") || !strings.HasPrefix(decoded[1].Raw, "VMOVSD 0(CX), X1 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawScalarPrecisionConvertCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawScalarPrecisionConvertSpecs {
		for source := 0; source < 16; source++ {
			for destination := 0; destination < 16; destination++ {
				code := encodeX86RawLegacyScalarPrecisionConvert(spec, source, destination)
				got, length, ok, err := decodedX86ScalarPrecisionConvertInstruction(code, 64)
				want := fmt.Sprintf("%s X%d, X%d", spec.legacy, source, destination)
				if err != nil || !ok || length != len(code) || got.Raw != want {
					t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
				}
				count++
			}
		}
		for first := 0; first < 16; first++ {
			for second := 0; second < 16; second++ {
				for destination := 0; destination < 16; destination++ {
					code := encodeX86RawVEXScalarPrecisionConvert(spec, first, second, destination)
					got, length, ok, err := decodedX86ScalarPrecisionConvertInstruction(code, 64)
					want := fmt.Sprintf("%s X%d, X%d, X%d", spec.vector, first, second, destination)
					if err != nil || !ok || length != len(code) || got.Raw != want {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
					}
					count++
				}
			}
		}
		controls := []int{-1, 0}
		if spec.inputBytes == 8 {
			controls = []int{-1, 0, 1, 2, 3}
		}
		for _, control := range controls {
			for _, masking := range []struct {
				mask    int
				zeroing bool
			}{{}, {mask: 3}, {mask: 7, zeroing: true}} {
				for first := 0; first < 32; first++ {
					for second := 0; second < 32; second++ {
						for destination := 0; destination < 32; destination++ {
							code := encodeX86RawEVEXScalarPrecisionConvert(spec, control, masking.mask, masking.zeroing, first, second, destination)
							got, length, ok, err := decodedX86ScalarPrecisionConvertInstruction(code, 64)
							suffix := ""
							if control >= 0 {
								if spec.inputBytes == 4 {
									suffix = ".SAE"
								} else {
									suffix = "." + [...]string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}[control]
								}
							}
							if masking.zeroing {
								suffix += ".Z"
							}
							args := []string{fmt.Sprintf("X%d", first), fmt.Sprintf("X%d", second)}
							if masking.mask != 0 {
								args = append(args, fmt.Sprintf("K%d", masking.mask))
							}
							args = append(args, fmt.Sprintf("X%d", destination))
							want := string(spec.vector) + suffix + " " + strings.Join(args, ", ")
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
	if count != 696832 {
		t.Fatalf("covered %d scalar precision-conversion register encodings, want 696832", count)
	}
}

func TestDecodedX86RawScalarPrecisionConvertMemoryAndInvalidForms(t *testing.T) {
	legacyMemory := []byte{0xf3, 0x47, 0x0f, 0x5a, 0x7c, 0x8b, 0x01}
	got, length, ok, err := decodedX86ScalarPrecisionConvertInstruction(legacyMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 1}
	if err != nil || !ok || length != len(legacyMemory) || got.Op != "CVTSS2SD" || got.Args[1].String() != "X15" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", legacyMemory, got, length, ok, err)
	}
	vexMemory := []byte{0xc4, 0x01, 0x73, 0x5a, 0x7c, 0x8b, 0x02}
	got, length, ok, err = decodedX86ScalarPrecisionConvertInstruction(vexMemory, 64)
	wantMemory.Off = 2
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VCVTSD2SS" || got.Args[1].String() != "X1" || got.Args[2].String() != "X15" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}
	evexMemory := []byte{0x62, 0xf1, 0x56, 0x83, 0x5a, 0x50, 0x02}
	got, length, ok, err = decodedX86ScalarPrecisionConvertInstruction(evexMemory, 64)
	wantMemory = MemRef{Base: "AX", Off: 8}
	if err != nil || !ok || length != len(evexMemory) || got.Op != "VCVTSS2SD.Z" || got.Args[1].String() != "X21" || got.Args[2].String() != "K3" || got.Args[3].String() != "X2" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexMemory, got, length, ok, err)
	}

	validVEX := encodeX86RawVEXScalarPrecisionConvert(rawScalarPrecisionConvertSpecs[0], 7, 6, 5)
	validEVEXSS := encodeX86RawEVEXScalarPrecisionConvert(rawScalarPrecisionConvertSpecs[0], -1, 0, false, 7, 6, 5)
	validEVEXSD := encodeX86RawEVEXScalarPrecisionConvert(rawScalarPrecisionConvertSpecs[1], -1, 0, false, 7, 6, 5)
	for name, invalid := range map[string][]byte{
		"vex W":                   {validVEX[0], validVEX[1], validVEX[2] | 0x80, validVEX[3], validVEX[4]},
		"vex L":                   {validVEX[0], validVEX[1], validVEX[2] | 0x04, validVEX[3], validVEX[4]},
		"evex fixed bit":          {validEVEXSS[0], validEVEXSS[1], validEVEXSS[2] &^ 0x04, validEVEXSS[3], validEVEXSS[4], validEVEXSS[5]},
		"evex SS wrong W":         {validEVEXSS[0], validEVEXSS[1], validEVEXSS[2] | 0x80, validEVEXSS[3], validEVEXSS[4], validEVEXSS[5]},
		"evex SD wrong W":         {validEVEXSD[0], validEVEXSD[1], validEVEXSD[2] &^ 0x80, validEVEXSD[3], validEVEXSD[4], validEVEXSD[5]},
		"evex length without SAE": {validEVEXSS[0], validEVEXSS[1], validEVEXSS[2], validEVEXSS[3] | 0x20, validEVEXSS[4], validEVEXSS[5]},
		"zero without mask":       {validEVEXSS[0], validEVEXSS[1], validEVEXSS[2], validEVEXSS[3] | 0x80, validEVEXSS[4], validEVEXSS[5]},
		"SS explicit rounding":    {validEVEXSS[0], validEVEXSS[1], validEVEXSS[2], validEVEXSS[3] | 0x30, validEVEXSS[4], validEVEXSS[5]},
		"address override":        append([]byte{0x67}, validVEX...),
	} {
		if instruction, _, matched, decodeErr := decodedX86ScalarPrecisionConvertInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	roundingMemory := []byte{0x62, 0xf1, 0xff, 0x10, 0x5a, 0x00}
	if instruction, _, matched, decodeErr := decodedX86ScalarPrecisionConvertInstruction(roundingMemory, 64); !matched || decodeErr == nil {
		t.Fatalf("rounding memory encoding %x decoded as %+v, ok=%v, err=%v", roundingMemory, instruction, matched, decodeErr)
	}
	masked386 := encodeX86RawEVEXScalarPrecisionConvert(rawScalarPrecisionConvertSpecs[0], -1, 1, false, 0, 1, 2)
	if instruction, _, matched, decodeErr := decodedX86ScalarPrecisionConvertInstruction(masked386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 masked encoding %x decoded as %+v, ok=%v, err=%v", masked386, instruction, matched, decodeErr)
	}
}

func TestTranslateX86RawScalarPrecisionConvertTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT raw_scalar_precision_convert(SB),NOSPLIT,$0-0\n")
			for _, spec := range rawScalarPrecisionConvertSpecs {
				var encodings [][]byte
				if target.goarch == "amd64" {
					control := 0
					if spec.inputBytes == 8 {
						control = 3
					}
					encodings = append(encodings,
						encodeX86RawLegacyScalarPrecisionConvert(spec, 15, 14),
						encodeX86RawVEXScalarPrecisionConvert(spec, 15, 14, 13),
						encodeX86RawEVEXScalarPrecisionConvert(spec, -1, 3, true, 31, 30, 29),
						encodeX86RawEVEXScalarPrecisionConvert(spec, control, 7, true, 31, 30, 29),
					)
				} else {
					control := 0
					if spec.inputBytes == 8 {
						control = 2
					}
					encodings = append(encodings,
						encodeX86RawLegacyScalarPrecisionConvert(spec, 7, 6),
						encodeX86RawVEXScalarPrecisionConvert(spec, 7, 6, 5),
						encodeX86RawEVEXScalarPrecisionConvert(spec, -1, 0, false, 20, 21, 22),
						encodeX86RawEVEXScalarPrecisionConvert(spec, control, 0, false, 20, 21, 22),
					)
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
					"raw_scalar_precision_convert": {Name: "raw_scalar_precision_convert", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-scalar-precision-convert-"+target.name+".ll", "raw-scalar-precision-convert-"+target.name+".o", ll)
		})
	}
}
