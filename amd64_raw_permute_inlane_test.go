package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86RawVEXInLaneFloatingPermute(double, immediate bool, vectorBits byte, first, second, destination int, imm byte) []byte {
	mapNumber := byte(2)
	opcode := byte(0x0c)
	if immediate {
		mapNumber = 3
		opcode = 0x04
	}
	if double {
		opcode++
	}
	p0 := byte((^destination>>3)&1)<<7 | 0x40 | byte((^first>>3)&1)<<5 | mapNumber
	p1 := byte(^second&15)<<3 | vectorBits<<2 | 1
	if immediate {
		p1 = 0x78 | vectorBits<<2 | 1
	}
	code := []byte{0xc4, p0, p1, opcode, byte(0xc0 | destination&7<<3 | first&7)}
	if immediate {
		code = append(code, imm)
	}
	return code
}

func encodeX86RawEVEXInLaneFloatingPermute(double, immediate bool, vectorBits byte, mask int, zeroing, broadcast bool, first, second, destination int, imm byte) []byte {
	mapNumber := byte(2)
	opcode := byte(0x0c)
	if immediate {
		mapNumber = 3
		opcode = 0x04
	}
	if double {
		opcode++
	}
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^first>>4)&1)<<6 |
		byte((^first>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | mapNumber
	p1 := byte(^second&15)<<3 | 5
	p2 := vectorBits<<5 | byte((^second>>4)&1)<<3 | byte(mask)
	if immediate {
		p1 = 0x7d
		p2 |= 0x08
	}
	if double {
		p1 |= 0x80
	}
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	code := []byte{0x62, p0, p1, p2, opcode, byte(0xc0 | destination&7<<3 | first&7)}
	if immediate {
		code = append(code, imm)
	}
	return code
}

func TestDecodeX86RawDirectiveGroupReportedSegDSPVPERMILPS(t *testing.T) {
	// vpermilps $180, %ymm2, %ymm3;
	// vblendps $72, %ymm3, %ymm1, %ymm3
	code := []byte{0xc4, 0xe3, 0x7d, 0x04, 0xda, 0xb4, 0xc4, 0xe3, 0x75, 0x0c, 0xdb, 0x48}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "segdsp VPERMILPS sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || !strings.HasPrefix(decoded[0].Raw, "VPERMILPS $180, Y2, Y3 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodedX86RawInLaneFloatingPermuteCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, double := range []bool{false, true} {
		op := "VPERMILPS"
		if double {
			op = "VPERMILPD"
		}
		for vectorBits := byte(0); vectorBits < 2; vectorBits++ {
			vectorName := [...]string{"X", "Y"}[vectorBits]
			for first := 0; first < 16; first++ {
				for destination := 0; destination < 16; destination++ {
					code := encodeX86RawVEXInLaneFloatingPermute(double, true, vectorBits, first, 0, destination, 0xa5)
					got, length, ok, err := decodedX86InLaneFloatingPermuteInstruction(code, 64)
					want := fmt.Sprintf("%s $165, %s%d, %s%d", op, vectorName, first, vectorName, destination)
					if err != nil || !ok || length != len(code) || got.Raw != want {
						t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
					}
					count++
				}
			}
			for first := 0; first < 16; first++ {
				for second := 0; second < 16; second++ {
					for destination := 0; destination < 16; destination++ {
						code := encodeX86RawVEXInLaneFloatingPermute(double, false, vectorBits, first, second, destination, 0)
						got, length, ok, err := decodedX86InLaneFloatingPermuteInstruction(code, 64)
						want := fmt.Sprintf("%s %s%d, %s%d, %s%d", op, vectorName, first, vectorName, second, vectorName, destination)
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
					for destination := 0; destination < 32; destination++ {
						code := encodeX86RawEVEXInLaneFloatingPermute(double, true, vectorBits, masking.mask, masking.zeroing, false, first, 0, destination, 0x5a)
						got, length, ok, err := decodedX86InLaneFloatingPermuteInstruction(code, 64)
						args := []string{"$90", fmt.Sprintf("%s%d", vectorName, first)}
						if masking.mask != 0 {
							args = append(args, fmt.Sprintf("K%d", masking.mask))
						}
						args = append(args, fmt.Sprintf("%s%d", vectorName, destination))
						want := op + masking.suffix + " " + strings.Join(args, ", ")
						if err != nil || !ok || length != len(code) || got.Raw != want {
							t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v; want %q", code, got, length, ok, err, want)
						}
						count++
					}
				}
				for first := 0; first < 32; first++ {
					for second := 0; second < 32; second++ {
						for destination := 0; destination < 32; destination++ {
							code := encodeX86RawEVEXInLaneFloatingPermute(double, false, vectorBits, masking.mask, masking.zeroing, false, first, second, destination, 0)
							got, length, ok, err := decodedX86InLaneFloatingPermuteInstruction(code, 64)
							args := []string{fmt.Sprintf("%s%d", vectorName, first), fmt.Sprintf("%s%d", vectorName, second)}
							if masking.mask != 0 {
								args = append(args, fmt.Sprintf("K%d", masking.mask))
							}
							args = append(args, fmt.Sprintf("%s%d", vectorName, destination))
							want := op + masking.suffix + " " + strings.Join(args, ", ")
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
	if count != 625664 {
		t.Fatalf("covered %d in-lane floating-permute register encodings, want 625664", count)
	}
}

func TestDecodedX86RawInLaneFloatingPermuteMemoryAndInvalidForms(t *testing.T) {
	vexMemory := []byte{0xc4, 0x03, 0x7d, 0x05, 0x7c, 0x8b, 0x02, 0xfe}
	got, length, ok, err := decodedX86InLaneFloatingPermuteInstruction(vexMemory, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 2}
	if err != nil || !ok || length != len(vexMemory) || got.Op != "VPERMILPD" || got.Args[0].Imm != 254 || got.Args[2].String() != "Y15" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", vexMemory, got, length, ok, err)
	}
	evexImmediateMemory := []byte{0x62, 0xf3, 0xfd, 0xdb, 0x05, 0x50, 0x02, 0x07}
	got, length, ok, err = decodedX86InLaneFloatingPermuteInstruction(evexImmediateMemory, 64)
	wantMemory = MemRef{Base: "AX", Off: 16}
	if err != nil || !ok || length != len(evexImmediateMemory) || got.Op != "VPERMILPD.BCST.Z" || got.Args[0].Imm != 7 || got.Args[2].String() != "K3" || got.Args[3].String() != "Z2" || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexImmediateMemory, got, length, ok, err)
	}
	evexVariableMemory := []byte{0x62, 0xf2, 0x75, 0x38, 0x0c, 0x50, 0x02}
	got, length, ok, err = decodedX86InLaneFloatingPermuteInstruction(evexVariableMemory, 64)
	wantMemory = MemRef{Base: "AX", Off: 8}
	if err != nil || !ok || length != len(evexVariableMemory) || got.Op != "VPERMILPS.BCST" || got.Args[1].String() != "Y1" || got.Args[2].String() != "Y2" || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", evexVariableMemory, got, length, ok, err)
	}

	validVEXImmediate := encodeX86RawVEXInLaneFloatingPermute(false, true, 0, 7, 0, 7, 1)
	validEVEXVariable := encodeX86RawEVEXInLaneFloatingPermute(false, false, 2, 0, false, false, 7, 6, 5, 0)
	validEVEXImmediate := encodeX86RawEVEXInLaneFloatingPermute(false, true, 2, 0, false, false, 7, 0, 5, 1)
	for name, invalid := range map[string][]byte{
		"vex missing immediate": validVEXImmediate[:len(validVEXImmediate)-1],
		"vex W":                 {validVEXImmediate[0], validVEXImmediate[1], validVEXImmediate[2] | 0x80, validVEXImmediate[3], validVEXImmediate[4], validVEXImmediate[5]},
		"vex prefix":            {validVEXImmediate[0], validVEXImmediate[1], validVEXImmediate[2] &^ 0x01, validVEXImmediate[3], validVEXImmediate[4], validVEXImmediate[5]},
		"vex immediate vvvv":    {validVEXImmediate[0], validVEXImmediate[1], validVEXImmediate[2] &^ 0x08, validVEXImmediate[3], validVEXImmediate[4], validVEXImmediate[5]},
		"evex fixed bit":        {validEVEXVariable[0], validEVEXVariable[1], validEVEXVariable[2] &^ 0x04, validEVEXVariable[3], validEVEXVariable[4], validEVEXVariable[5]},
		"evex wrong W":          {validEVEXVariable[0], validEVEXVariable[1], validEVEXVariable[2] | 0x80, validEVEXVariable[3], validEVEXVariable[4], validEVEXVariable[5]},
		"evex immediate vvvvv":  {validEVEXImmediate[0], validEVEXImmediate[1], validEVEXImmediate[2] &^ 0x08, validEVEXImmediate[3] &^ 0x08, validEVEXImmediate[4], validEVEXImmediate[5], validEVEXImmediate[6]},
		"evex reserved length":  {validEVEXVariable[0], validEVEXVariable[1], validEVEXVariable[2], validEVEXVariable[3] | 0x60, validEVEXVariable[4], validEVEXVariable[5]},
		"zero without mask":     {validEVEXVariable[0], validEVEXVariable[1], validEVEXVariable[2], validEVEXVariable[3] | 0x80, validEVEXVariable[4], validEVEXVariable[5]},
		"register broadcast":    {validEVEXVariable[0], validEVEXVariable[1], validEVEXVariable[2], validEVEXVariable[3] | 0x10, validEVEXVariable[4], validEVEXVariable[5]},
		"address override":      append([]byte{0x67}, validVEXImmediate...),
	} {
		if instruction, _, matched, decodeErr := decodedX86InLaneFloatingPermuteInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	masked386 := encodeX86RawEVEXInLaneFloatingPermute(false, false, 0, 1, false, false, 0, 1, 2, 0)
	if instruction, _, matched, decodeErr := decodedX86InLaneFloatingPermuteInstruction(masked386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 masked encoding %x decoded as %+v, ok=%v, err=%v", masked386, instruction, matched, decodeErr)
	}
	highZ386 := encodeX86RawEVEXInLaneFloatingPermute(false, false, 2, 0, false, false, 8, 1, 2, 0)
	if instruction, _, matched, decodeErr := decodedX86InLaneFloatingPermuteInstruction(highZ386, 32); !matched || decodeErr == nil {
		t.Fatalf("386 high-Z encoding %x decoded as %+v, ok=%v, err=%v", highZ386, instruction, matched, decodeErr)
	}
}

func TestX86InLaneFloatingPermuteRawGo127ArchitectureOracle(t *testing.T) {
	const accepted386 = `TEXT ok(SB),$0-0
	VPERMILPS $7, X0, X1
	VPERMILPD X0, X1, X2
	VPERMILPS $7, X20, X21
	VPERMILPD Z0, Z6, Z7
	RET
`
	requireX86GoAssemblerResult(t, "386", accepted386, true)
	for _, instruction := range []string{
		"VPERMILPS $7, Z8, Z0",
		"VPERMILPD Z0, Z1, Z8",
		"VPERMILPS X0, X1, K1, X2",
	} {
		requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
	}
}

func TestTranslateX86RawInLaneFloatingPermuteTargets(t *testing.T) {
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
			source.WriteString("TEXT raw_in_lane_floating_permute(SB),NOSPLIT,$0-0\n")
			for _, double := range []bool{false, true} {
				var encodings [][]byte
				if target.goarch == "amd64" {
					encodings = append(encodings,
						encodeX86RawVEXInLaneFloatingPermute(double, true, 1, 15, 0, 14, 0xa5),
						encodeX86RawVEXInLaneFloatingPermute(double, false, 1, 15, 14, 13, 0),
						encodeX86RawEVEXInLaneFloatingPermute(double, true, 2, 7, true, false, 31, 0, 30, 0x5a),
						encodeX86RawEVEXInLaneFloatingPermute(double, false, 2, 3, false, false, 31, 30, 29, 0),
					)
				} else {
					encodings = append(encodings,
						encodeX86RawVEXInLaneFloatingPermute(double, true, 1, 7, 0, 6, 0xa5),
						encodeX86RawVEXInLaneFloatingPermute(double, false, 1, 7, 6, 5, 0),
						encodeX86RawEVEXInLaneFloatingPermute(double, true, 0, 0, false, false, 20, 0, 21, 0x5a),
						encodeX86RawEVEXInLaneFloatingPermute(double, false, 2, 0, false, false, 5, 6, 7, 0),
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
					"raw_in_lane_floating_permute": {Name: "raw_in_lane_floating_permute", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-in-lane-floating-permute-"+target.name+".ll", "raw-in-lane-floating-permute-"+target.name+".o", ll)
		})
	}
}
