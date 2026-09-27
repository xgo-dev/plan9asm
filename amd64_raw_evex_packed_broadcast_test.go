package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86RawEVEXPackedBroadcast(op Op, vectorBits byte, mask int, zeroing, vectorSource bool, source, destination int) []byte {
	opcode := byte(0)
	width64 := false
	if vectorSource {
		switch op {
		case "VPBROADCASTB":
			opcode = 0x78
		case "VPBROADCASTW":
			opcode = 0x79
		case "VPBROADCASTD":
			opcode = 0x58
		case "VPBROADCASTQ":
			opcode = 0x59
			width64 = true
		}
	} else {
		switch op {
		case "VPBROADCASTB":
			opcode = 0x7a
		case "VPBROADCASTW":
			opcode = 0x7b
		case "VPBROADCASTD":
			opcode = 0x7c
		case "VPBROADCASTQ":
			opcode = 0x7c
			width64 = true
		}
	}
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^source>>4)&1)<<6 |
		byte((^source>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 2
	p1 := byte(0x7d)
	if width64 {
		p1 |= 0x80
	}
	p2 := vectorBits<<5 | 0x08 | byte(mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | destination&7<<3 | source&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM}
}

func TestDecodeX86RawDirectiveGroupReportedHasteEVEXBroadcast(t *testing.T) {
	code := []byte{0x62, 0x52, 0xfd, 0x48, 0x7c, 0xf2}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "haste VPBROADCASTQ sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "VPBROADCASTQ R10, Z14"
	if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, want+" ") {
		t.Fatalf("decoded %x as %#v, want %q", code, decoded, want)
	}
}

func TestDecodedX86RawEVEXPackedBroadcastCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, op := range []Op{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
		for vectorBits, vectorName := range []string{"X", "Y", "Z"} {
			for _, masking := range []struct {
				mask    int
				zeroing bool
				suffix  string
			}{
				{},
				{mask: 3},
				{mask: 7, zeroing: true, suffix: ".Z"},
			} {
				for _, sourceKind := range []struct {
					vector bool
					count  int
					prefix string
				}{
					{count: 16, prefix: "R"},
					{vector: true, count: 32, prefix: "X"},
				} {
					for source := 0; source < sourceKind.count; source++ {
						for destination := 0; destination < 32; destination++ {
							code := encodeX86RawEVEXPackedBroadcast(op, byte(vectorBits), masking.mask, masking.zeroing, sourceKind.vector, source, destination)
							got, length, ok, err := decodedX86VEXPackedBroadcastInstruction(code, 64)
							args := []string{fmt.Sprintf("%s%d", sourceKind.prefix, source)}
							if !sourceKind.vector {
								args[0] = decodedX86RegisterNameForTest(source)
							}
							if masking.mask != 0 {
								args = append(args, fmt.Sprintf("K%d", masking.mask))
							}
							args = append(args, fmt.Sprintf("%s%d", vectorName, destination))
							want := string(op) + masking.suffix + " " + strings.Join(args, ", ")
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
	if count != 55296 {
		t.Fatalf("covered %d EVEX packed-broadcast register encodings, want 55296", count)
	}
}

func TestDecodedX86RawEVEXPackedBroadcastMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x65, 0x62, 0x12, 0x7d, 0x2b, 0x58, 0x64, 0x8b, 0x20}
	got, length, ok, err := decodedX86VEXPackedBroadcastInstruction(code, 64)
	wantMemory := MemRef{Segment: GS, Base: "R11", Index: "R9", Scale: 4, Off: 128}
	if err != nil || !ok || length != len(code) || got.Op != "VPBROADCASTD" || len(got.Args) != 3 || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) || got.Args[1].String() != "K3" || got.Args[2].String() != "Y12" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86RawEVEXPackedBroadcast("VPBROADCASTD", 0, 0, false, false, 0, 0)
	for name, mutate := range map[string]func([]byte){
		"W on byte":           func(code []byte) { code[2] |= 0x80; code[4] = 0x7a },
		"used vvvv":           func(code []byte) { code[2] &^= 0x08 },
		"used high vvvv":      func(code []byte) { code[3] &^= 0x08 },
		"EVEX.b":              func(code []byte) { code[3] |= 0x10 },
		"reserved length":     func(code []byte) { code[3] |= 0x60 },
		"zero without mask":   func(code []byte) { code[3] |= 0x80 },
		"GP high extension":   func(code []byte) { code[1] &^= 0x40 },
		"GP opcode on memory": func(code []byte) { code[5] &^= 0xc0 },
	} {
		invalid := append([]byte(nil), valid...)
		mutate(invalid)
		if instruction, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	for _, invalid := range [][]byte{
		{0x62},
		{valid[0], valid[1] ^ 1, valid[2], valid[3], valid[4], valid[5]},
		{valid[0], valid[1], valid[2] &^ 1, valid[3], valid[4], valid[5]},
		{valid[0], valid[1], valid[2], valid[3], 0x77, valid[5]},
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("unrelated encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}

	ripRelative := []byte{0x62, 0xf2, 0x7d, 0x08, 0x58, 0x05, 0, 0, 0, 0}
	if _, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(ripRelative, 64); !matched || decodeErr == nil {
		t.Fatalf("RIP-relative encoding returned ok=%v err=%v", matched, decodeErr)
	}
	addressOverride := append([]byte{0x67}, valid...)
	if _, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(addressOverride, 64); !matched || decodeErr == nil {
		t.Fatalf("address-override encoding returned ok=%v err=%v", matched, decodeErr)
	}
	for name, invalid := range map[string][]byte{
		"extended destination on 386": encodeX86RawEVEXPackedBroadcast("VPBROADCASTD", 0, 0, false, false, 0, 8),
		"extended source on 386":      encodeX86RawEVEXPackedBroadcast("VPBROADCASTD", 0, 0, false, true, 8, 0),
		"qword GP source on 386":      encodeX86RawEVEXPackedBroadcast("VPBROADCASTQ", 0, 0, false, false, 0, 0),
	} {
		if _, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(invalid, 32); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x returned ok=%v err=%v", name, invalid, matched, decodeErr)
		}
	}
	valid386 := encodeX86RawEVEXPackedBroadcast("VPBROADCASTD", 0, 0, false, false, 7, 7)
	got, length, ok, err = decodedX86VEXPackedBroadcastInstruction(valid386, 32)
	if err != nil || !ok || length != len(valid386) || got.Raw != "VPBROADCASTD DI, X7" {
		t.Fatalf("386 base-register form decoded as %+v, length=%d ok=%v err=%v", got, length, ok, err)
	}
}

func TestTranslateX86RawEVEXPackedBroadcastTargets(t *testing.T) {
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
			code := [][]byte{
				encodeX86RawEVEXPackedBroadcast("VPBROADCASTD", 0, 0, false, false, 0, 1),
				encodeX86RawEVEXPackedBroadcast("VPBROADCASTB", 1, 1, true, true, 1, 2),
			}
			if target.goarch == "amd64" {
				code = append(code, []byte{0x62, 0x52, 0xfd, 0x48, 0x7c, 0xf2})
			}
			var source strings.Builder
			source.WriteString("TEXT raw_evex_packed_broadcast(SB),NOSPLIT,$0-0\n")
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
				Sigs: map[string]FuncSig{"raw_evex_packed_broadcast": {Name: "raw_evex_packed_broadcast", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-evex-packed-broadcast-"+target.name+".ll", "raw-evex-packed-broadcast-"+target.name+".o", ir)
		})
	}
}
