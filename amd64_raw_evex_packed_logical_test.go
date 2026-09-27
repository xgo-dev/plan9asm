package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86RawEVEXPackedLogical(op Op, vectorBits byte, mask int, zeroing, broadcast bool, first, second, destination int) []byte {
	opcode := map[Op]byte{
		"VPANDD":  0xdb,
		"VPANDQ":  0xdb,
		"VPANDND": 0xdf,
		"VPANDNQ": 0xdf,
		"VPORD":   0xeb,
		"VPORQ":   0xeb,
		"VPXORD":  0xef,
		"VPXORQ":  0xef,
	}[op]
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^first>>4)&1)<<6 |
		byte((^first>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 1
	p1 := byte(^second&15)<<3 | 5
	if strings.HasSuffix(string(op), "Q") {
		p1 |= 0x80
	}
	p2 := vectorBits<<5 | byte((^second>>4)&1)<<3 | byte(mask)
	if zeroing {
		p2 |= 0x80
	}
	if broadcast {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | destination&7<<3 | first&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM}
}

func TestDecodeX86RawDirectiveGroupReportedHasteEVEXPackedLogical(t *testing.T) {
	code := []byte{0x62, 0xf1, 0xf5, 0x48, 0xef, 0xc9}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "haste VPXORQ sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "VPXORQ Z1, Z1, Z1"
	if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, want+" ") {
		t.Fatalf("decoded %x as %#v, want %q", code, decoded, want)
	}
}

func TestDecodedX86RawEVEXPackedLogicalCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, op := range []Op{"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ"} {
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
				for first := 0; first < 32; first++ {
					for second := 0; second < 32; second++ {
						for destination := 0; destination < 32; destination++ {
							code := encodeX86RawEVEXPackedLogical(op, byte(vectorBits), masking.mask, masking.zeroing, false, first, second, destination)
							got, length, ok, err := decodedX86EVEXPackedLogicalInstruction(code, 64)
							args := []string{
								fmt.Sprintf("%s%d", vectorName, first),
								fmt.Sprintf("%s%d", vectorName, second),
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
	if count != 2359296 {
		t.Fatalf("covered %d EVEX packed-logical register encodings, want 2359296", count)
	}
}

func TestDecodedX86RawEVEXPackedLogicalMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x62, 0x01, 0x95, 0xd3, 0xdb, 0x64, 0x8b, 0x20}
	got, length, ok, err := decodedX86EVEXPackedLogicalInstruction(code, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 256}
	if err != nil || !ok || length != len(code) || got.Op != "VPANDQ.BCST.Z" || len(got.Args) != 4 || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) || got.Args[1].String() != "Z29" || got.Args[2].String() != "K3" || got.Args[3].String() != "Z28" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86RawEVEXPackedLogical("VPXORD", 0, 0, false, false, 0, 1, 2)
	for name, mutate := range map[string]func([]byte){
		"missing EVEX fixed bit": func(code []byte) { code[2] &^= 0x04 },
		"reserved length":        func(code []byte) { code[3] |= 0x60 },
		"zero without mask":      func(code []byte) { code[3] |= 0x80 },
		"broadcast register":     func(code []byte) { code[3] |= 0x10 },
	} {
		invalid := append([]byte(nil), valid...)
		mutate(invalid)
		if instruction, _, matched, decodeErr := decodedX86EVEXPackedLogicalInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	for _, invalid := range [][]byte{
		{0x62},
		{valid[0], valid[1] ^ 1, valid[2], valid[3], valid[4], valid[5]},
		{valid[0], valid[1], valid[2] &^ 1, valid[3], valid[4], valid[5]},
		{valid[0], valid[1], valid[2], valid[3], 0xee, valid[5]},
	} {
		if instruction, _, matched, decodeErr := decodedX86EVEXPackedLogicalInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("unrelated encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	ripRelative := []byte{0x62, 0xf1, 0x75, 0x08, 0xef, 0x15, 0, 0, 0, 0}
	if _, _, matched, decodeErr := decodedX86EVEXPackedLogicalInstruction(ripRelative, 64); !matched || decodeErr == nil {
		t.Fatalf("RIP-relative encoding returned ok=%v err=%v", matched, decodeErr)
	}
	addressOverride := append([]byte{0x67}, valid...)
	if _, _, matched, decodeErr := decodedX86EVEXPackedLogicalInstruction(addressOverride, 64); !matched || decodeErr == nil {
		t.Fatalf("address-override encoding returned ok=%v err=%v", matched, decodeErr)
	}
	for name, invalid := range map[string][]byte{
		"masked on 386":          encodeX86RawEVEXPackedLogical("VPXORD", 0, 1, false, false, 0, 1, 2),
		"high Z first on 386":    encodeX86RawEVEXPackedLogical("VPXORD", 2, 0, false, false, 8, 1, 2),
		"high Z second on 386":   encodeX86RawEVEXPackedLogical("VPXORD", 2, 0, false, false, 0, 8, 2),
		"high Z destination 386": encodeX86RawEVEXPackedLogical("VPXORD", 2, 0, false, false, 0, 1, 8),
	} {
		if _, _, matched, decodeErr := decodedX86EVEXPackedLogicalInstruction(invalid, 32); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x returned ok=%v err=%v", name, invalid, matched, decodeErr)
		}
	}
	valid386 := encodeX86RawEVEXPackedLogical("VPXORD", 1, 0, false, false, 29, 30, 31)
	got, length, ok, err = decodedX86EVEXPackedLogicalInstruction(valid386, 32)
	if err != nil || !ok || length != len(valid386) || got.Raw != "VPXORD Y29, Y30, Y31" {
		t.Fatalf("386 high X/Y register form decoded as %+v, length=%d ok=%v err=%v", got, length, ok, err)
	}
}

func TestTranslateX86RawEVEXPackedLogicalTargets(t *testing.T) {
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
				encodeX86RawEVEXPackedLogical("VPXORD", 1, 0, false, false, 29, 30, 31),
			}
			if target.goarch == "amd64" {
				code = append(code,
					[]byte{0x62, 0xf1, 0xf5, 0x48, 0xef, 0xc9},
					[]byte{0x62, 0x01, 0x95, 0xd3, 0xdb, 0x64, 0x8b, 0x20},
				)
			}
			var source strings.Builder
			source.WriteString("TEXT raw_evex_packed_logical(SB),NOSPLIT,$0-0\n")
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
				Sigs: map[string]FuncSig{"raw_evex_packed_logical": {Name: "raw_evex_packed_logical", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-evex-packed-logical-"+target.name+".ll", "raw-evex-packed-logical-"+target.name+".o", ir)
		})
	}
}
