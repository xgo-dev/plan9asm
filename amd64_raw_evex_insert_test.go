package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86RawEVEXPackedInsert(op Op, vectorBits byte, mask int, zeroing bool, first, second, destination int, immediate byte) []byte {
	opcode := map[Op]byte{
		"VINSERTF32X4": 0x18,
		"VINSERTF64X2": 0x18,
		"VINSERTF32X8": 0x1a,
		"VINSERTF64X4": 0x1a,
		"VINSERTI32X4": 0x38,
		"VINSERTI64X2": 0x38,
		"VINSERTI32X8": 0x3a,
		"VINSERTI64X4": 0x3a,
	}[op]
	p0 := byte((^destination>>3)&1)<<7 |
		byte((^first>>4)&1)<<6 |
		byte((^first>>3)&1)<<5 |
		byte((^destination>>4)&1)<<4 | 3
	p1 := byte(^second&15)<<3 | 5
	if strings.Contains(string(op), "64") {
		p1 |= 0x80
	}
	p2 := vectorBits<<5 | byte((^second>>4)&1)<<3 | byte(mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | destination&7<<3 | first&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM, immediate}
}

func TestDecodeX86RawDirectiveGroupReportedHasteEVEXPackedInsert(t *testing.T) {
	code := []byte{0x62, 0xf3, 0xfd, 0x48, 0x38, 0x47, 0x01, 0x01}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "haste VINSERTI64X2 sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "VINSERTI64X2 $1, 16(DI), Z0, Z0"
	if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, want+" ") {
		t.Fatalf("decoded %x as %#v, want %q", code, decoded, want)
	}
}

func TestDecodedX86RawEVEXPackedInsertCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, family := range []struct {
		ops        []Op
		vectorBits []byte
	}{
		{
			ops:        []Op{"VINSERTF32X4", "VINSERTF64X2", "VINSERTI32X4", "VINSERTI64X2"},
			vectorBits: []byte{1, 2},
		},
		{
			ops:        []Op{"VINSERTF32X8", "VINSERTF64X4", "VINSERTI32X8", "VINSERTI64X4"},
			vectorBits: []byte{2},
		},
	} {
		for _, op := range family.ops {
			for _, vectorBits := range family.vectorBits {
				vectorName := [...]string{"X", "Y", "Z"}[vectorBits]
				firstName := "X"
				if strings.HasSuffix(string(op), "X8") || strings.HasSuffix(string(op), "X4") && strings.Contains(string(op), "64X4") {
					firstName = "Y"
				}
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
								immediate := byte(first*8 + destination)
								code := encodeX86RawEVEXPackedInsert(op, vectorBits, masking.mask, masking.zeroing, first, second, destination, immediate)
								got, length, ok, err := decodedX86EVEXPackedInsertInstruction(code, 64)
								args := []string{
									fmt.Sprintf("$%d", immediate),
									fmt.Sprintf("%s%d", firstName, first),
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
	}
	if count != 1179648 {
		t.Fatalf("covered %d EVEX packed-insert register encodings, want 1179648", count)
	}
}

func TestDecodedX86RawEVEXPackedInsertMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x62, 0x03, 0x15, 0xc3, 0x3a, 0x64, 0x8b, 0x02, 0xff}
	got, length, ok, err := decodedX86EVEXPackedInsertInstruction(code, 64)
	wantMemory := MemRef{Base: "R11", Index: "R9", Scale: 4, Off: 64}
	if err != nil || !ok || length != len(code) || got.Op != "VINSERTI32X8.Z" || len(got.Args) != 5 || got.Args[0].Imm != 255 || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) || got.Args[2].String() != "Z29" || got.Args[3].String() != "K3" || got.Args[4].String() != "Z28" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86RawEVEXPackedInsert("VINSERTI64X2", 2, 0, false, 0, 1, 2, 3)
	for name, mutate := range map[string]func([]byte){
		"missing EVEX fixed bit": func(code []byte) { code[2] &^= 0x04 },
		"EVEX.b":                 func(code []byte) { code[3] |= 0x10 },
		"reserved length":        func(code []byte) { code[3] |= 0x60 },
		"zero without mask":      func(code []byte) { code[3] |= 0x80 },
		"x4 with X output":       func(code []byte) { code[3] &^= 0x60 },
		"x8 with Y output": func(code []byte) {
			code[3] = code[3]&^0x60 | 0x20
			code[4] = 0x3a
		},
	} {
		invalid := append([]byte(nil), valid...)
		mutate(invalid)
		if instruction, _, matched, decodeErr := decodedX86EVEXPackedInsertInstruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, invalid, instruction, matched, decodeErr)
		}
	}
	for _, invalid := range [][]byte{
		{0x62},
		{valid[0], valid[1] ^ 1, valid[2], valid[3], valid[4], valid[5], valid[6]},
		{valid[0], valid[1], valid[2] &^ 1, valid[3], valid[4], valid[5], valid[6]},
		{valid[0], valid[1], valid[2], valid[3], 0x19, valid[5], valid[6]},
	} {
		if instruction, _, matched, decodeErr := decodedX86EVEXPackedInsertInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("unrelated encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	truncatedImmediate := valid[:len(valid)-1]
	if _, _, matched, decodeErr := decodedX86EVEXPackedInsertInstruction(truncatedImmediate, 64); !matched || decodeErr == nil {
		t.Fatalf("truncated immediate returned ok=%v err=%v", matched, decodeErr)
	}
	ripRelative := []byte{0x62, 0xf3, 0xfd, 0x48, 0x38, 0x05, 0, 0, 0, 0, 1}
	if _, _, matched, decodeErr := decodedX86EVEXPackedInsertInstruction(ripRelative, 64); !matched || decodeErr == nil {
		t.Fatalf("RIP-relative encoding returned ok=%v err=%v", matched, decodeErr)
	}
	addressOverride := append([]byte{0x67}, valid...)
	if _, _, matched, decodeErr := decodedX86EVEXPackedInsertInstruction(addressOverride, 64); !matched || decodeErr == nil {
		t.Fatalf("address-override encoding returned ok=%v err=%v", matched, decodeErr)
	}
	for _, op := range []Op{"VINSERTF32X4", "VINSERTF64X2", "VINSERTF32X8", "VINSERTF64X4", "VINSERTI32X4", "VINSERTI64X2", "VINSERTI32X8", "VINSERTI64X4"} {
		vectorBits := byte(1)
		if strings.HasSuffix(string(op), "X8") || strings.Contains(string(op), "64X4") {
			vectorBits = 2
		}
		invalid := encodeX86RawEVEXPackedInsert(op, vectorBits, 0, false, 0, 0, 1, 0)
		if _, _, matched, decodeErr := decodedX86EVEXPackedInsertInstruction(invalid, 32); !matched || decodeErr == nil {
			t.Fatalf("386 %s encoding %x returned ok=%v err=%v", op, invalid, matched, decodeErr)
		}
	}
}

func TestTranslateX86RawEVEXPackedInsertTargets(t *testing.T) {
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
	} {
		t.Run(target.name, func(t *testing.T) {
			code := [][]byte{
				encodeX86RawEVEXPackedInsert("VINSERTI64X2", 1, 3, true, 20, 20, 21, 1),
			}
			code = append(code,
				[]byte{0x62, 0xf3, 0xfd, 0x48, 0x38, 0x47, 0x01, 0x01},
				[]byte{0x62, 0x03, 0x15, 0xc3, 0x3a, 0x64, 0x8b, 0x02, 0xff},
			)
			var source strings.Builder
			source.WriteString("TEXT raw_evex_packed_insert(SB),NOSPLIT,$0-0\n")
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
				Sigs: map[string]FuncSig{"raw_evex_packed_insert": {Name: "raw_evex_packed_insert", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-evex-packed-insert-"+target.name+".ll", "raw-evex-packed-insert-"+target.name+".o", ir)
		})
	}
}
