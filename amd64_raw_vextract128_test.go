package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXTRACT128(opcode, immediate byte, source, destination int) []byte {
	vex0 := byte((1-source/8)<<7 | 1<<6 | (1-destination/8)<<5 | 3)
	modRM := byte(0xc0 | (source&7)<<3 | destination&7)
	return []byte{0xc4, vex0, 0x7d, opcode, modRM, immediate}
}

func encodeX86EVEXTRACT(opcode, immediate byte, width64 bool, vectorBits byte, mask int, zeroing bool, source, destination int) []byte {
	p0 := byte((1-source/8&1)<<7 | (1-destination/16)<<6 | (1-destination/8&1)<<5 | (1-source/16)<<4 | 3)
	p1 := byte(0x7d)
	if width64 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 1<<3 | byte(mask))
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (source&7)<<3 | destination&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM, immediate}
}

func TestTranslateRawVEXTRACT128WeaviateRegression(t *testing.T) {
	const source = `TEXT rawExtract(SB), $0-0
	LONG $0x197de3c4; WORD $0x01c1
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawExtract": {Name: "rawExtract", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "shufflevector <32 x i8>") {
		t.Fatalf("raw VEXTRACTF128 lowering omitted vector extract:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vextract128.ll", "amd64-raw-vextract128.o", ir)
}

func TestDecodedX86VEXTRACT128CompleteRegisterFamily(t *testing.T) {
	count := 0
	for opcode, wantOp := range map[byte]Op{0x19: "VEXTRACTF128", 0x39: "VEXTRACTI128"} {
		for source := 0; source < 16; source++ {
			for destination := 0; destination < 16; destination++ {
				for immediate := 0; immediate < 256; immediate++ {
					code := encodeX86VEXTRACT128(opcode, byte(immediate), source, destination)
					got, length, ok, err := decodedX86VEXTRACT128Instruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					if got.Op != wantOp || len(got.Args) != 3 || got.Args[0].Imm != int64(immediate) || got.Args[1].String() != fmt.Sprintf("Y%d", source) || got.Args[2].String() != fmt.Sprintf("X%d", destination) {
						t.Fatalf("decode %x = %+v, want %s $%d, Y%d, X%d", code, got, wantOp, immediate, source, destination)
					}
					count++
				}
			}
		}
	}
	if count != 131072 {
		t.Fatalf("covered %d VEXTRACT128 register encodings, want 131072", count)
	}
}

func TestDecodedX86VEXTRACT128MemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x64, 0xc4, 0x03, 0x7d, 0x39, 0x64, 0x88, 0x20, 0xff}
	got, length, ok, err := decodedX86VEXTRACT128Instruction(code, 64)
	wantDestination := MemRef{Segment: FS, Base: "R8", Index: "R9", Scale: 4, Off: 32}
	if err != nil || !ok || length != len(code) || got.Op != "VEXTRACTI128" || len(got.Args) != 3 || got.Args[0].Imm != 0xff || got.Args[1].String() != "Y12" || got.Args[2].Kind != OpMem || got.Args[2].Mem != wantDestination {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86VEXTRACT128(0x19, 1, 0, 0)
	for _, invalid := range [][]byte{
		{0xc4},
		{valid[0], valid[1] ^ 1, valid[2], valid[3], valid[4], valid[5]},
		encodeX86VEXTRACT128(0x18, 1, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXTRACT128Instruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	for _, invalid := range [][]byte{
		{valid[0], valid[1], valid[2] &^ 1, valid[3], valid[4], valid[5]},
		{valid[0], valid[1], valid[2] &^ 4, valid[3], valid[4], valid[5]},
		{valid[0], valid[1], valid[2] | 0x80, valid[3], valid[4], valid[5]},
	} {
		if _, _, matched, decodeErr := decodedX86VEXTRACT128Instruction(invalid, 64); !matched || decodeErr == nil {
			t.Fatalf("reserved encoding %x returned ok=%v err=%v", invalid, matched, decodeErr)
		}
	}
	extended := encodeX86VEXTRACT128(0x19, 1, 8, 8)
	if _, _, matched, decodeErr := decodedX86VEXTRACT128Instruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
}

func TestTranslateRawEVEXTRACTWeaviateRegression(t *testing.T) {
	const source = `TEXT rawEVEXTRACT(SB), $0-0
	LONG $0x48fdf362
	WORD $0xc13b
	BYTE $0x01
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawEVEXTRACT": {Name: "rawEVEXTRACT", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "shufflevector <64 x i8>") {
		t.Fatalf("raw VEXTRACTI64X4 lowering omitted 256-bit block extract:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-evextract.ll", "amd64-raw-evextract.o", ir)
}

func TestDecodedX86VEXTRACTCompleteEVEXRegisterFamily(t *testing.T) {
	tests := []struct {
		opcode      byte
		width64     bool
		op          Op
		outputBytes int
		vectorBits  []byte
	}{
		{opcode: 0x19, op: "VEXTRACTF32X4", outputBytes: 16, vectorBits: []byte{1, 2}},
		{opcode: 0x19, width64: true, op: "VEXTRACTF64X2", outputBytes: 16, vectorBits: []byte{1, 2}},
		{opcode: 0x1b, op: "VEXTRACTF32X8", outputBytes: 32, vectorBits: []byte{2}},
		{opcode: 0x1b, width64: true, op: "VEXTRACTF64X4", outputBytes: 32, vectorBits: []byte{2}},
		{opcode: 0x39, op: "VEXTRACTI32X4", outputBytes: 16, vectorBits: []byte{1, 2}},
		{opcode: 0x39, width64: true, op: "VEXTRACTI64X2", outputBytes: 16, vectorBits: []byte{1, 2}},
		{opcode: 0x3b, op: "VEXTRACTI32X8", outputBytes: 32, vectorBits: []byte{2}},
		{opcode: 0x3b, width64: true, op: "VEXTRACTI64X4", outputBytes: 32, vectorBits: []byte{2}},
	}
	count := 0
	for _, test := range tests {
		for _, vectorBits := range test.vectorBits {
			sourcePrefix := [...]string{"", "Y", "Z"}[vectorBits]
			destinationPrefix := "X"
			if test.outputBytes == 32 {
				destinationPrefix = "Y"
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
				for source := 0; source < 32; source++ {
					for destination := 0; destination < 32; destination++ {
						immediate := byte(source<<3 | destination&7)
						code := encodeX86EVEXTRACT(test.opcode, immediate, test.width64, vectorBits, masking.mask, masking.zeroing, source, destination)
						got, length, ok, err := decodedX86VEXTRACT128Instruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{fmt.Sprintf("$%d", immediate), fmt.Sprintf("%s%d", sourcePrefix, source)}
						if masking.mask != 0 {
							wantArgs = append(wantArgs, fmt.Sprintf("K%d", masking.mask))
						}
						wantArgs = append(wantArgs, fmt.Sprintf("%s%d", destinationPrefix, destination))
						wantOp := test.op + Op(masking.suffix)
						if got.Op != wantOp || len(got.Args) != len(wantArgs) {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
						}
						for index := range wantArgs {
							if got.Args[index].String() != wantArgs[index] {
								t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
							}
						}
						count++
					}
				}
			}
		}
	}
	if count != 36864 {
		t.Fatalf("covered %d EVEX vector extract register encodings, want 36864", count)
	}
}

func TestDecodedX86VEXTRACTCompleteEVEXMemoryAndInvalidForms(t *testing.T) {
	tests := []struct {
		opcode      byte
		width64     bool
		op          Op
		outputBytes int
		vectorBits  byte
	}{
		{opcode: 0x19, op: "VEXTRACTF32X4", outputBytes: 16, vectorBits: 1},
		{opcode: 0x19, width64: true, op: "VEXTRACTF64X2", outputBytes: 16, vectorBits: 2},
		{opcode: 0x1b, op: "VEXTRACTF32X8", outputBytes: 32, vectorBits: 2},
		{opcode: 0x1b, width64: true, op: "VEXTRACTF64X4", outputBytes: 32, vectorBits: 2},
		{opcode: 0x39, op: "VEXTRACTI32X4", outputBytes: 16, vectorBits: 1},
		{opcode: 0x39, width64: true, op: "VEXTRACTI64X2", outputBytes: 16, vectorBits: 2},
		{opcode: 0x3b, op: "VEXTRACTI32X8", outputBytes: 32, vectorBits: 2},
		{opcode: 0x3b, width64: true, op: "VEXTRACTI64X4", outputBytes: 32, vectorBits: 2},
	}
	for _, test := range tests {
		code := encodeX86EVEXTRACT(test.opcode, 0xff, test.width64, test.vectorBits, 2, false, 21, 0)
		code[5] = 0x68
		code = append(code[:6], append([]byte{0x7f}, code[6:]...)...)
		got, length, ok, err := decodedX86VEXTRACT128Instruction(code, 64)
		wantSourcePrefix := [...]string{"", "Y", "Z"}[test.vectorBits]
		wantDestination := fmt.Sprintf("%d(AX)", test.outputBytes*127)
		if err != nil || !ok || length != len(code) || got.Op != test.op || len(got.Args) != 4 || got.Args[0].Imm != 0xff || got.Args[1].String() != fmt.Sprintf("%s21", wantSourcePrefix) || got.Args[2].String() != "K2" || got.Args[3].String() != wantDestination {
			t.Fatalf("decode %x = %+v, length=%d ok=%v err=%v; want %s $255, %s21, K2, %s", code, got, length, ok, err, test.op, wantSourcePrefix, wantDestination)
		}
	}

	valid := encodeX86EVEXTRACT(0x3b, 1, true, 2, 1, false, 0, 0)
	for name, mutate := range map[string]func([]byte){
		"used vvvv":       func(code []byte) { code[2] &^= 0x08 },
		"broadcast":       func(code []byte) { code[3] |= 0x10 },
		"reserved length": func(code []byte) { code[3] |= 0x20 },
	} {
		code := append([]byte(nil), valid...)
		mutate(code)
		if _, _, matched, decodeErr := decodedX86VEXTRACT128Instruction(code, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x returned ok=%v err=%v", name, code, matched, decodeErr)
		}
	}
	memoryZero := encodeX86EVEXTRACT(0x3b, 1, true, 2, 1, true, 0, 0)
	memoryZero[5] = 0x00
	memoryZero = append(memoryZero[:6], append([]byte{0, 0, 0, 0}, memoryZero[6:]...)...)
	if _, _, matched, decodeErr := decodedX86VEXTRACT128Instruction(memoryZero, 64); !matched || decodeErr == nil {
		t.Fatalf("zeroing memory encoding returned ok=%v err=%v", matched, decodeErr)
	}
}
