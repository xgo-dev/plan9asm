package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86RawBroadcastLiteral(op Op, encoding string, vectorBits, mask int, zeroing bool) ([]byte, int64) {
	opcode := map[Op]byte{
		"VPBROADCASTB": 0x78,
		"VPBROADCASTW": 0x79,
		"VPBROADCASTD": 0x58,
		"VPBROADCASTQ": 0x59,
	}[op]
	width := map[Op]int{
		"VPBROADCASTB": 1,
		"VPBROADCASTW": 2,
		"VPBROADCASTD": 4,
		"VPBROADCASTQ": 8,
	}[op]
	value := int64(0)
	data := make([]byte, width)
	for i := range data {
		data[i] = byte(0x11 + i*0x22)
		value |= int64(data[i]) << (8 * i)
	}

	var code []byte
	if encoding == "VEX" {
		p2 := byte(0x79)
		if vectorBits == 256 {
			p2 |= 0x04
		}
		code = []byte{0xc4, 0xe2, p2, opcode, 0x05, 1, 0, 0, 0}
	} else {
		p1 := byte(0x7d)
		if op == "VPBROADCASTQ" {
			p1 |= 0x80
		}
		lengthBits := map[int]byte{128: 0, 256: 1, 512: 2}[vectorBits]
		p2 := lengthBits<<5 | 0x08 | byte(mask)
		if zeroing {
			p2 |= 0x80
		}
		code = []byte{0x62, 0xf2, p1, p2, opcode, 0x05, 1, 0, 0, 0}
	}
	code = append(code, 0xc3)
	code = append(code, data...)
	return code, value
}

func TestDecodeX86RawPackedBroadcastRIPLiteralCompleteFamily(t *testing.T) {
	for _, op := range []Op{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
		for _, encoding := range []string{"VEX", "EVEX"} {
			for _, vectorBits := range []int{128, 256, 512} {
				if encoding == "VEX" && vectorBits == 512 {
					continue
				}
				for _, masking := range []struct {
					mask    int
					zeroing bool
				}{
					{},
					{mask: 3},
					{mask: 7, zeroing: true},
				} {
					if encoding == "VEX" && masking.mask != 0 {
						continue
					}
					name := fmt.Sprintf("%s/%s/%d/mask%d/zero%t", op, encoding, vectorBits, masking.mask, masking.zeroing)
					t.Run(name, func(t *testing.T) {
						code, value := x86RawBroadcastLiteral(op, encoding, vectorBits, masking.mask, masking.zeroing)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						if len(decoded) != 2 || decoded[0].Op != op && decoded[0].Op != op+".Z" ||
							len(decoded[0].Args) < 2 || decoded[0].Args[0].Kind != OpImm ||
							decoded[0].Args[0].Imm != value || !decoded[0].x86Encoded || decoded[1].Op != OpRET {
							t.Fatalf("decoded %x as %#v, want a literal %s and RET", code, decoded, op)
						}
					})
				}
			}
		}
	}
}

func TestTranslateX86RawPackedBroadcastRIPLiteralObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, op := range []Op{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
		name := fmt.Sprintf("literalBroadcast%d", index)
		code, _ := x86RawBroadcastLiteral(op, "EVEX", 512, 3, false)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-broadcast-literal.ll", "raw-broadcast-literal.o", ir)
		})
	}
}

func TestDecodeX86RawPackedBroadcastRIPLiteralRejectsExecutableAndMissingData(t *testing.T) {
	for _, displacement := range []byte{0xf7, 0xf6, 0x20} {
		code, _ := x86RawBroadcastLiteral("VPBROADCASTD", "VEX", 256, 0, false)
		code[5] = displacement
		if displacement != 0x20 {
			copy(code[6:9], []byte{0xff, 0xff, 0xff})
		}
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "invalid RIP literal", map[string]bool{}); err == nil {
			t.Fatalf("accepted RIP literal displacement %#x", displacement)
		}
	}
	code, _ := x86RawBroadcastLiteral("VPBROADCASTQ", "EVEX", 512, 0, false)
	code[6] = 5 // Only the last four bytes remain; a QWORD read is truncated.
	if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "truncated RIP literal", map[string]bool{}); err == nil {
		t.Fatal("accepted truncated RIP-relative QWORD literal")
	}

	for _, prefix := range []byte{0x64, 0x65, 0x67} {
		code, _ := x86RawBroadcastLiteral("VPBROADCASTD", "VEX", 256, 0, false)
		code = append([]byte{prefix}, code...)
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "prefixed RIP literal", map[string]bool{}); err == nil {
			t.Fatalf("folded a source with prefix %#x", prefix)
		}
	}
}

func TestDecodeX86RawPackedBroadcastRIPLiteralDoesNotChange386AbsoluteMemory(t *testing.T) {
	code, _ := x86RawBroadcastLiteral("VPBROADCASTD", "VEX", 256, 0, false)
	decoded, err := decodeX86RawDirectiveGroup(code, 32, 0, "386 absolute source", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) < 1 || decoded[0].Args[0].Kind != OpMem || decoded[0].x86RIPLiteral {
		t.Fatalf("changed a 386 absolute memory operand into a literal: %#v", decoded)
	}
}

func TestTranslateX86RawPackedBroadcastRIPLiteralRejectsAddressObservedText(t *testing.T) {
	code, _ := x86RawBroadcastLiteral("VPBROADCASTD", "VEX", 256, 0, false)
	var source strings.Builder
	source.WriteString("TEXT address(SB),$0-0\n\tLEAQ raw+1(SB), AX\n\tRET\n")
	source.WriteString("TEXT raw(SB),$0-0\n\tMOVQ AX, AX\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"address": {Name: "address", Ret: Void},
			"raw":     {Name: "raw", Ret: Void},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "address-observed RIP-relative raw literal") {
		t.Fatalf("address-observed raw TEXT was silently folded: %v", err)
	}
}

func x86RawVMOVIntegerLiteral(encoding string, width int, alternateQ bool) ([]byte, int64) {
	var code []byte
	switch encoding {
	case "VEX2":
		if alternateQ {
			code = []byte{0xc5, 0xfa, 0x7e, 0x05}
		} else {
			code = []byte{0xc5, 0xf9, 0x6e, 0x05}
		}
	case "VEX3":
		p1 := byte(0x79)
		if width == 8 {
			p1 |= 0x80
		}
		opcode := byte(0x6e)
		if alternateQ {
			p1 = 0x7a
			opcode = 0x7e
		}
		code = []byte{0xc4, 0xe1, p1, opcode, 0x05}
	case "EVEX":
		p1 := byte(0x7d)
		if width == 8 {
			p1 |= 0x80
		}
		opcode := byte(0x6e)
		if alternateQ {
			p1 = 0xfe
			opcode = 0x7e
		}
		code = []byte{0x62, 0xf1, p1, 0x08, opcode, 0x05}
	}
	code = append(code, 1, 0, 0, 0, 0xc3)
	var value int64
	for index := 0; index < width; index++ {
		b := byte(0x13 + index*0x11)
		code = append(code, b)
		value |= int64(b) << (8 * index)
	}
	return code, value
}

func TestDecodeX86RawVMOVIntegerRIPLiteralCompleteLoadForms(t *testing.T) {
	for _, test := range []struct {
		encoding   string
		width      int
		alternateQ bool
	}{
		{"VEX2", 4, false},
		{"VEX3", 4, false},
		{"EVEX", 4, false},
		{"VEX2", 8, true},
		{"VEX3", 8, false},
		{"VEX3", 8, true},
		{"EVEX", 8, false},
		{"EVEX", 8, true},
	} {
		name := fmt.Sprintf("%s/%d/alternate%t", test.encoding, test.width, test.alternateQ)
		t.Run(name, func(t *testing.T) {
			code, value := x86RawVMOVIntegerLiteral(test.encoding, test.width, test.alternateQ)
			decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			op := Op("VMOVD")
			if test.width == 8 {
				op = "VMOVQ"
			}
			if len(decoded) != 2 || decoded[0].Op != op || len(decoded[0].Args) != 2 ||
				decoded[0].Args[0].Kind != OpImm || decoded[0].Args[0].Imm != value ||
				!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET {
				t.Fatalf("decoded %x as %#v, want %s literal load and RET", code, decoded, op)
			}
		})
	}
}

func TestTranslateX86RawVMOVIntegerRIPLiteralObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, test := range []struct {
		encoding   string
		width      int
		alternateQ bool
	}{
		{"VEX2", 4, false}, {"VEX3", 4, false}, {"EVEX", 4, false},
		{"VEX2", 8, true}, {"VEX3", 8, false}, {"VEX3", 8, true},
		{"EVEX", 8, false}, {"EVEX", 8, true},
	} {
		name := fmt.Sprintf("literalVMOV%d", index)
		code, _ := x86RawVMOVIntegerLiteral(test.encoding, test.width, test.alternateQ)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-vmov-literal.ll", "raw-vmov-literal.o", ir)
		})
	}
}

func TestDecodeX86RawVMOVIntegerRIPLiteralRejectsUnsafeSources(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{name: "inside_instruction", edit: func(code []byte) []byte {
			copy(code[5:9], []byte{0xfa, 0xff, 0xff, 0xff}) // Target the opcode.
			return code
		}},
		{name: "missing_pool", edit: func(code []byte) []byte {
			code[5] = 0x20
			return code
		}},
		{name: "truncated_pool", edit: func(code []byte) []byte {
			code[5] = 5 // Only the last four bytes remain.
			return code
		}},
		{name: "segment_override", edit: func(code []byte) []byte {
			return append([]byte{0x64}, code...)
		}},
		{name: "address_override", edit: func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, _ := x86RawVMOVIntegerLiteral("VEX3", 8, false)
			code = test.edit(code)
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, test.name, map[string]bool{}); err == nil {
				t.Fatalf("folded unsafe raw VMOVQ source: %x", code)
			}
		})
	}
}

func TestTranslateX86RawVMOVIntegerRIPLiteralRejectsAddressObservedText(t *testing.T) {
	code, _ := x86RawVMOVIntegerLiteral("VEX3", 8, false)
	var source strings.Builder
	source.WriteString("TEXT address(SB),$0-0\n\tLEAQ raw+1(SB), AX\n\tRET\n")
	source.WriteString("TEXT raw(SB),$0-0\n\tMOVQ AX, AX\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"address": {Name: "address", Ret: Void},
			"raw":     {Name: "raw", Ret: Void},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "address-observed RIP-relative raw literal") {
		t.Fatalf("address-observed raw TEXT was silently folded: %v", err)
	}
}

func x86RawScalarFloatBroadcastLiteral(double, evex bool, vectorBits, mask int, zeroing bool) ([]byte, int64) {
	opcode := byte(0x18)
	width := 4
	if double {
		opcode = 0x19
		width = 8
	}
	var code []byte
	if evex {
		p1 := byte(0x7d)
		if double {
			p1 |= 0x80
		}
		p2 := byte(map[int]int{128: 0, 256: 1, 512: 2}[vectorBits]<<5 | 0x08 | mask)
		if zeroing {
			p2 |= 0x80
		}
		code = []byte{0x62, 0xf2, p1, p2, opcode, 0x05}
	} else {
		p1 := byte(0x79)
		if vectorBits == 256 {
			p1 |= 0x04
		}
		code = []byte{0xc4, 0xe2, p1, opcode, 0x05}
	}
	code = append(code, 1, 0, 0, 0, 0xc3)
	var value int64
	for index := 0; index < width; index++ {
		b := byte(0x21 + index*0x13)
		code = append(code, b)
		value |= int64(b) << (8 * index)
	}
	return code, value
}

func TestDecodeX86RawScalarFloatBroadcastRIPLiteral(t *testing.T) {
	for _, test := range []struct {
		double, evex bool
		vectorBits   int
		mask         int
		zeroing      bool
	}{
		{vectorBits: 128}, {vectorBits: 256}, {double: true, vectorBits: 256},
		{evex: true, vectorBits: 128}, {evex: true, vectorBits: 256, mask: 3},
		{evex: true, vectorBits: 512, mask: 7, zeroing: true},
		{double: true, evex: true, vectorBits: 256},
		{double: true, evex: true, vectorBits: 512, mask: 7, zeroing: true},
	} {
		name := fmt.Sprintf("double%t/evex%t/%d/mask%d/zero%t", test.double, test.evex, test.vectorBits, test.mask, test.zeroing)
		t.Run(name, func(t *testing.T) {
			code, value := x86RawScalarFloatBroadcastLiteral(test.double, test.evex, test.vectorBits, test.mask, test.zeroing)
			decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			op := Op("VBROADCASTSS")
			if test.double {
				op = "VBROADCASTSD"
			}
			if test.zeroing {
				op += ".Z"
			}
			if len(decoded) != 2 || decoded[0].Op != op ||
				decoded[0].Args[0].Kind != OpImm || decoded[0].Args[0].Imm != value ||
				!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET {
				t.Fatalf("decoded %x as %#v, want scalar broadcast of literal", code, decoded)
			}
		})
	}
}

func TestTranslateX86RawScalarFloatBroadcastRIPLiteralObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, test := range []struct {
		double, evex bool
		vectorBits   int
		mask         int
		zeroing      bool
	}{
		{vectorBits: 128}, {vectorBits: 256}, {double: true, vectorBits: 256},
		{evex: true, vectorBits: 128}, {evex: true, vectorBits: 256, mask: 3},
		{evex: true, vectorBits: 512, mask: 7, zeroing: true},
		{double: true, evex: true, vectorBits: 256},
		{double: true, evex: true, vectorBits: 512, mask: 7, zeroing: true},
	} {
		name := fmt.Sprintf("scalarFloatLiteral%d", index)
		code, _ := x86RawScalarFloatBroadcastLiteral(test.double, test.evex, test.vectorBits, test.mask, test.zeroing)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "scalar-float-literal.ll", "scalar-float-literal.o", ir)
		})
	}
}

func TestDecodeX86RawScalarFloatBroadcastRIPLiteralRejectsUnsafeSources(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{name: "instruction_overlap", edit: func(code []byte) []byte {
			copy(code[6:10], []byte{0xfa, 0xff, 0xff, 0xff})
			return code
		}},
		{name: "outside_group", edit: func(code []byte) []byte {
			code[6] = 0x20
			return code
		}},
		{name: "segment_override", edit: func(code []byte) []byte {
			return append([]byte{0x65}, code...)
		}},
		{name: "address_override", edit: func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, _ := x86RawScalarFloatBroadcastLiteral(true, true, 512, 0, false)
			code = test.edit(code)
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, test.name, map[string]bool{}); err == nil {
				t.Fatalf("folded unsafe scalar broadcast source: %x", code)
			}
		})
	}
}
