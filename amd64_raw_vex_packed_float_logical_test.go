package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86VEXPackedFloatLogicalTestOpcodes = map[byte]string{
	0x54: "VAND",
	0x55: "VANDN",
	0x56: "VOR",
	0x57: "VXOR",
}

func encodeX86VEXPackedFloatLogical(opcode, pp byte, vex3, width256, widthIgnored bool, destination, source1, source2 int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	if !vex3 {
		vex1 := byte((1-destination/8)<<7 | ((^source1)&15)<<3 | int(l)<<2 | int(pp))
		return []byte{0xc5, vex1, opcode, modRM}
	}
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source2/8)<<5 | 1)
	vex1 := byte(((^source1)&15)<<3 | int(l)<<2 | int(pp))
	if widthIgnored {
		vex1 |= 0x80
	}
	return []byte{0xc4, vex0, vex1, opcode, modRM}
}

func TestTranslateRawVEXPackedFloatLogicalWeaviateRegression(t *testing.T) {
	const source = `TEXT rawLogical(SB), $0-0
	WORD $0x8944; BYTE $0xc8
	WORD $0xe083; BYTE $0x03
	LONG $0xc057f8c5
	WORD $0xc931
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawLogical": {Name: "rawLogical", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "xor <4 x i32>") {
		t.Fatalf("raw VXORPS lowering omitted vector xor:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-logical.ll", "amd64-raw-vex-logical.o", ir)
}

func TestDecodedX86VEXPackedFloatLogicalCompleteRegisterFamily(t *testing.T) {
	count := 0
	for opcode, stem := range x86VEXPackedFloatLogicalTestOpcodes {
		for pp, suffix := range map[byte]string{0: "PS", 1: "PD"} {
			for _, vex3 := range []bool{false, true} {
				for _, width256 := range []bool{false, true} {
					prefix := "X"
					if width256 {
						prefix = "Y"
					}
					for _, widthIgnored := range []bool{false, true} {
						if !vex3 && widthIgnored {
							continue
						}
						source2Limit := 16
						if !vex3 {
							source2Limit = 8
						}
						for destination := 0; destination < 16; destination++ {
							for source1 := 0; source1 < 16; source1++ {
								for source2 := 0; source2 < source2Limit; source2++ {
									code := encodeX86VEXPackedFloatLogical(opcode, pp, vex3, width256, widthIgnored, destination, source1, source2)
									got, length, ok, err := decodedX86VEXPackedFloatLogicalInstruction(code, 64)
									if err != nil || !ok || length != len(code) {
										t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
									}
									wantOp := Op(stem + suffix)
									wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), fmt.Sprintf("%s%d", prefix, destination)}
									if got.Op != wantOp || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
										t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
									}
									count++
								}
							}
						}
					}
				}
			}
		}
	}
	if count != 163840 {
		t.Fatalf("covered %d VEX packed floating logical register encodings, want 163840", count)
	}
}

func TestDecodedX86VEXPackedFloatLogicalMemoryForms(t *testing.T) {
	tests := []struct {
		name   string
		code   []byte
		op     Op
		source MemRef
		second Reg
		dest   Reg
	}{
		{name: "base", code: []byte{0xc4, 0xe1, 0x78, 0x57, 0x00}, op: "VXORPS", source: MemRef{Base: AX}, second: "X0", dest: "X0"},
		{name: "extended SIB displacement and FS", code: []byte{0x64, 0xc4, 0x01, 0x65, 0x54, 0x64, 0x88, 0x20}, op: "VANDPD", source: MemRef{Segment: FS, Base: "R8", Index: "R9", Scale: 4, Off: 32}, second: "Y3", dest: "Y12"},
		{name: "base displacement and GS", code: []byte{0x65, 0xc5, 0xec, 0x56, 0x4d, 0x7f}, op: "VORPS", source: MemRef{Segment: GS, Base: BP, Off: 0x7f}, second: "Y2", dest: "Y1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86VEXPackedFloatLogicalInstruction(test.code, 64)
			if err != nil || !ok || length != len(test.code) {
				t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", test.code, got, length, ok, err)
			}
			if got.Op != test.op || len(got.Args) != 3 || got.Args[0].Kind != OpMem || got.Args[0].Mem != test.source || got.Args[1].Kind != OpReg || got.Args[1].Reg != test.second || got.Args[2].Kind != OpReg || got.Args[2].Reg != test.dest {
				t.Fatalf("decode %x = %+v, want %s %+v, %s, %s", test.code, got, test.op, test.source, test.second, test.dest)
			}
		})
	}
}

func TestDecodedX86VEXPackedFloatLogicalRejectsReservedForms(t *testing.T) {
	valid := encodeX86VEXPackedFloatLogical(0x57, 0, true, false, false, 0, 0, 0)
	for _, code := range [][]byte{
		{0xc5},
		{0xc4, valid[1] ^ 1, valid[2], valid[3], valid[4]},
		encodeX86VEXPackedFloatLogical(0x58, 0, true, false, false, 0, 0, 0),
	} {
		if got, _, ok, err := decodedX86VEXPackedFloatLogicalInstruction(code, 64); ok || err != nil {
			t.Fatalf("reserved encoding %x decoded as %+v, ok=%v, err=%v", code, got, ok, err)
		}
	}
	reservedPP := encodeX86VEXPackedFloatLogical(0x57, 2, true, false, false, 0, 0, 0)
	if _, _, ok, err := decodedX86VEXPackedFloatLogicalInstruction(reservedPP, 64); !ok || err == nil {
		t.Fatalf("reserved pp encoding %x returned ok=%v err=%v", reservedPP, ok, err)
	}
	ripRelative := []byte{0xc5, 0xec, 0x56, 0x0d, 0x78, 0x56, 0x34, 0x12}
	if _, _, ok, err := decodedX86VEXPackedFloatLogicalInstruction(ripRelative, 64); !ok || err == nil {
		t.Fatalf("source-layout-unsafe RIP-relative encoding %x returned ok=%v err=%v", ripRelative, ok, err)
	}
	extended := encodeX86VEXPackedFloatLogical(0x57, 0, true, false, false, 8, 8, 8)
	if _, _, ok, err := decodedX86VEXPackedFloatLogicalInstruction(extended, 32); !ok || err == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", ok, err)
	}
}
