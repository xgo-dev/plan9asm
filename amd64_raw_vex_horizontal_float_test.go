package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXHorizontalFloat(opcode, pp byte, vex3, width256, widthIgnored bool, destination, source1, source2 int) []byte {
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

func TestTranslateRawVEXHorizontalFloatWeaviateRegression(t *testing.T) {
	const source = `TEXT rawHorizontal(SB), $0-0
	LONG $0xc07cffc5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawHorizontal": {Name: "rawHorizontal", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "fadd float") {
		t.Fatalf("raw VHADDPS lowering omitted horizontal addition:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-horizontal-float.ll", "amd64-raw-vex-horizontal-float.o", ir)
}

func TestDecodedX86VEXHorizontalFloatCompleteRegisterFamily(t *testing.T) {
	count := 0
	for opcode, stem := range map[byte]string{0x7c: "VHADD", 0x7d: "VHSUB", 0xd0: "VADDSUB"} {
		for pp, suffix := range map[byte]string{1: "PD", 3: "PS"} {
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
									code := encodeX86VEXHorizontalFloat(opcode, pp, vex3, width256, widthIgnored, destination, source1, source2)
									got, length, ok, err := decodedX86VEXHorizontalFloatInstruction(code, 64)
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
	if count != 122880 {
		t.Fatalf("covered %d VEX horizontal and alternating floating register encodings, want 122880", count)
	}
}

func TestTranslateRawVEXAddSubComplexAVX2Regression(t *testing.T) {
	const source = "TEXT rawAddSub(SB),$0-0\n\tLONG $0xc1d0f9c5\n\tRET\n"
	file, err := Parse(ArchAMD64, source)
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
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
				"rawAddSub": {Name: "rawAddSub", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "fsub double") || !strings.Contains(ir, "fadd double") {
				t.Fatalf("VADDSUBPD omitted alternating arithmetic:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "raw-vaddsub.ll", "raw-vaddsub.o", ir)
		})
	}
}

func TestDecodedX86VEXHorizontalFloatMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x64, 0xc4, 0x01, 0xe5, 0x7d, 0x64, 0x88, 0x20}
	got, length, ok, err := decodedX86VEXHorizontalFloatInstruction(code, 64)
	wantSource := MemRef{Segment: FS, Base: "R8", Index: "R9", Scale: 4, Off: 32}
	if err != nil || !ok || length != len(code) || got.Op != "VHSUBPD" || len(got.Args) != 3 || got.Args[0].Kind != OpMem || got.Args[0].Mem != wantSource || got.Args[1].String() != "Y3" || got.Args[2].String() != "Y12" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}
	code[4] = 0xd0
	got, length, ok, err = decodedX86VEXHorizontalFloatInstruction(code, 64)
	if err != nil || !ok || length != len(code) || got.Op != "VADDSUBPD" ||
		got.Args[0].Kind != OpMem || got.Args[0].Mem != wantSource ||
		got.Args[1].String() != "Y3" || got.Args[2].String() != "Y12" {
		t.Fatalf("VADDSUBPD memory source %x decoded as %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86VEXHorizontalFloat(0x7c, 1, true, false, false, 0, 0, 0)
	for _, invalid := range [][]byte{
		{0xc5},
		{0xc4, valid[1] ^ 1, valid[2], valid[3], valid[4]},
		encodeX86VEXHorizontalFloat(0x7e, 1, true, false, false, 0, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXHorizontalFloatInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	invalidPP := encodeX86VEXHorizontalFloat(0x7c, 0, true, false, false, 0, 0, 0)
	if _, _, matched, decodeErr := decodedX86VEXHorizontalFloatInstruction(invalidPP, 64); !matched || decodeErr == nil {
		t.Fatalf("invalid pp encoding %x returned ok=%v err=%v", invalidPP, matched, decodeErr)
	}
	extended := encodeX86VEXHorizontalFloat(0x7c, 1, true, false, false, 8, 8, 8)
	if _, _, matched, decodeErr := decodedX86VEXHorizontalFloatInstruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
}
