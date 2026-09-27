package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXFMA3(opcode byte, width64, width256 bool, destination, source1, source2 int) []byte {
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source2/8)<<5 | 2)
	vex1 := byte(((^source1)&15)<<3 | 1)
	if width64 {
		vex1 |= 0x80
	}
	if width256 {
		vex1 |= 0x04
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	return []byte{0xc4, vex0, vex1, opcode, modRM}
}

func encodeX86EVEXFMA3(opcode byte, width64 bool, vectorBits byte, broadcastOrRounding, zeroing bool, mask, destination, source1, source2 int) []byte {
	p0 := byte((1-(destination>>3)&1)<<7 | (1-(source2>>4)&1)<<6 | (1-(source2>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | 2)
	p1 := byte((^source1&15)<<3 | 1<<2 | 1)
	if width64 {
		p1 |= 0x80
	}
	p2 := byte(int(vectorBits)<<5 | (^source1>>4&1)<<3 | mask)
	if broadcastOrRounding {
		p2 |= 0x10
	}
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM}
}

func TestTranslateRawVEXFMA3WeaviateRegression(t *testing.T) {
	const source = `TEXT rawFMA(SB), $0-0
	LONG $0x985de2c4; BYTE $0x1e
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawFMA": {Name: "rawFMA", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "@llvm.fma.v8f32") {
		t.Fatalf("raw VFMADD132PS lowering omitted vector FMA:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-fma3.ll", "amd64-raw-vex-fma3.o", ir)
}

func TestTranslateRawEVEXFMA3WeaviateRegression(t *testing.T) {
	const source = `TEXT rawFMAEVEX(SB), $0-0
	LONG $0x4835d262; WORD $0xc9b8
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawFMAEVEX": {Name: "rawFMAEVEX", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "@llvm.fma.v16f32") {
		t.Fatalf("raw EVEX VFMADD231PS lowering omitted vector FMA:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-evex-fma3.ll", "amd64-raw-evex-fma3.o", ir)
}

func TestDecodedX86VEXFMA3CompleteRegisterFamily(t *testing.T) {
	count := 0
	for opcode, spec := range decodedX86VEXFMA3Ops {
		for _, width64 := range []bool{false, true} {
			widths := []bool{false, true}
			if spec.scalar {
				widths = []bool{false}
			}
			for _, width256 := range widths {
				prefix := "X"
				if width256 {
					prefix = "Y"
				}
				for destination := 0; destination < 16; destination++ {
					for source1 := 0; source1 < 16; source1++ {
						for source2 := 0; source2 < 16; source2++ {
							code := encodeX86VEXFMA3(opcode, width64, width256, destination, source1, source2)
							got, length, ok, err := decodedX86VEXFMA3Instruction(code, 64)
							if err != nil || !ok || length != len(code) {
								t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
							}
							wantOp := spec.op(width64)
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
	if count != 393216 {
		t.Fatalf("covered %d VEX FMA3 register encodings, want 393216", count)
	}
}

func TestDecodedX86EVEXFMA3CompleteRegisterFamily(t *testing.T) {
	count := 0
	for opcode, spec := range decodedX86VEXFMA3Ops {
		for _, width64 := range []bool{false, true} {
			vectorLengths := []byte{0, 1, 2}
			for _, vectorBits := range vectorLengths {
				prefix := [...]string{"X", "Y", "Z"}[vectorBits]
				if spec.scalar {
					prefix = "X"
				}
				for destination := 0; destination < 32; destination++ {
					for source1 := 0; source1 < 32; source1++ {
						for source2 := 0; source2 < 32; source2++ {
							code := encodeX86EVEXFMA3(opcode, width64, vectorBits, false, false, 1, destination, source1, source2)
							got, length, ok, err := decodedX86VEXFMA3Instruction(code, 64)
							if err != nil || !ok || length != len(code) {
								t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
							}
							wantOp := spec.op(width64)
							wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), "K1", fmt.Sprintf("%s%d", prefix, destination)}
							if got.Op != wantOp || len(got.Args) != 4 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] || got.Args[3].String() != wantArgs[3] {
								t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 5898240 {
		t.Fatalf("covered %d EVEX FMA3 register encodings, want 5898240", count)
	}
}

func TestDecodedX86EVEXFMA3ModifiersAndMemory(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		op   Op
		args []string
	}{
		{name: "packed zeroing", code: encodeX86EVEXFMA3(0xb8, false, 1, false, true, 3, 29, 28, 21), op: "VFMADD231PS.Z", args: []string{"Y21", "Y28", "K3", "Y29"}},
		{name: "packed broadcast zeroing", code: []byte{0x62, 0xf2, 0xed, 0xd9, 0x98, 0x08}, op: "VFMADD132PD.BCST.Z", args: []string{"0(AX)", "Z2", "K1", "Z1"}},
		{name: "packed round nearest", code: encodeX86EVEXFMA3(0xa8, true, 0, true, false, 1, 1, 2, 3), op: "VFMADD213PD.RN_SAE", args: []string{"Z3", "Z2", "K1", "Z1"}},
		{name: "packed round down", code: encodeX86EVEXFMA3(0xba, false, 1, true, false, 2, 4, 5, 6), op: "VFMSUB231PS.RD_SAE", args: []string{"Z6", "Z5", "K2", "Z4"}},
		{name: "packed round up", code: encodeX86EVEXFMA3(0x9c, true, 2, true, false, 3, 7, 8, 9), op: "VFNMADD132PD.RU_SAE", args: []string{"Z9", "Z8", "K3", "Z7"}},
		{name: "packed round zero zeroing", code: encodeX86EVEXFMA3(0xae, false, 3, true, true, 4, 10, 11, 12), op: "VFNMSUB213PS.RZ_SAE.Z", args: []string{"Z12", "Z11", "K4", "Z10"}},
		{name: "scalar round up", code: encodeX86EVEXFMA3(0xb9, false, 2, true, false, 5, 13, 14, 15), op: "VFMADD231SS.RU_SAE", args: []string{"X15", "X14", "K5", "X13"}},
		{name: "compressed memory", code: []byte{0x62, 0xd2, 0x35, 0x48, 0xb8, 0x49, 0x02}, op: "VFMADD231PS", args: []string{"128(R9)", "Z9", "Z1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86VEXFMA3Instruction(test.code, 64)
			if err != nil || !ok || length != len(test.code) {
				t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", test.code, got, length, ok, err)
			}
			if got.Op != test.op || len(got.Args) != len(test.args) {
				t.Fatalf("decode %x = %+v, want %s %s", test.code, got, test.op, strings.Join(test.args, ", "))
			}
			for index := range test.args {
				if got.Args[index].String() != test.args[index] {
					t.Fatalf("decode %x = %+v, want %s %s", test.code, got, test.op, strings.Join(test.args, ", "))
				}
			}
		})
	}

	scalarBroadcast := encodeX86EVEXFMA3(0x99, false, 0, true, false, 0, 0, 0, 0)
	scalarBroadcast[len(scalarBroadcast)-1] = 0
	wrongPP := encodeX86EVEXFMA3(0x98, false, 0, false, false, 0, 0, 0, 0)
	wrongPP[2] &^= 1
	invalid := [][]byte{
		encodeX86EVEXFMA3(0x98, false, 0, false, true, 0, 0, 0, 0),
		encodeX86EVEXFMA3(0x98, false, 3, false, false, 0, 0, 0, 0),
		scalarBroadcast,
		wrongPP,
	}
	for _, code := range invalid {
		if _, _, ok, err := decodedX86VEXFMA3Instruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid EVEX encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}

	mode32 := encodeX86EVEXFMA3(0x98, false, 0, false, false, 1, 0, 0, 0)
	if _, _, ok, err := decodedX86VEXFMA3Instruction(mode32, 32); !ok || err == nil {
		t.Fatalf("masked EVEX form in 32-bit mode returned ok=%v err=%v", ok, err)
	}
}

func TestDecodedX86VEXFMA3MemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x64, 0xc4, 0x02, 0xe5, 0x98, 0x64, 0x88, 0x20}
	got, length, ok, err := decodedX86VEXFMA3Instruction(code, 64)
	wantSource := MemRef{Segment: FS, Base: "R8", Index: "R9", Scale: 4, Off: 32}
	if err != nil || !ok || length != len(code) || got.Op != "VFMADD132PD" || len(got.Args) != 3 || got.Args[0].Kind != OpMem || got.Args[0].Mem != wantSource || got.Args[1].String() != "Y3" || got.Args[2].String() != "Y12" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86VEXFMA3(0x98, false, false, 0, 0, 0)
	for _, invalid := range [][]byte{
		{0xc4},
		{valid[0], valid[1] ^ 3, valid[2], valid[3], valid[4]},
		encodeX86VEXFMA3(0x95, false, false, 0, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXFMA3Instruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	invalidPP := []byte{valid[0], valid[1], valid[2] &^ 1, valid[3], valid[4]}
	if _, _, matched, decodeErr := decodedX86VEXFMA3Instruction(invalidPP, 64); !matched || decodeErr == nil {
		t.Fatalf("invalid pp encoding %x returned ok=%v err=%v", invalidPP, matched, decodeErr)
	}
	scalarY := encodeX86VEXFMA3(0x99, false, true, 0, 0, 0)
	if _, _, matched, decodeErr := decodedX86VEXFMA3Instruction(scalarY, 64); !matched || decodeErr == nil {
		t.Fatalf("scalar VEX.256 encoding %x returned ok=%v err=%v", scalarY, matched, decodeErr)
	}
	extended := encodeX86VEXFMA3(0x98, false, false, 8, 8, 8)
	if _, _, matched, decodeErr := decodedX86VEXFMA3Instruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
}
