package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86VEXBinaryFloatTestOpcodes = map[byte]string{
	0x58: "VADD",
	0x59: "VMUL",
	0x5c: "VSUB",
	0x5d: "VMIN",
	0x5e: "VDIV",
	0x5f: "VMAX",
}

func encodeX86VEXBinaryFloat(opcode, pp byte, vex3, width256, widthIgnored bool, destination, source1, source2 int) []byte {
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

func encodeX86EVEXBinaryFloat(opcode, pp, vectorBits byte, broadcastOrRounding, zeroing bool, mask, destination, source1, source2 int) []byte {
	p0 := byte((1-(destination>>3)&1)<<7 | (1-(source2>>4)&1)<<6 | (1-(source2>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | 1)
	p1 := byte((^source1&15)<<3 | 1<<2 | int(pp))
	if pp == 1 || pp == 3 {
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

func TestTranslateRawVEXBinaryFloatWeaviateRegression(t *testing.T) {
	const source = `TEXT rawBinary(SB), $0-0
	LONG $0x0e5cf2c5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawBinary": {Name: "rawBinary", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "fsub float") {
		t.Fatalf("raw VSUBSS lowering omitted scalar subtraction:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-binary-float.ll", "amd64-raw-vex-binary-float.o", ir)
}

func TestTranslateRawScalarSqrtKelindarRegression(t *testing.T) {
	const source = `TEXT rawScalarSqrt(SB), $0-0
	LONG $0xdc51dac5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawScalarSqrt": {Name: "rawScalarSqrt", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "llvm.sqrt.f32") {
		t.Fatalf("raw VSQRTSS omitted square root:\n%s", ir)
	}
}

func TestDecodedX86RawScalarSqrtCompleteGoRows(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{"VEX single register", []byte{0xc5, 0xea, 0x51, 0xd9}, "VSQRTSS X1, X2, X3"},
		{"VEX double register", []byte{0xc5, 0xeb, 0x51, 0xd9}, "VSQRTSD X1, X2, X3"},
		{"VEX single memory", []byte{0xc5, 0xea, 0x51, 0x18}, "VSQRTSS 0(AX), X2, X3"},
		{"VEX double memory", []byte{0xc5, 0xeb, 0x51, 0x58, 0x10}, "VSQRTSD 16(AX), X2, X3"},
		{"EVEX single mask zero", []byte{0x62, 0xa1, 0x56, 0x81, 0x51, 0xf4}, "VSQRTSS.Z X20, X21, K1, X22"},
		{"EVEX double mask zero", []byte{0x62, 0xa1, 0xd7, 0x81, 0x51, 0xf4}, "VSQRTSD.Z X20, X21, K1, X22"},
		{"EVEX single rounding", []byte{0x62, 0xf1, 0x6e, 0x18, 0x51, 0xd9}, "VSQRTSS.RN_SAE X1, X2, X3"},
		{"EVEX double rounding", []byte{0x62, 0xf1, 0xef, 0x38, 0x51, 0xd9}, "VSQRTSD.RD_SAE X1, X2, X3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, recognized, err := decodedX86VEXBinaryFloatInstruction(test.code, 64)
			if err != nil || !recognized || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decode %x: raw=%q length=%d recognized=%v err=%v; want %q", test.code, instruction.Raw, length, recognized, err, test.want)
			}
		})
	}
}

func TestTranslateRawScalarSqrtLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			encodings := [][]byte{
				{0xc5, 0xea, 0x51, 0xd9},
				{0xc5, 0xeb, 0x51, 0x58, 0x10},
				{0x62, 0xf1, 0x6e, 0x18, 0x51, 0xd9},
				{0x62, 0xf1, 0xef, 0x38, 0x51, 0xd9},
			}
			if target.goarch == "amd64" {
				encodings = append(encodings,
					[]byte{0x62, 0xa1, 0x56, 0x81, 0x51, 0xf4},
					[]byte{0x62, 0xa1, 0xd7, 0x81, 0x51, 0xf4},
				)
			}
			var source strings.Builder
			source.WriteString("TEXT rawScalarSqrtFamily(SB), $0-0\n")
			for _, code := range encodings {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawScalarSqrtFamily": {Name: "rawScalarSqrtFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-scalar-sqrt.ll", "raw-scalar-sqrt.o", ir)
		})
	}
}

func TestTranslateRawEVEXBinaryFloatWeaviateRegression(t *testing.T) {
	const source = `TEXT rawBinaryEVEX(SB), $0-0
	LONG $0x48347162
	WORD $0x0e5c
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawBinaryEVEX": {Name: "rawBinaryEVEX", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "fsub <16 x float>") {
		t.Fatalf("raw EVEX VSUBPS lowering omitted packed subtraction:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-evex-binary-float.ll", "amd64-raw-evex-binary-float.o", ir)
}

func TestDecodedX86VEXBinaryFloatCompleteRegisterFamily(t *testing.T) {
	count := 0
	suffixes := map[byte]string{0: "PS", 1: "PD", 2: "SS", 3: "SD"}
	for opcode, stem := range x86VEXBinaryFloatTestOpcodes {
		for pp, suffix := range suffixes {
			scalar := pp >= 2
			for _, vex3 := range []bool{false, true} {
				widths := []bool{false, true}
				if scalar {
					widths = []bool{false}
				}
				for _, width256 := range widths {
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
									code := encodeX86VEXBinaryFloat(opcode, pp, vex3, width256, widthIgnored, destination, source1, source2)
									got, length, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64)
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
	if count != 368640 {
		t.Fatalf("covered %d VEX binary floating register encodings, want 368640", count)
	}
}

func TestDecodedX86EVEXBinaryFloatCompleteRegisterFamily(t *testing.T) {
	count := 0
	suffixes := map[byte]string{0: "PS", 1: "PD", 2: "SS", 3: "SD"}
	for opcode, stem := range x86VEXBinaryFloatTestOpcodes {
		for pp, suffix := range suffixes {
			vectorLengths := []byte{0, 1, 2}
			for _, vectorBits := range vectorLengths {
				prefix := [...]string{"X", "Y", "Z"}[vectorBits]
				if pp >= 2 {
					prefix = "X"
				}
				for destination := 0; destination < 32; destination++ {
					for source1 := 0; source1 < 32; source1++ {
						for source2 := 0; source2 < 32; source2++ {
							code := encodeX86EVEXBinaryFloat(opcode, pp, vectorBits, false, false, 1, destination, source1, source2)
							got, length, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64)
							if err != nil || !ok || length != len(code) {
								t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
							}
							wantOp := Op(stem + suffix)
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
	if count != 2359296 {
		t.Fatalf("covered %d EVEX binary floating register encodings, want 2359296", count)
	}
}

func TestDecodedX86EVEXBinaryFloatModifiersAndMemory(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		op   Op
		args []string
	}{
		{name: "packed zeroing", code: encodeX86EVEXBinaryFloat(0x58, 0, 1, false, true, 3, 29, 28, 21), op: "VADDPS.Z", args: []string{"Y21", "Y28", "K3", "Y29"}},
		{name: "packed broadcast zeroing", code: []byte{0x62, 0xf1, 0xed, 0xd9, 0x58, 0x08}, op: "VADDPD.BCST.Z", args: []string{"0(AX)", "Z2", "K1", "Z1"}},
		{name: "packed round nearest", code: []byte{0x62, 0xf1, 0xed, 0x19, 0x58, 0xcb}, op: "VADDPD.RN_SAE", args: []string{"Z3", "Z2", "K1", "Z1"}},
		{name: "packed round down", code: []byte{0x62, 0xf1, 0xed, 0x39, 0x58, 0xcb}, op: "VADDPD.RD_SAE", args: []string{"Z3", "Z2", "K1", "Z1"}},
		{name: "packed round up", code: []byte{0x62, 0xf1, 0xed, 0x59, 0x58, 0xcb}, op: "VADDPD.RU_SAE", args: []string{"Z3", "Z2", "K1", "Z1"}},
		{name: "packed round zero zeroing", code: []byte{0x62, 0xf1, 0xed, 0xf9, 0x58, 0xcb}, op: "VADDPD.RZ_SAE.Z", args: []string{"Z3", "Z2", "K1", "Z1"}},
		{name: "packed sae", code: []byte{0x62, 0xf1, 0xed, 0x59, 0x5f, 0xcb}, op: "VMAXPD.SAE", args: []string{"Z3", "Z2", "K1", "Z1"}},
		{name: "scalar round up", code: encodeX86EVEXBinaryFloat(0x5c, 2, 2, true, false, 2, 5, 6, 7), op: "VSUBSS.RU_SAE", args: []string{"X7", "X6", "K2", "X5"}},
		{name: "scalar sae zeroing", code: encodeX86EVEXBinaryFloat(0x5d, 3, 0, true, true, 4, 8, 9, 10), op: "VMINSD.SAE.Z", args: []string{"X10", "X9", "K4", "X8"}},
		{name: "compressed memory", code: []byte{0x62, 0x71, 0x34, 0x48, 0x5c, 0x4e, 0x02}, op: "VSUBPS", args: []string{"128(SI)", "Z9", "Z9"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86VEXBinaryFloatInstruction(test.code, 64)
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

	scalarBroadcast := encodeX86EVEXBinaryFloat(0x58, 2, 0, true, false, 0, 0, 0, 0)
	scalarBroadcast[len(scalarBroadcast)-1] = 0
	wrongW := encodeX86EVEXBinaryFloat(0x58, 0, 0, false, false, 0, 0, 0, 0)
	wrongW[2] ^= 0x80
	invalid := [][]byte{
		encodeX86EVEXBinaryFloat(0x58, 0, 0, false, true, 0, 0, 0, 0),
		encodeX86EVEXBinaryFloat(0x58, 0, 3, false, false, 0, 0, 0, 0),
		scalarBroadcast,
		wrongW,
	}
	for _, code := range invalid {
		if _, _, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid EVEX encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}

	mode32 := encodeX86EVEXBinaryFloat(0x58, 0, 0, false, false, 1, 0, 0, 0)
	if _, _, ok, err := decodedX86VEXBinaryFloatInstruction(mode32, 32); !ok || err == nil {
		t.Fatalf("masked EVEX form in 32-bit mode returned ok=%v err=%v", ok, err)
	}
}

func TestDecodedX86VEXBinaryFloatMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x64, 0xc4, 0x01, 0xe5, 0x58, 0x64, 0x88, 0x20}
	got, length, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64)
	wantSource := MemRef{Segment: FS, Base: "R8", Index: "R9", Scale: 4, Off: 32}
	if err != nil || !ok || length != len(code) || got.Op != "VADDPD" || len(got.Args) != 3 || got.Args[0].Kind != OpMem || got.Args[0].Mem != wantSource || got.Args[1].String() != "Y3" || got.Args[2].String() != "Y12" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86VEXBinaryFloat(0x58, 0, true, false, false, 0, 0, 0)
	for _, invalid := range [][]byte{
		{0xc5},
		{0xc4, valid[1] ^ 1, valid[2], valid[3], valid[4]},
		encodeX86VEXBinaryFloat(0x5a, 0, true, false, false, 0, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXBinaryFloatInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	scalarY := encodeX86VEXBinaryFloat(0x58, 2, true, true, false, 0, 0, 0)
	if _, _, matched, decodeErr := decodedX86VEXBinaryFloatInstruction(scalarY, 64); !matched || decodeErr == nil {
		t.Fatalf("scalar VEX.256 encoding %x returned ok=%v err=%v", scalarY, matched, decodeErr)
	}
	extended := encodeX86VEXBinaryFloat(0x58, 0, true, false, false, 8, 8, 8)
	if _, _, matched, decodeErr := decodedX86VEXBinaryFloatInstruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
}
