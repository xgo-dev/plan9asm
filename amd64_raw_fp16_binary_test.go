package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var rawFP16BinaryOpcodes = map[byte]Op{
	0x58: "VADDPH",
	0x59: "VMULPH",
	0x5c: "VSUBPH",
	0x5d: "VMINPH",
	0x5e: "VDIVPH",
	0x5f: "VMAXPH",
}

func encodeRawFP16Binary(opcode, width byte, source1, source2, destination, mask int, memory, broadcast, zero bool) []byte {
	code := encodeX86EVEXBinaryFloat(opcode, 0, width, broadcast, zero, mask, destination, source1, source2)
	code[1] = code[1]&^byte(0x0f) | 5
	if memory {
		code[5] = byte(0x40 | (destination&7)<<3)
		code = append(code, 1)
	}
	return code
}

func TestDecodeRawFP16BinaryGoATReproduction(t *testing.T) {
	// VADDPH 64(SI)(R8*2), Z1, Z1 from go-highway's GoAT output.
	code := []byte{0x62, 0xb5, 0x74, 0x48, 0x58, 0x4c, 0x46, 0x01}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "GoAT VADDPH", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VADDPH" {
		t.Fatalf("decoded %#v, want one VADDPH", decoded)
	}
}

func TestDecodeRawFP16BinaryCompleteForms(t *testing.T) {
	for opcode, baseOp := range rawFP16BinaryOpcodes {
		for width := byte(0); width < 3; width++ {
			for _, memory := range []bool{false, true} {
				for _, broadcast := range []bool{false, true} {
					if broadcast && !memory {
						continue
					}
					for _, masked := range []bool{false, true} {
						mask := 0
						if masked {
							mask = 3
						}
						for _, zero := range []bool{false, true} {
							if zero && !masked {
								continue
							}
							code := encodeRawFP16Binary(opcode, width, 20, 21, 22, mask, memory, broadcast, zero)
							got, length, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64)
							if err != nil || !ok || length != len(code) {
								t.Fatalf("%x: decoded %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
							}
							wantOp := baseOp
							if broadcast {
								wantOp += ".BCST"
							}
							if zero {
								wantOp += ".Z"
							}
							prefix := [...]string{"X", "Y", "Z"}[width]
							if got.Op != wantOp || !got.x86Encoded ||
								got.Args[len(got.Args)-1].String() != fmt.Sprintf("%s22", prefix) ||
								got.Args[1].String() != fmt.Sprintf("%s20", prefix) {
								t.Fatalf("%x: decoded %+v, want %s on %s", code, got, wantOp, prefix)
							}
							if !memory && got.Args[0].String() != fmt.Sprintf("%s21", prefix) {
								t.Fatalf("%x: wrong register source %+v", code, got)
							}
							if masked && (len(got.Args) != 4 || got.Args[2].String() != "K3") {
								t.Fatalf("%x: missing mask %+v", code, got)
							}
						}
					}
				}
			}
		}
	}
}

func TestTranslateRawFP16BinaryLLVM22Targets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawFP16Binary(SB),4,$0-0\n")
	for opcode := range rawFP16BinaryOpcodes {
		for width := byte(0); width < 3; width++ {
			for _, memory := range []bool{false, true} {
				code := encodeRawFP16Binary(opcode, width, 1, 2, 3, 1, memory, memory, true)
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
		}
	}
	source.WriteString("\tRET\n")
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
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawFP16Binary": {Name: "rawFP16Binary", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "fadd <8 x half>") ||
				!strings.Contains(ir, "fsub <16 x half>") ||
				!strings.Contains(ir, "fdiv <32 x half>") ||
				!strings.Contains(ir, "load i16, ptr") {
				t.Fatalf("missing FP16 lane operation or broadcast:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "raw-fp16-binary.ll", "raw-fp16-binary.o", ir)
		})
	}
}

func TestDecodeRawFP16BinaryEmbeddedControlAndRejections(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawFP16Control(SB),4,$0-0\n")
	for opcode, baseOp := range rawFP16BinaryOpcodes {
		for control := byte(0); control < 4; control++ {
			code := encodeRawFP16Binary(opcode, control, 1, 2, 3, 1, false, true, true)
			got, length, ok, err := decodedX86VEXBinaryFloatInstruction(code, 64)
			if err != nil || !ok || length != len(code) {
				t.Fatalf("embedded control %x: %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
			}
			want := baseOp + ".SAE.Z"
			if opcode != 0x5d && opcode != 0x5f {
				want = baseOp + "." + [...]Op{"RN_SAE.Z", "RD_SAE.Z", "RU_SAE.Z", "RZ_SAE.Z"}[control]
			}
			if got.Op != want || got.Args[0].String() != "Z2" ||
				got.Args[1].String() != "Z1" || got.Args[2].String() != "K1" ||
				got.Args[3].String() != "Z3" {
				t.Fatalf("embedded control %x: %+v, want %s Z2,Z1,K1,Z3", code, got, want)
			}
			for _, value := range code {
				fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"rawFP16Control": {Name: "rawFP16Control", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "llvm.experimental.constrained.fadd.v32f16") ||
		!strings.Contains(ir, "llvm.experimental.constrained.fdiv.v32f16") {
		t.Fatal("embedded FP16 rounding did not reach constrained LLVM operations")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-fp16-control.ll", "raw-fp16-control.o", ir)

	valid := encodeRawFP16Binary(0x58, 0, 1, 2, 3, 1, false, false, false)
	for _, mutation := range []struct {
		name  string
		index int
		mask  byte
	}{
		{"EVEX.W", 2, 0x80},
		{"zero without mask", 3, 0x81},
		{"reserved width", 3, 0x60},
	} {
		bad := append([]byte(nil), valid...)
		bad[mutation.index] ^= mutation.mask
		if _, _, matched, err := decodedX86VEXBinaryFloatInstruction(bad, 64); !matched || err == nil {
			t.Errorf("%s %x: matched=%v, err=%v", mutation.name, bad, matched, err)
		}
	}
	if _, _, matched, err := decodedX86VEXBinaryFloatInstruction(valid[:5], 64); matched && err == nil {
		t.Fatal("accepted truncated FP16 binary encoding")
	}
}

func TestTranslateRawFP16Binary386Mask(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawFP16386(SB),4,$0-0\n")
	for _, code := range [][]byte{
		encodeRawFP16Binary(0x58, 0, 1, 2, 3, 1, false, false, true),
		encodeRawFP16Binary(0x5c, 1, 1, 0, 3, 1, true, true, true),
	} {
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
		}
	}
	source.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "386", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "386", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawFP16386": {Name: "rawFP16386", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-fp16-386.ll", "raw-fp16-386.o", ir)
		})
	}
}

func TestRawFP16BinaryRejectsNamedGoForm(t *testing.T) {
	const source = "TEXT invalidNamedHalf(SB),4,$0-0\n\tVADDPH X0, X1, X2\n\tRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, false)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"invalidNamedHalf": {Name: "invalidNamedHalf", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted FP16 mnemonic absent from Go's named assembler table")
	}
}
