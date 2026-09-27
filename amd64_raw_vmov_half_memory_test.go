package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVectorHalfMemory(op Op, encoding string, vector, upper int, store, wig bool) []byte {
	high := strings.Contains(string(op), "H")
	pd := strings.HasSuffix(string(op), "PD")
	opcode := byte(0x12)
	if high {
		opcode = 0x16
	}
	if store {
		opcode++
		upper = 0
	}
	pp := byte(0)
	if pd {
		pp = 1
	}
	modRM := byte((vector&7)<<3 | 2)
	rExt := byte(1 - ((vector >> 3) & 1))
	switch encoding {
	case "VEX2":
		p1 := rExt<<7 | byte(^upper&15)<<3 | pp
		return []byte{0xc5, p1, opcode, modRM}
	case "VEX3":
		p0 := rExt<<7 | 1 // SIB index and base are R13 and R12.
		p1 := byte(^upper&15)<<3 | pp
		if wig {
			p1 |= 0x80
		}
		return []byte{0xc4, p0, p1, opcode, (modRM & 0x38) | 0x44, 0xac, 2}
	case "EVEX":
		r2Ext := byte(1 - ((vector >> 4) & 1))
		p0 := rExt<<7 | r2Ext<<4 | 1
		p1 := byte(^upper&15)<<3 | 4 | pp
		if pd {
			p1 |= 0x80
		}
		p2 := byte((1 - ((upper >> 4) & 1)) << 3)
		return []byte{0x62, p0, p1, p2, opcode, (modRM & 0x38) | 0x44, 0xac, 2}
	default:
		panic("unknown half-vector encoding")
	}
}

func TestTranslateRawVMOVHPDPathtracerRegression(t *testing.T) {
	const source = `
TEXT rawVMOVHPD(SB),$0-0
	MOVQ $0, DX
	LONG $0x0217f9c5 // VMOVHPD X0, (DX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"rawVMOVHPD": {Name: "rawVMOVHPD", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "extractelement <2 x i64>") {
		t.Fatalf("raw VMOVHPD did not store the high lane:\n%s", ll)
	}
}

func TestDecodedX86RawVectorHalfMemoryCompleteGo127Family(t *testing.T) {
	for _, op := range []Op{"VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD"} {
		for _, store := range []bool{false, true} {
			for _, encoding := range []string{"VEX2", "VEX3", "EVEX"} {
				vector, upper := 3, 4
				if encoding == "VEX3" {
					vector, upper = 11, 12
				}
				if encoding == "EVEX" {
					vector, upper = 20, 21
				}
				code := encodeX86RawVectorHalfMemory(op, encoding, vector, upper, store, encoding == "VEX3")
				got, length, recognized, err := decodedX86RawVectorHalfMemoryInstruction(code, 64)
				if err != nil || !recognized || length != len(code) || got.Op != op {
					t.Fatalf("decode %s %s store=%v bytes=%x: got=%+v length=%d recognized=%v err=%v", op, encoding, store, code, got, length, recognized, err)
				}
				memoryIndex := 0
				registerIndex := 2
				if store {
					memoryIndex, registerIndex = 1, 0
				}
				if got.Args[memoryIndex].Kind != OpMem || got.Args[registerIndex].Reg != Reg(fmt.Sprintf("X%d", vector)) {
					t.Fatalf("decoded wrong memory/register operands for %x: %+v", code, got.Args)
				}
				memory := got.Args[memoryIndex].Mem
				if encoding == "VEX2" && (memory.Base != DX || memory.Off != 0) {
					t.Fatalf("decoded wrong VEX2 memory operand for %x: %+v", code, memory)
				}
				if encoding == "VEX3" && (memory.Base != "R12" || memory.Index != "R13" || memory.Scale != 4 || memory.Off != 2) {
					t.Fatalf("decoded wrong VEX3 memory operand for %x: %+v", code, memory)
				}
				if encoding == "EVEX" && (memory.Base != "R12" || memory.Index != "R13" || memory.Scale != 4 || memory.Off != 16) {
					t.Fatalf("decoded wrong EVEX memory operand for %x: %+v", code, memory)
				}
				if !store && got.Args[1].Reg != Reg(fmt.Sprintf("X%d", upper)) {
					t.Fatalf("decoded wrong upper-lane register for %x: %+v", code, got.Args)
				}
			}
		}
	}
}

func TestDecodedX86RawVectorHalfMemoryRejectsInvalidForms(t *testing.T) {
	valid := encodeX86RawVectorHalfMemory("VMOVHPD", "EVEX", 20, 21, false, false)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"missing ModRM", valid[:5]},
		{"wrong fixed bit", append([]byte(nil), valid...)},
		{"wrong W bit", append([]byte(nil), valid...)},
		{"vector length", append([]byte(nil), valid...)},
		{"mask", append([]byte(nil), valid...)},
		{"zeroing", append([]byte(nil), valid...)},
		{"broadcast", append([]byte(nil), valid...)},
		{"register operand", append([]byte(nil), valid...)},
		{"RIP relative", append([]byte(nil), valid...)},
	} {
		switch test.name {
		case "wrong fixed bit":
			test.code[2] &^= 4
		case "wrong W bit":
			test.code[2] &^= 0x80
		case "vector length":
			test.code[3] |= 0x20
		case "mask":
			test.code[3] |= 1
		case "zeroing":
			test.code[3] |= 0x80
		case "broadcast":
			test.code[3] |= 0x10
		case "register operand":
			test.code[5] |= 0xc0
		case "RIP relative":
			test.code[5] = 0x05
		}
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86RawVectorHalfMemoryInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted invalid half-vector encoding %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
	store := encodeX86RawVectorHalfMemory("VMOVHPD", "VEX2", 3, 0, true, false)
	store[1] &^= 0x08 // A non-reserved VEX.vvvv field is not a Go store form.
	if _, _, recognized, err := decodedX86RawVectorHalfMemoryInstruction(store, 64); !recognized || err == nil {
		t.Fatalf("accepted store with non-reserved vvvv: recognized=%v err=%v", recognized, err)
	}
	extended := encodeX86RawVectorHalfMemory("VMOVHPD", "VEX3", 11, 12, false, false)
	if _, _, recognized, err := decodedX86RawVectorHalfMemoryInstruction(extended, 32); !recognized || err == nil {
		t.Fatalf("accepted 386 extended register form: recognized=%v err=%v", recognized, err)
	}
}

func TestTranslateRawX86VectorHalfMemoryLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawHalfMemory(SB),$0-0\n")
			if target.goarch == "386" {
				source.WriteString("\tMOVL $0, DX\n")
			} else {
				source.WriteString("\tMOVQ $0, DX\n")
			}
			for _, op := range []Op{"VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD"} {
				for _, store := range []bool{false, true} {
					encodings := []string{"VEX2"}
					if target.goarch == "amd64" {
						encodings = append(encodings, "VEX3", "EVEX")
					}
					for _, encoding := range encodings {
						vector, upper := 3, 4
						if encoding == "VEX3" {
							vector, upper = 11, 12
						}
						if encoding == "EVEX" {
							vector, upper = 20, 21
						}
						for _, value := range encodeX86RawVectorHalfMemory(op, encoding, vector, upper, store, false) {
							fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
						}
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"rawHalfMemory": {Name: "rawHalfMemory", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"extractelement <2 x i64>", "insertelement <2 x i64>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("half-vector lowering omitted %q", want)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-half-memory.ll", "raw-half-memory.o", ll)
		})
	}
}
