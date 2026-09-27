package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86RawEVEXVPINSRForms = []struct {
	op        Op
	mapNumber int
	opcode    byte
	width64   bool
	laneBytes int
}{
	{"VPINSRB", 3, 0x20, false, 1},
	{"VPINSRW", 1, 0xc4, false, 2},
	{"VPINSRD", 3, 0x22, false, 4},
	{"VPINSRQ", 3, 0x22, true, 8},
}

func x86RawEVEXVPINSRGoForms() string {
	var source strings.Builder
	source.WriteString("TEXT rawVPINSR(SB),4,$0-0\n")
	for _, form := range x86RawEVEXVPINSRForms {
		fmt.Fprintf(&source, "\t%s $5, AX, X20, X21\n", form.op)
		fmt.Fprintf(&source, "\t%s $255, %d(BX), X20, X21\n", form.op, form.laneBytes)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestDecodeX86RawEVEXVPINSRSeBiShogunRegression(t *testing.T) {
	// Go disassembles these bytes as VPINSRB $5, 1(SI)(R9*1), X6, X16.
	code := []byte{0x62, 0xa3, 0x4d, 0x08, 0x20, 0x44, 0x0e, 0x01, 0x05, 0xc3}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "bitshuffleU8 AVX512 VPINSRB", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VPINSRB" ||
		decoded[0].Args[0].Imm != 5 || decoded[0].Args[2].Reg != "X6" ||
		decoded[0].Args[3].Reg != "X16" {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawEVEXVPINSRCompleteGoForms(t *testing.T) {
	if len(x86RawEVEXVPINSRForms) != 4 {
		t.Fatalf("EVEX VPINSR grammar has %d entries, want four", len(x86RawEVEXVPINSRForms))
	}
	source := x86RawEVEXVPINSRGoForms()
	code := assembleX87ControlBytes(t, "amd64", source)
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	named, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	want := named.Funcs[0].Instrs[1:]
	if len(decoded.Instrs) != len(want) {
		t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
	}
	for index, got := range decoded.Instrs {
		if got.Op != want[index].Op || !reflect.DeepEqual(got.Args, want[index].Args) {
			t.Fatalf("instruction %d=%+v, want %+v", index, got, want[index])
		}
	}
}

func TestDecodeX86RawEVEXVPINSRRejectsInvalidForms(t *testing.T) {
	base := []byte{0x62, 0xa3, 0x4d, 0x08, 0x20, 0x44, 0x0e, 0x01, 0x05}
	for _, variant := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"mask", func(code []byte) []byte { code[3] |= 1; return code }},
		{"zeroing", func(code []byte) []byte { code[3] |= 0x80; return code }},
		{"broadcast", func(code []byte) []byte { code[3] |= 0x10; return code }},
		{"vector length", func(code []byte) []byte { code[3] |= 0x20; return code }},
		{"address override", func(code []byte) []byte { return append([]byte{0x67}, code...) }},
		{"truncated immediate", func(code []byte) []byte { return code[:len(code)-1] }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			code := variant.mutate(append([]byte(nil), base...))
			if _, _, matched, err := decodedX86EVEXVPINSRInstruction(code, 64); !matched || err == nil {
				t.Fatalf("invalid %x: matched=%v err=%v", code, matched, err)
			}
		})
	}
	if _, _, matched, err := decodedX86EVEXVPINSRInstruction(base, 32); !matched || err == nil {
		t.Fatalf("accepted 386 EVEX VPINSR: matched=%v err=%v", matched, err)
	}
}

func TestTranslateX86RawEVEXVPINSRLLVM22Objects(t *testing.T) {
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
			source := x86RawEVEXVPINSRGoForms()
			code := assembleX87ControlBytes(t, "amd64", source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			file.Funcs[0].Instrs = append(file.Funcs[0].Instrs[:1], rawX86Function(code).Instrs...)
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawVPINSR": {Name: "rawVPINSR", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-vpinsr.ll", "raw-vpinsr.o", ir)
		})
	}
}
