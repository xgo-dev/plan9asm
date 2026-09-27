package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestDecodeX86RawByteIncrementWidth(t *testing.T) {
	code := []byte{0xfe, 0xc1, 0xc3}
	inst, err := x86asm.Decode(code, 64)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Op != x86asm.INC || x86asm.GoSyntax(inst, 0, nil) != "INCL CL" {
		t.Fatalf("x/arch INC baseline changed: %+v", inst)
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "byte increment", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "INCB" || decoded[0].Args[0].Reg != CL {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawIncrementDecrementCompleteGoForms(t *testing.T) {
	for _, goarch := range []string{"386", "amd64"} {
		var source strings.Builder
		source.WriteString("TEXT rawIncDec(SB),4,$0-0\n")
		for _, op := range []string{"INC", "DEC"} {
			for _, form := range []struct {
				suffix, register string
			}{
				{"B", "CL"}, {"W", "CX"}, {"L", "CX"}, {"Q", "CX"},
			} {
				if goarch == "386" && form.suffix == "Q" {
					continue
				}
				fmt.Fprintf(&source, "\t%s%s %s\n", op, form.suffix, form.register)
				fmt.Fprintf(&source, "\t%s%s 8(AX)\n", op, form.suffix)
			}
		}
		source.WriteString("\tRET\n")
		code := assembleX87ControlBytes(t, goarch, source.String())
		decoded, err := decodeX86RawDirectives(rawX86Function(code), goarch)
		if err != nil {
			t.Fatalf("%s: %v", goarch, err)
		}
		named, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		want := named.Funcs[0].Instrs[1:]
		if len(decoded.Instrs) != len(want) {
			t.Fatalf("%s decoded %d instructions, want %d", goarch, len(decoded.Instrs), len(want))
		}
		for index, ins := range decoded.Instrs {
			if ins.Op != want[index].Op || !reflect.DeepEqual(ins.Args, want[index].Args) {
				t.Fatalf("%s instruction %d=%+v, want %+v", goarch, index, ins, want[index])
			}
		}
	}
}

func TestX86MixedSSESymbolReadLengthsMatchGoAssembler(t *testing.T) {
	for op := range x86RawMixedSSESymbolReadOps {
		for _, register := range []string{"X0", "X10"} {
			t.Run(string(op)+"/"+register, func(t *testing.T) {
				instruction := fmt.Sprintf("%s pool(SB), %s", op, register)
				if op == "CMPPS" || op == "CMPPD" {
					instruction += ", $5"
				}
				source := "TEXT width(SB),4,$0-0\n\t" + instruction + "\n\tRET\n"
				code := assembleX87ControlBytes(t, "amd64", source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				length, ok := x86RawMixedSSESymbolReadSize(file.Funcs[0].Instrs[1])
				if !ok || length != len(code)-1 {
					t.Fatalf("%s length=%d, recognized=%t, Go bytes=%x", instruction, length, ok, code)
				}
			})
		}
	}
}

func TestTranslateX86MixedRawJumpAcrossNamedSSERead(t *testing.T) {
	const source = `TEXT mixedRawJump(SB),4,$0-0
	BYTE $0xe9
	LONG $8
	POR pool(SB), X0
	BYTE $0xc3
`
	code := assembleX87ControlBytes(t, "amd64", source)
	if len(code) != 14 || code[0] != 0xe9 || code[13] != 0xc3 {
		t.Fatalf("unexpected Go assembler layout: %x", code)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"mixedRawJump": {Name: "mixedRawJump", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "raw_jcc_") {
				t.Fatal("cross-segment branch label missing")
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "mixed-raw-jump.ll", "mixed-raw-jump.o", ir)
		})
	}
}
