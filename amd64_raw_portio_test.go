package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawScalarPortIOCompleteEncodingFamily(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		op   Op
		port int64
	}{
		{"in byte immediate", []byte{0xe4, 0x7f}, "INB", 0x7f},
		{"in word immediate", []byte{0x66, 0xe5, 0x7f}, "INW", 0x7f},
		{"in long immediate", []byte{0xe5, 0x7f}, "INL", 0x7f},
		{"in byte DX", []byte{0xec}, "INB", -1},
		{"in word DX", []byte{0x66, 0xed}, "INW", -1},
		{"in long DX", []byte{0xed}, "INL", -1},
		{"out byte immediate", []byte{0xe6, 0x7f}, "OUTB", 0x7f},
		{"out word immediate", []byte{0x66, 0xe7, 0x7f}, "OUTW", 0x7f},
		{"out long immediate", []byte{0xe7, 0x7f}, "OUTL", 0x7f},
		{"out byte DX", []byte{0xee}, "OUTB", -1},
		{"out word DX", []byte{0x66, 0xef}, "OUTW", -1},
		{"out long DX", []byte{0xef}, "OUTL", -1},
	}
	for _, goarch := range []string{"386", "amd64"} {
		for _, test := range tests {
			t.Run(goarch+"/"+test.name, func(t *testing.T) {
				fn := Func{}
				for _, value := range test.code {
					fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
				}
				got, err := decodeX86RawDirectives(fn, goarch)
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 {
					t.Fatalf("decoded %#x as %#v, want one instruction", test.code, got.Instrs)
				}
				ins := got.Instrs[0]
				wantArgs := 0
				if test.port >= 0 {
					wantArgs = 1
				}
				if ins.Op != test.op || len(ins.Args) != wantArgs {
					t.Fatalf("decoded %#x as %#v, want %s with port %d", test.code, ins, test.op, test.port)
				}
				if test.port >= 0 && (ins.Args[0].Kind != OpImm || ins.Args[0].Imm != test.port) {
					t.Fatalf("decoded %#x port as %#v, want $%d", test.code, ins.Args[0], test.port)
				}
			})
		}
	}
}

func TestX86RawScalarPortIOImmediateByteRange(t *testing.T) {
	for _, opcode := range []byte{0xe4, 0xe5, 0xe6, 0xe7} {
		for port := 0; port < 256; port++ {
			instruction, length, ok, err := decodedX86ScalarPortIOInstruction([]byte{opcode, byte(port)})
			if !ok || err != nil || length != 2 || len(instruction.Args) != 1 || instruction.Args[0].Imm != int64(port) {
				t.Fatalf("opcode %#x port %d: instruction=%#v length=%d recognized=%t error=%v", opcode, port, instruction, length, ok, err)
			}
		}
		_, _, ok, err := decodedX86ScalarPortIOInstruction([]byte{opcode})
		if !ok || err == nil {
			t.Fatalf("opcode %#x with missing port: recognized=%t error=%v", opcode, ok, err)
		}
	}
}

func TestX86RawScalarPortIOCompilesEveryForm(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawportio(SB),NOSPLIT,$0-0\n")
			for _, code := range [][]byte{
				{0xe4, 0x7f}, {0x66, 0xe5, 0x7f}, {0xe5, 0x7f},
				{0xec}, {0x66, 0xed}, {0xed},
				{0xe6, 0x7f}, {0x66, 0xe7, 0x7f}, {0xe7, 0x7f},
				{0xee}, {0x66, 0xef}, {0xef},
			} {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $%d\n", value)
				}
				source.WriteString("\tNOP\n")
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawportio": {Name: "rawportio", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-portio.ll", "raw-portio.o", ir)
		})
	}
}
