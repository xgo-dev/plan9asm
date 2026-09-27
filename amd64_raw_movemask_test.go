package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

var x86RawMoveMaskForms = []struct {
	name string
	code []byte
	op   Op
	src  Reg
	dst  Reg
}{
	{"PMOVMSKB/MMX", []byte{0x0f, 0xd7, 0xc1}, "PMOVMSKB", "M1", AX},
	{"PMOVMSKB/X", []byte{0x66, 0x0f, 0xd7, 0xc1}, "PMOVMSKB", "X1", AX},
	{"MOVMSKPS/X", []byte{0x0f, 0x50, 0xc1}, "MOVMSKPS", "X1", AX},
	{"MOVMSKPD/X", []byte{0x66, 0x0f, 0x50, 0xc1}, "MOVMSKPD", "X1", AX},
	{"VPMOVMSKB/X", []byte{0xc5, 0xf9, 0xd7, 0xc1}, "VPMOVMSKB", "X1", AX},
	{"VPMOVMSKB/Y", []byte{0xc5, 0xfd, 0xd7, 0xc1}, "VPMOVMSKB", "Y1", AX},
	{"VMOVMSKPS/X", []byte{0xc5, 0xf8, 0x50, 0xc1}, "VMOVMSKPS", "X1", AX},
	{"VMOVMSKPS/Y", []byte{0xc5, 0xfc, 0x50, 0xc1}, "VMOVMSKPS", "Y1", AX},
	{"VMOVMSKPD/X", []byte{0xc5, 0xf9, 0x50, 0xc1}, "VMOVMSKPD", "X1", AX},
	{"VMOVMSKPD/Y", []byte{0xc5, 0xfd, 0x50, 0xc1}, "VMOVMSKPD", "Y1", AX},
}

func TestX86RawMoveMaskCompleteGo127Family(t *testing.T) {
	if len(amd64MoveMaskSpecs) != 6 {
		t.Fatalf("move-mask grammar has %d operations, want six", len(amd64MoveMaskSpecs))
	}
	for _, goarch := range []string{"386", "amd64"} {
		for _, form := range x86RawMoveMaskForms {
			t.Run(goarch+"/"+form.name, func(t *testing.T) {
				fn := Func{}
				for _, value := range form.code {
					fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
				}
				got, err := decodeX86RawDirectives(fn, goarch)
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 || got.Instrs[0].Op != form.op || len(got.Instrs[0].Args) != 2 {
					t.Fatalf("decoded %#x as %#v, want %s", form.code, got.Instrs, form.op)
				}
				args := got.Instrs[0].Args
				if args[0].Kind != OpReg || args[0].Reg != form.src || args[1].Kind != OpReg || args[1].Reg != form.dst {
					t.Fatalf("decoded %#x as %#v, want %s, %s", form.code, args, form.src, form.dst)
				}
			})
		}
	}
}

func TestX86RawMoveMaskRejectsReservedEncodings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"reserved-vvvv", []byte{0xc5, 0xe9, 0xd7, 0xc1}, 64},
		{"memory-source", []byte{0xc5, 0xfd, 0xd7, 0x01}, 64},
		{"address-override", []byte{0x67, 0xc5, 0xfd, 0xd7, 0xc1}, 64},
		{"missing-modrm", []byte{0xc5, 0xfd, 0xd7}, 64},
		{"extended-386", []byte{0xc4, 0x61, 0x7d, 0xd7, 0xc1}, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86VEXMoveMaskInstruction(tc.code, tc.mode); !recognized || err == nil {
				t.Fatalf("reserved encoding %#x: recognized=%v error=%v", tc.code, recognized, err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		code []byte
		src  Reg
		dst  Reg
	}{
		{"W-ignored", []byte{0xc4, 0xe1, 0xfd, 0xd7, 0xc1}, "Y1", AX},
		{"extended-vector-and-GP", []byte{0xc4, 0x41, 0x7d, 0xd7, 0xc8}, "Y8", "R9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, length, recognized, err := decodedX86VEXMoveMaskInstruction(tc.code, 64)
			if !recognized || err != nil || length != len(tc.code) {
				t.Fatalf("encoding %#x: instruction=%+v length=%d recognized=%v error=%v", tc.code, got, length, recognized, err)
			}
			if got.Args[0].Reg != tc.src || got.Args[1].Reg != tc.dst {
				t.Fatalf("encoding %#x operands = %+v, want %s, %s", tc.code, got.Args, tc.src, tc.dst)
			}
		})
	}
}

func TestX86RawMoveMaskCompilesEveryGoForm(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawmovemaskforms(SB),4,$0-0\n")
			for _, form := range x86RawMoveMaskForms {
				for _, value := range form.code {
					fmt.Fprintf(&source, "\tBYTE $%d\n", value)
				}
				source.WriteString("\tNOP\n")
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawmovemaskforms": {Name: "rawmovemaskforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-movemask.ll", "raw-movemask.o", ir)
		})
	}
}

func TestX86RawMoveMaskRuntime(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT rawmovemasksemantics(SB),4,$0-16
	MOVQ input+0(FP), DI
	MOVQ out+8(FP), SI
	VMOVDQU (DI), Y1
	BYTE $0xc5; BYTE $0xfd; BYTE $0xd7; BYTE $0xc1
	MOVL AX, 0(SI)
	BYTE $0xc5; BYTE $0xf8; BYTE $0x50; BYTE $0xc1
	MOVL AX, 4(SI)
	BYTE $0xc5; BYTE $0xfd; BYTE $0x50; BYTE $0xc1
	MOVL AX, 8(SI)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"rawmovemasksemantics": {
			Name: "rawmovemasksemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawmovemasksemantics(const uint8_t *, uint32_t *);
int main(void) {
  uint8_t input[32] = {0};
  uint32_t out[3] = {0};
  input[3] = 0x80; input[7] = 0x80; input[15] = 0x80; input[31] = 0x80;
  rawmovemasksemantics(input, out);
  if (out[0] != ((1u << 3) | (1u << 7) | (1u << 15) | (1u << 31))) return 1;
  if (out[1] != ((1u << 0) | (1u << 1) | (1u << 3))) return 2;
  if (out[2] != ((1u << 0) | (1u << 1) | (1u << 3))) return 3;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_move_mask", triple, ir, mainC, runPrefix)
}
