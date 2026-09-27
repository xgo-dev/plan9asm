package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Intel AVX512-FP16 section 5.61: EVEX.128.66.MAP5.WIG 6E/7E.
// The ModRM.reg operand is always X; ModRM.r/m is GP or m16, never X.
func rawVMOVW(load, wide bool, vector, general int, memory bool) []byte {
	p0 := byte(0xf5)
	p0 &^= byte((vector>>3&1)<<7 | (vector>>4&1)<<4 | (general>>3&1)<<5)
	p1 := byte(0x7d)
	if wide {
		p1 |= 0x80
	}
	opcode := byte(0x7e)
	if load {
		opcode = 0x6e
	}
	modRM := byte(0xc0 | (vector&7)<<3 | general&7)
	if memory {
		modRM = 0x40 | byte(vector&7)<<3 | byte(general&7)
	}
	code := []byte{0x62, p0, p1, 0x08, opcode, modRM}
	if memory {
		code = append(code, 1)
	}
	return code
}

func TestRawVMOVWCompleteFormats(t *testing.T) {
	for _, mode := range []int{32, 64} {
		vectors, generals := 8, 8
		if mode == 64 {
			vectors, generals = 32, 16
		}
		for _, load := range []bool{false, true} {
			for _, wide := range []bool{false, true} {
				for vector := 0; vector < vectors; vector++ {
					for general := 0; general < generals; general++ {
						code := rawVMOVW(load, wide, vector, general, false)
						got, n, ok, err := decodedX86VMOVQInstruction(code, mode)
						if err != nil || !ok || n != len(code) || got.Op != "VMOVW" || !got.x86Encoded {
							t.Fatalf("mode %d %x: %+v, n=%d, matched=%v, err=%v", mode, code, got, n, ok, err)
						}
						xIndex := 0
						if load {
							xIndex = 1
						}
						wantGeneral, _ := decodedX86GeneralRegister(general)
						if got.Args[xIndex].String() != fmt.Sprintf("X%d", vector) || got.Args[1-xIndex].Kind != OpReg ||
							got.Args[1-xIndex].Reg != wantGeneral {
							t.Fatalf("%x: wrong operands %+v", code, got.Args)
						}
					}
				}
				code := rawVMOVW(load, wide, 1, 0, true)
				got, _, ok, err := decodedX86VMOVQInstruction(code, mode)
				if err != nil || !ok {
					t.Fatalf("%x: matched=%v, err=%v", code, ok, err)
				}
				memoryIndex := 1
				if load {
					memoryIndex = 0
				}
				if got.Args[memoryIndex].String() != "2(AX)" {
					t.Fatalf("%x: expected two-byte displacement scaling, got %+v", code, got.Args)
				}
			}
		}
	}
}

func TestRawVMOVWInvalidFormats(t *testing.T) {
	for _, change := range []struct {
		index int
		bits  byte
	}{
		{2, 4}, {2, 8}, {3, 8}, {3, 1}, {3, 0x80}, {3, 0x10}, {3, 0x20}, {3, 0x40}, {1, 0x40},
	} {
		code := rawVMOVW(true, false, 0, 1, false)
		code[change.index] ^= change.bits
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "invalid VMOVW", map[string]bool{}); err == nil {
			t.Fatalf("accepted reserved VMOVW %x", code)
		}
	}
	for _, code := range [][]byte{rawVMOVW(true, false, 8, 0, false), rawVMOVW(false, true, 0, 8, false)} {
		if _, err := decodeX86RawDirectiveGroup(code, 32, 0, "386 high VMOVW", map[string]bool{}); err == nil {
			t.Fatalf("accepted 386 extended register %x", code)
		}
	}
}

func TestRawVMOVWLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawWordMove(SB),4,$0-0\n")
	for _, load := range []bool{false, true} {
		for _, wide := range []bool{false, true} {
			for _, memory := range []bool{false, true} {
				for _, b := range rawVMOVW(load, wide, 1, 0, memory) {
					fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
				}
			}
		}
	}
	source.WriteString("RET\n")
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawWordMove": {Name: "rawWordMove", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load i16", "store i16", "zext i16", "+avx512fp16"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %s", want)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-vmovw.ll", "raw-vmovw.o", ir)
		})
	}
}

func TestRawVMOVWPortableRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString("TEXT wordMove(SB),4,$0-24\nMOVQ input+0(FP), AX\nMOVQ out+8(FP), SI\nMOVQ vector+16(FP), DI\nVMOVDQU64 (DI), Z0\nMOVQ $-1, CX\n")
	for _, code := range [][]byte{
		{0x62, 0xf5, 0x7d, 0x08, 0x6e, 0x00}, // m16 -> X0; no wider memory access.
		{0x62, 0xf5, 0xfd, 0x08, 0x7e, 0xc1}, // X0 -> CX; WIG, zero-extend.
	} {
		for _, b := range code {
			fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
		}
	}
	source.WriteString("MOVQ CX, (SI)\nVMOVDQU64 Z0, 8(SI)\nMOVQ $-1, CX\n")
	for _, code := range [][]byte{
		{0x62, 0xf5, 0x7d, 0x08, 0x6e, 0xc1}, // CX -> X0, truncate and clear all upper lanes.
		{0x62, 0xf5, 0xfd, 0x08, 0x7e, 0x00}, // X0 -> m16; exactly two bytes.
	} {
		for _, b := range code {
			fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
		}
	}
	source.WriteString("VMOVDQU64 Z0, 72(SI)\nRET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: testTargetTriple(runtime.GOOS, runtime.GOARCH),
		Sigs: map[string]FuncSig{"wordMove": {
			Name: "wordMove", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Attrs: "nounwind",
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n" + x86TestGuardPagesC + `
extern void wordMove(void *, void *, const void *);
int main(void) {
    if (setup_guard()) return 1;
    uint64_t output[17], vector[8];
    memset(vector, 0xff, sizeof(vector));
    for (int offset = 2; offset <= 3; offset++) {
        unsigned char *pointer = guard + page - offset;
        uint16_t input = 0x8123;
        memcpy(pointer, &input, 2);
        wordMove(pointer, output, vector);
        if (output[0] != input || output[1] != input || output[9] != 0xffff) return 2;
        for (int lane = 2; lane < 9; lane++) if (output[lane] != 0) return 3;
        for (int lane = 10; lane < 17; lane++) if (output[lane] != 0) return 4;
        memcpy(&input, pointer, 2);
        if (input != 0xffff) return 5;
    }
    return free_guard();
}
`
	compileAndRunRuntimeTest(t, llc, clang, "vmovw_portable", ir, mainC)
}

func TestRawVMOVWRIPLiteralAndNamedRejection(t *testing.T) {
	code := []byte{0x62, 0xf5, 0x7d, 8, 0x6e, 5, 1, 0, 0, 0, 0xc3, 0x23, 0x81}
	got, err := decodeX86RawDirectiveGroup(code, 64, 0, "word RIP literal", map[string]bool{})
	if err != nil || len(got) != 2 || !got[0].x86RIPLiteral || got[0].Args[0].Kind != OpImm || got[0].Args[0].Imm != 0x8123 {
		t.Fatalf("literal: %+v, err=%v", got, err)
	}
	if _, err := decodeX86RawDirectiveGroup(code[:len(code)-1], 64, 0, "truncated word pool", map[string]bool{}); err == nil {
		t.Fatal("accepted truncated word pool")
	}
	const source = "TEXT namedWordMove(SB),4,$0-0\nVMOVW X0, AX\nRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, false)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"namedWordMove": {Name: "namedWordMove", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted VMOVW absent from Go's named assembler table")
	}
}
