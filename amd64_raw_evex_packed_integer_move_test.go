package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawEVEXPackedIntegerMoveCompleteGo127Family(t *testing.T) {
	// Go 1.27 gives VMOVDQA32/64 and VMOVDQU8/16/32/64 the same
	// 12-row _yvmovdqa32 table: X/Y/Z, load/store, with and without a
	// nonzero K mask. These LLVM-verified encodings exercise every opcode,
	// both directions, every vector width, high registers, SIB addressing,
	// zeroing, and EVEX compressed disp8 scaling.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "dqa32 x load", code: []byte{0x62, 0xf1, 0x7d, 0x08, 0x6f, 0xc1}, want: "VMOVDQA32 X1, X0"},
		{name: "dqa32 x store compressed disp8", code: []byte{0x62, 0xf1, 0x7d, 0x08, 0x7f, 0x50, 0x01}, want: "VMOVDQA32 X2, 16(AX)"},
		{name: "dqa64 y high load masked", code: []byte{0x62, 0xa1, 0xfd, 0x29, 0x6f, 0xe5}, want: "VMOVDQA64 Y21, K1, Y20"},
		{name: "dqa64 y store masked sib", code: []byte{0x62, 0x91, 0xfd, 0x2a, 0x7f, 0x64, 0x88, 0x03}, want: "VMOVDQA64 Y4, K2, 96(R8)(R9*4)"},
		{name: "dqu8 z high load zeroing", code: []byte{0x62, 0x01, 0x7f, 0xcf, 0x6f, 0xfe}, want: "VMOVDQU8.Z Z30, K7, Z31"},
		{name: "dqu8 z store compressed disp8", code: []byte{0x62, 0xf1, 0x7f, 0x4e, 0x7f, 0x7f, 0x07}, want: "VMOVDQU8 Z7, K6, 448(DI)"},
		{name: "dqu16 x load masked", code: []byte{0x62, 0xf1, 0xff, 0x09, 0x6f, 0xd3}, want: "VMOVDQU16 X3, K1, X2"},
		{name: "dqu16 x store compressed disp8", code: []byte{0x62, 0xf1, 0xff, 0x0a, 0x7f, 0x60, 0x02}, want: "VMOVDQU16 X4, K2, 32(AX)"},
		{name: "dqu32 y memory load zeroing sib", code: []byte{0x62, 0x91, 0x7e, 0xaa, 0x6f, 0x64, 0x88, 0x03}, want: "VMOVDQU32.Z 96(R8)(R9*4), K2, Y4"},
		{name: "dqu32 y high store masked", code: []byte{0x62, 0x41, 0x7e, 0x2b, 0x7f, 0x4c, 0x24, 0x02}, want: "VMOVDQU32 Y25, K3, 64(R12)"},
		{name: "dqu64 z high load masked", code: []byte{0x62, 0x01, 0xfe, 0x4f, 0x6f, 0xf7}, want: "VMOVDQU64 Z31, K7, Z30"},
		{name: "dqu64 z high store masked sib", code: []byte{0x62, 0x01, 0xfe, 0x4b, 0x7f, 0x4c, 0x6c, 0x02}, want: "VMOVDQU64 Z25, K3, 128(R12)(R13*2)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeX86RawDirectives(rawX86Function(test.code), "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Instrs) != 1 || !strings.HasPrefix(got.Instrs[0].Raw, test.want+" ") {
				t.Fatalf("decoded %#x as %#v, want %q", test.code, got.Instrs, test.want)
			}
		})
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT raw_evex_packed_integer_move(SB),NOSPLIT,$0-0\n")
	for _, test := range tests {
		for _, value := range test.code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"raw_evex_packed_integer_move": {Name: "raw_evex_packed_integer_move", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-evex-packed-integer-move.ll", "raw-evex-packed-integer-move.o", ir)
}

func TestX86RawEVEXPackedIntegerMoveReportedMinioSequence(t *testing.T) {
	var code []byte
	for register := byte(0); register < 8; register++ {
		modRM := byte(0x07 | register<<3)
		code = append(code, 0x62, 0xf1, 0x7e, 0x48, 0x6f, modRM)
		if register != 0 {
			code[len(code)-1] |= 0x40
			code = append(code, register)
		}
	}
	got, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Instrs) != 8 {
		t.Fatalf("decoded minio sequence as %d instructions: %#v", len(got.Instrs), got.Instrs)
	}
	for index, instruction := range got.Instrs {
		want := fmt.Sprintf("VMOVDQU32 %d(DI), Z%d", index*64, index)
		if !strings.HasPrefix(instruction.Raw, want+" ") {
			t.Fatalf("instruction %d = %q, want %q", index, instruction.Raw, want)
		}
	}
}

func TestX86RawEVEXPackedIntegerMoveZeroingRegisterStoreEncoding(t *testing.T) {
	for _, spec := range []struct {
		op Op
		pp int
		w  byte
	}{{"VMOVDQA32", 1, 0}, {"VMOVDQA64", 1, 0x80}, {"VMOVDQU8", 3, 0}, {"VMOVDQU16", 3, 0x80}, {"VMOVDQU32", 2, 0}, {"VMOVDQU64", 2, 0x80}} {
		for width, prefix := range []string{"X", "Y", "Z"} {
			for src := 0; src < 32; src++ {
				for dst := 0; dst < 32; dst++ {
					code := encodeRawScalarMove(true, spec.pp, 0x11, src, 0, dst, 7, true)
					code[2] = code[2]&0x7f | spec.w
					code[3] |= byte(width) << 5
					code[4] = 0x7f
					got, size, matched, err := decodedX86EVEXPackedIntegerMoveInstruction(code, 64)
					want := fmt.Sprintf("%s.Z %s%d, K7, %s%d", spec.op, prefix, src, prefix, dst)
					if err != nil || !matched || size != len(code) || got.Raw != want {
						t.Fatalf("decode %x=%q size=%d matched=%v err=%v, want %q", code, got.Raw, size, matched, err, want)
					}
				}
			}
		}
	}
}

func TestX86RawEVEXPackedIntegerMoveRejectsInvalidEVEXForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
	}{
		{name: "broadcast bit", code: []byte{0x62, 0xf1, 0x7e, 0x58, 0x6f, 0xc1}},
		{name: "zeroing without mask", code: []byte{0x62, 0xf1, 0x7e, 0xc8, 0x6f, 0xc1}},
		{name: "zeroing store", code: []byte{0x62, 0xf1, 0x7e, 0x89, 0x7f, 0x08}},
		{name: "reserved vector length", code: []byte{0x62, 0xf1, 0x7e, 0x68, 0x6f, 0xc1}},
		{name: "address override", code: []byte{0x67, 0x62, 0xf1, 0x7e, 0x48, 0x6f, 0x07}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, ok, err := decodedX86EVEXPackedIntegerMoveInstruction(test.code, 64); !ok || err == nil {
				t.Fatalf("decoded invalid encoding %#x with ok=%v err=%v", test.code, ok, err)
			}
		})
	}
}

func rawX86Function(code []byte) Func {
	fn := Func{}
	for _, value := range code {
		fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
	}
	return fn
}
