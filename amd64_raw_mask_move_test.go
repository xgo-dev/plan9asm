package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawMaskMoveCompleteGo127Family(t *testing.T) {
	// Go 1.27's shared _ykmovb table gives KMOVB/W/D/Q the same four
	// encoding rows: K->memory, K->GP, K-or-memory->K, and GP->K. Cover
	// every row at every width, plus the extended GP form reported by
	// github.com/minio/sha256-simd.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "b k to k", code: []byte{0xc5, 0xf9, 0x90, 0xcd}, want: "KMOVB K5, K1"},
		{name: "b memory to k", code: []byte{0xc5, 0xf9, 0x90, 0x08}, want: "KMOVB 0(AX), K1"},
		{name: "b k to memory", code: []byte{0xc5, 0xf9, 0x91, 0x00}, want: "KMOVB K0, 0(AX)"},
		{name: "b k to gp", code: []byte{0xc5, 0xf9, 0x93, 0xc5}, want: "KMOVB K5, AX"},
		{name: "b gp to k", code: []byte{0xc5, 0xf9, 0x92, 0xe8}, want: "KMOVB AX, K5"},
		{name: "w k to k", code: []byte{0xc5, 0xf8, 0x90, 0xcd}, want: "KMOVW K5, K1"},
		{name: "w memory to k", code: []byte{0xc5, 0xf8, 0x90, 0x08}, want: "KMOVW 0(AX), K1"},
		{name: "w k to memory", code: []byte{0xc5, 0xf8, 0x91, 0x00}, want: "KMOVW K0, 0(AX)"},
		{name: "w k to gp", code: []byte{0xc5, 0xf8, 0x93, 0xc5}, want: "KMOVW K5, AX"},
		{name: "w gp to k", code: []byte{0xc5, 0xf8, 0x92, 0xe8}, want: "KMOVW AX, K5"},
		{name: "d k to k", code: []byte{0xc4, 0xe1, 0xf9, 0x90, 0xcd}, want: "KMOVD K5, K1"},
		{name: "d memory to k", code: []byte{0xc4, 0xe1, 0xf9, 0x90, 0x08}, want: "KMOVD 0(AX), K1"},
		{name: "d k to memory", code: []byte{0xc4, 0xe1, 0xf9, 0x91, 0x00}, want: "KMOVD K0, 0(AX)"},
		{name: "d k to gp", code: []byte{0xc5, 0xfb, 0x93, 0xc5}, want: "KMOVD K5, AX"},
		{name: "d gp to k", code: []byte{0xc5, 0xfb, 0x92, 0xe8}, want: "KMOVD AX, K5"},
		{name: "q k to k", code: []byte{0xc4, 0xe1, 0xf8, 0x90, 0xcd}, want: "KMOVQ K5, K1"},
		{name: "q memory to k", code: []byte{0xc4, 0xe1, 0xf8, 0x90, 0x08}, want: "KMOVQ 0(AX), K1"},
		{name: "q k to memory", code: []byte{0xc4, 0xe1, 0xf8, 0x91, 0x00}, want: "KMOVQ K0, 0(AX)"},
		{name: "q k to gp", code: []byte{0xc4, 0xe1, 0xfb, 0x93, 0xc5}, want: "KMOVQ K5, AX"},
		{name: "q gp to k", code: []byte{0xc4, 0xe1, 0xfb, 0x92, 0xe8}, want: "KMOVQ AX, K5"},
		{name: "q reported extended gp to k", code: []byte{0xc4, 0xc1, 0xfb, 0x92, 0xce}, want: "KMOVQ R14, K1"},
		{name: "q extended k to gp", code: []byte{0xc4, 0x61, 0xfb, 0x93, 0xd7}, want: "KMOVQ K7, R10"},
		{name: "q extended sib memory to k", code: []byte{0xc4, 0x81, 0xf8, 0x90, 0x4c, 0x88, 0x20}, want: "KMOVQ 32(R8)(R9*4), K1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fn := Func{}
			for _, value := range test.code {
				fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
			}
			got, err := decodeX86RawDirectives(fn, "amd64")
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
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		t.Run(target.goarch+"/lower", func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT raw_mask_move(SB),NOSPLIT,$0-0\n")
			for _, test := range tests[:20] {
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
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"raw_mask_move": {Name: "raw_mask_move", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-mask-move-"+target.goarch+".ll", "raw-mask-move-"+target.goarch+".o", ir)
		})
	}
}
