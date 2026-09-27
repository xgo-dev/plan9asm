package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawEVEXPackedFloatMoveCompleteGo127Family(t *testing.T) {
	// Go 1.27's _yvmovapd table gives VMOVAPS/APD/UPS/UPD the same
	// bidirectional X/Y/Z and K-masked EVEX forms in addition to the four
	// legacy VEX rows. These LLVM-verified encodings cover every EVEX opcode,
	// direction, vector width, mask mode, high-register field, and compressed
	// disp8 addressing shape used by that table.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "aps x load masked", code: []byte{0x62, 0xf1, 0x7c, 0x09, 0x28, 0xc1}, want: "VMOVAPS X1, K1, X0"},
		{name: "aps x store compressed disp8", code: []byte{0x62, 0xf1, 0x7c, 0x0a, 0x29, 0x50, 0x01}, want: "VMOVAPS X2, K2, 16(AX)"},
		{name: "apd y high load masked", code: []byte{0x62, 0xa1, 0xfd, 0x29, 0x28, 0xe5}, want: "VMOVAPD Y21, K1, Y20"},
		{name: "apd y store masked sib", code: []byte{0x62, 0x91, 0xfd, 0x2a, 0x29, 0x64, 0x88, 0x03}, want: "VMOVAPD Y4, K2, 96(R8)(R9*4)"},
		{name: "apd z high load zeroing", code: []byte{0x62, 0xa1, 0xfd, 0xcb, 0x28, 0xe5}, want: "VMOVAPD.Z Z21, K3, Z20"},
		{name: "ups z high load zeroing", code: []byte{0x62, 0x01, 0x7c, 0xcf, 0x10, 0xfe}, want: "VMOVUPS.Z Z30, K7, Z31"},
		{name: "ups z store compressed disp8", code: []byte{0x62, 0xf1, 0x7c, 0x4e, 0x11, 0x7f, 0x07}, want: "VMOVUPS Z7, K6, 448(DI)"},
		{name: "upd x load masked", code: []byte{0x62, 0xf1, 0xfd, 0x09, 0x10, 0xd3}, want: "VMOVUPD X3, K1, X2"},
		{name: "upd x store compressed disp8", code: []byte{0x62, 0xf1, 0xfd, 0x0a, 0x11, 0x60, 0x02}, want: "VMOVUPD X4, K2, 32(AX)"},
		{name: "ups y memory load zeroing sib", code: []byte{0x62, 0x91, 0x7c, 0xaa, 0x10, 0x64, 0x88, 0x03}, want: "VMOVUPS.Z 96(R8)(R9*4), K2, Y4"},
		{name: "ups y high store masked", code: []byte{0x62, 0x41, 0x7c, 0x2b, 0x11, 0x4c, 0x24, 0x02}, want: "VMOVUPS Y25, K3, 64(R12)"},
		{name: "upd z high store masked sib", code: []byte{0x62, 0x01, 0xfd, 0x4b, 0x11, 0x4c, 0x6c, 0x02}, want: "VMOVUPD Z25, K3, 128(R12)(R13*2)"},
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
	source.WriteString("TEXT raw_evex_packed_float_move(SB),NOSPLIT,$0-0\n")
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
		Sigs: map[string]FuncSig{"raw_evex_packed_float_move": {Name: "raw_evex_packed_float_move", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "raw-evex-packed-float-move.ll", "raw-evex-packed-float-move.o", ir)
}

func TestX86RawEVEXPackedFloatMoveReportedMinioInstruction(t *testing.T) {
	code := []byte{0x62, 0xc1, 0x7c, 0x48, 0x10, 0x04, 0x09}
	got, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Instrs) != 1 || !strings.HasPrefix(got.Instrs[0].Raw, "VMOVUPS 0(R9)(CX*1), Z16 ") {
		t.Fatalf("decoded reported minio bytes as %#v", got.Instrs)
	}
}
