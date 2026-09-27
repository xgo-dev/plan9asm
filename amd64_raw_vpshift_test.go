package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodedX86PackedLogicalShiftCompleteGo127Family(t *testing.T) {
	// Go 1.27's _yvpslld table covers six logical shifts with both immediate
	// and XMM/m128 uniform-count encodings. These LLVM 22 bytes also cover
	// VEX/EVEX, every width, masks, zeroing, broadcast, high registers, and
	// compressed disp8.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "vex immediate right dword", code: []byte{0xc5, 0xb5, 0x72, 0xd2, 0x07}, want: "VPSRLD $7, Y2, Y9"},
		{name: "vex count left qword memory", code: []byte{0xc4, 0x41, 0x6d, 0xf3, 0x4c, 0x24, 0x20}, want: "VPSLLQ 32(R12), Y2, Y9"},
		{name: "immediate left word", code: []byte{0x62, 0xb1, 0x4d, 0x01, 0x71, 0xf4, 0x06}, want: "VPSLLW $6, X20, K1, X22"},
		{name: "immediate left dword", code: []byte{0x62, 0xd1, 0x6d, 0xaa, 0x72, 0x70, 0x03, 0x07}, want: "VPSLLD.Z $7, 96(R8), K2, Y2"},
		{name: "immediate left qword", code: []byte{0x62, 0xb1, 0xb5, 0x48, 0x73, 0xf1, 0x44}, want: "VPSLLQ $68, Z17, Z9"},
		{name: "immediate right word", code: []byte{0x62, 0xd1, 0x35, 0x24, 0x71, 0x54, 0x24, 0x02, 0x0a}, want: "VPSRLW $10, 64(R12), K4, Y25"},
		{name: "immediate right dword reported minio", code: []byte{0x62, 0x91, 0x05, 0x48, 0x72, 0xd6, 0x0a}, want: "VPSRLD $10, Z30, Z15"},
		{name: "immediate right qword broadcast", code: []byte{0x62, 0xf1, 0xed, 0xdb, 0x73, 0x50, 0x7f, 0x09}, want: "VPSRLQ.BCST.Z $9, 1016(AX), K3, Z2"},
		{name: "count left word", code: []byte{0x62, 0xa1, 0x55, 0x01, 0xf1, 0xf4}, want: "VPSLLW X20, X21, K1, X22"},
		{name: "count left dword memory", code: []byte{0x62, 0xd1, 0x75, 0xaa, 0xf2, 0x50, 0x03}, want: "VPSLLD.Z 48(R8), Y1, K2, Y2"},
		{name: "count left qword", code: []byte{0x62, 0x31, 0xfd, 0x40, 0xf3, 0xc9}, want: "VPSLLQ X17, Z16, Z9"},
		{name: "count right word memory", code: []byte{0x62, 0x41, 0x3d, 0x04, 0xd1, 0x4c, 0x24, 0x02}, want: "VPSRLW 32(R12), X24, K4, X25"},
		{name: "count right dword", code: []byte{0x62, 0xa1, 0x55, 0x21, 0xd2, 0xf4}, want: "VPSRLD X20, Y21, K1, Y22"},
		{name: "count right qword memory", code: []byte{0x62, 0xf1, 0xf5, 0xcb, 0xd3, 0x50, 0x7f}, want: "VPSRLQ.Z 2032(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86PackedUniformShiftInstruction(test.code, 64)
			if !ok {
				t.Fatal("packed logical shift encoding was not recognized")
			}
			if err != nil {
				t.Fatal(err)
			}
			if length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decoded %x as length=%d raw=%q, want length=%d raw=%q", test.code, length, instruction.Raw, len(test.code), test.want)
			}
		})
	}
}

func TestDecodedX86PackedArithmeticShiftStreamVByteRegression(t *testing.T) {
	code := []byte{0xc5, 0xfd, 0x72, 0xe0, 0x1f}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "streamvbyte VPSRAD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPSRAD" || !strings.HasPrefix(decoded[0].Raw, "VPSRAD $31, Y0, Y0 ") {
		t.Fatalf("decoded streamvbyte VPSRAD as %#v", decoded)
	}
}

func TestDecodedX86PackedArithmeticShiftCompleteGo127Family(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{"VEX immediate word", []byte{0xc5, 0xe9, 0x71, 0xe1, 0x03}, "VPSRAW $3, X1, X2"},
		{"VEX immediate dword", []byte{0xc5, 0xed, 0x72, 0xe1, 0x07}, "VPSRAD $7, Y1, Y2"},
		{"EVEX immediate qword", []byte{0x62, 0xf1, 0xed, 0x48, 0x72, 0xe1, 0x07}, "VPSRAQ $7, Z1, Z2"},
		{"VEX packed count word", []byte{0xc5, 0xed, 0xe1, 0xd9}, "VPSRAW X1, Y2, Y3"},
		{"EVEX packed count dword", []byte{0x62, 0xf1, 0x6d, 0x48, 0xe2, 0xd9}, "VPSRAD X1, Z2, Z3"},
		{"EVEX packed count qword", []byte{0x62, 0xf1, 0xed, 0x48, 0xe2, 0xd9}, "VPSRAQ X1, Z2, Z3"},
		{"EVEX dword broadcast zeroing", []byte{0x62, 0xf1, 0x6d, 0xbb, 0x72, 0x20, 0x07}, "VPSRAD.BCST.Z $7, 0(AX), K3, Y2"},
		{"EVEX qword broadcast high register", []byte{0x62, 0xf1, 0xed, 0xd3, 0x72, 0x60, 0x01, 0x07}, "VPSRAQ.BCST.Z $7, 8(AX), K3, Z18"},
		{"EVEX qword high register packed count", []byte{0x62, 0xa1, 0xd5, 0xc1, 0xe2, 0xf4}, "VPSRAQ.Z X20, Z21, K1, Z22"},
		{"EVEX word memory zeroing", []byte{0x62, 0xd1, 0x35, 0xaa, 0x71, 0x60, 0x01, 0x03}, "VPSRAW.Z $3, 32(R8), K2, Y9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, recognized, err := decodedX86PackedUniformShiftInstruction(test.code, 64)
			if err != nil || !recognized || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decode %x: raw=%q length=%d recognized=%v err=%v; want %q", test.code, instruction.Raw, length, recognized, err, test.want)
			}
		})
	}
}

func TestTranslateRawPackedArithmeticShiftLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			encodings := [][]byte{
				{0xc5, 0xe9, 0x71, 0xe1, 0x03},
				{0xc5, 0xed, 0x72, 0xe1, 0x07},
				{0x62, 0xf1, 0xed, 0x48, 0x72, 0xe1, 0x07},
				{0xc5, 0xed, 0xe1, 0xd9},
				{0x62, 0xf1, 0x6d, 0x48, 0xe2, 0xd9},
				{0x62, 0xf1, 0xed, 0x48, 0xe2, 0xd9},
			}
			encodings = append(encodings, []byte{0x62, 0xf1, 0x6d, 0xbb, 0x72, 0x20, 0x07})
			var source strings.Builder
			source.WriteString("TEXT packedArithmeticShiftRaw(SB), $0-0\n")
			for _, code := range encodings {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"packedArithmeticShiftRaw": {Name: "packedArithmeticShiftRaw", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-arithmetic-shift.ll", "raw-arithmetic-shift.o", ir)
		})
	}
}

func TestDecodeX86RawDirectiveGroupReportedMinioVPSRLD(t *testing.T) {
	code := []byte{0x62, 0x91, 0x05, 0x48, 0x72, 0xd6, 0x0a}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VPSRLD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPSRLD" || !strings.HasPrefix(decoded[0].Raw, "VPSRLD $10, Z30, Z15 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
