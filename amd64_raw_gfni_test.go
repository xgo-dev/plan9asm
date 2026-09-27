package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeX86RawGFNIGoFECRegression(t *testing.T) {
	// GoFEC v1.4.2 emits this EVEX-512 affine instruction as BYTE directives.
	code := []byte{0x62, 0xf3, 0x85, 0x48, 0xce, 0xc8, 0x00}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "GoFEC GFNI", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || !strings.HasPrefix(decoded[0].Raw, "VGF2P8AFFINEQB $0, Z0, Z15, Z1 ") {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawGFNICompleteGoFamily(t *testing.T) {
	for _, family := range []struct {
		name   string
		mapID  byte
		opcode byte
		w      byte
		imm    bool
	}{
		{name: "VGF2P8MULB", mapID: 2, opcode: 0xcf},
		{name: "VGF2P8AFFINEQB", mapID: 3, opcode: 0xce, w: 1, imm: true},
		{name: "VGF2P8AFFINEINVQB", mapID: 3, opcode: 0xcf, w: 1, imm: true},
	} {
		for _, encoding := range []struct {
			name    string
			width   int
			evex    bool
			masked  bool
			zeroing bool
		}{
			{name: "vex-x", width: 0},
			{name: "vex-y", width: 1},
			{name: "evex-x", width: 0, evex: true},
			{name: "evex-y-mask", width: 1, evex: true, masked: true},
			{name: "evex-z-zero", width: 2, evex: true, masked: true, zeroing: true},
		} {
			t.Run(family.name+"/"+encoding.name, func(t *testing.T) {
				width := []string{"X", "Y", "Z"}[encoding.width]
				var code []byte
				if encoding.evex {
					last := byte(encoding.width<<5) | 0x08
					if encoding.masked {
						last |= 1
					}
					if encoding.zeroing {
						last |= 0x80
					}
					code = []byte{0x62, 0xf0 | family.mapID, family.w<<7 | 0x75, last, family.opcode, 0xd0}
				} else {
					code = []byte{0xc4, 0xe0 | family.mapID, family.w<<7 | 0x71 | byte(encoding.width<<2), family.opcode, 0xd0}
				}
				if family.imm {
					code = append(code, 0x63)
				}
				instruction, length, ok, err := decodedX86GFNIInstruction(code, 64)
				if !ok || err != nil || length != len(code) {
					t.Fatalf("decode %x: ok=%v length=%d err=%v", code, ok, length, err)
				}
				args := fmt.Sprintf("%s0, %s1", width, width)
				if family.imm {
					args = "$99, " + args
				}
				if encoding.masked {
					args += ", K1"
				}
				wantOp := family.name
				if encoding.zeroing {
					wantOp += ".Z"
				}
				want := fmt.Sprintf("%s %s, %s2", wantOp, args, width)
				if instruction.Raw != want {
					t.Fatalf("decode %x as %q, want %q", code, instruction.Raw, want)
				}
			})
		}
	}
}

func TestDecodeX86RawGFNIRejectsReservedForms(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
	}{
		{name: "affine wrong W", code: []byte{0x62, 0xf3, 0x75, 0x48, 0xce, 0xd0, 0x63}},
		{name: "multiply wrong W", code: []byte{0x62, 0xf2, 0xf5, 0x48, 0xcf, 0xd0}},
		{name: "multiply broadcast", code: []byte{0x62, 0xf2, 0x75, 0x58, 0xcf, 0x50, 0x01}},
		{name: "affine broadcast register", code: []byte{0x62, 0xf3, 0xf5, 0x58, 0xce, 0xd0, 0x63}},
		{name: "zero without mask", code: []byte{0x62, 0xf3, 0xf5, 0xc8, 0xce, 0xd0, 0x63}},
		{name: "truncated immediate", code: []byte{0x62, 0xf3, 0xf5, 0x48, 0xce, 0xd0}},
		{name: "reserved vector length", code: []byte{0x62, 0xf3, 0xf5, 0x68, 0xce, 0xd0, 0x63}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, ok, err := decodedX86GFNIInstruction(test.code, 64)
			if !ok || err == nil {
				t.Fatalf("decode %x: ok=%v err=%v, want recognized rejection", test.code, ok, err)
			}
		})
	}
}

func TestDecodeX86RawGFNIMemoryAndBroadcast(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want string
	}{
		{name: "vex multiply memory", code: []byte{0xc4, 0xe2, 0x71, 0xcf, 0x50, 0x08}, want: "VGF2P8MULB 8(AX), X1, X2"},
		{name: "evex affine broadcast", code: []byte{0x62, 0xf3, 0xf5, 0x59, 0xce, 0x50, 0x01, 0x63}, want: "VGF2P8AFFINEQB.BCST $99, 8(AX), Z1, K1, Z2"},
		{name: "evex inverse broadcast zero", code: []byte{0x62, 0xf3, 0xf5, 0xd9, 0xcf, 0x50, 0x01, 0xa5}, want: "VGF2P8AFFINEINVQB.BCST.Z $165, 8(AX), Z1, K1, Z2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86GFNIInstruction(test.code, 64)
			if !ok || err != nil || length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decode %x = %q, length=%d, ok=%v, err=%v; want %q", test.code, instruction.Raw, length, ok, err, test.want)
			}
		})
	}
}

func TestTranslateX86RawGFNIAllObjectTargets(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawgfni(SB),$0-0\n")
			for _, instruction := range [][]byte{
				{0xc4, 0xe2, 0x71, 0xcf, 0xd0},
				{0xc4, 0xe3, 0xf1, 0xce, 0xd0, 0x63},
				{0x62, 0xf3, 0xf5, 0xc9, 0xcf, 0xd0, 0xa5},
			} {
				for _, value := range instruction {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawgfni": {Name: "rawgfni", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "raw-gfni.ll", "raw-gfni.o", ir)
		})
	}
}
