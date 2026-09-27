package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86RawPackedDoubleDwordBaseForms = []struct {
	op     Op
	pp     byte
	length byte
	evex   bool
	src    Reg
	dst    Reg
}{
	{"VCVTDQ2PD", 2, 0, false, "X1", "X0"},
	{"VCVTDQ2PD", 2, 1, false, "X1", "Y0"},
	{"VCVTDQ2PD", 2, 0, true, "X1", "X0"},
	{"VCVTDQ2PD", 2, 1, true, "X1", "Y0"},
	{"VCVTDQ2PD", 2, 2, true, "Y1", "Z0"},
	{"VCVTPD2DQX", 3, 0, false, "X1", "X0"},
	{"VCVTPD2DQY", 3, 1, false, "Y1", "X0"},
	{"VCVTPD2DQX", 3, 0, true, "X1", "X0"},
	{"VCVTPD2DQY", 3, 1, true, "Y1", "X0"},
	{"VCVTPD2DQ", 3, 2, true, "Z1", "Y0"},
	{"VCVTTPD2DQX", 1, 0, false, "X1", "X0"},
	{"VCVTTPD2DQY", 1, 1, false, "Y1", "X0"},
	{"VCVTTPD2DQX", 1, 0, true, "X1", "X0"},
	{"VCVTTPD2DQY", 1, 1, true, "Y1", "X0"},
	{"VCVTTPD2DQ", 1, 2, true, "Z1", "Y0"},
}

func TestX86RawPackedDoubleDwordCompleteGo127BaseForms(t *testing.T) {
	if len(amd64PackedDoubleDwordOps) != 9 {
		t.Fatalf("packed double/dword grammar has %d entries, want nine", len(amd64PackedDoubleDwordOps))
	}
	for _, tc := range x86RawPackedDoubleDwordBaseForms {
		for _, memory := range []bool{false, true} {
			name := fmt.Sprintf("%s/LL=%d/EVEX=%t/memory=%t", tc.op, tc.length, tc.evex, memory)
			t.Run(name, func(t *testing.T) {
				modRM := byte(0xc1)
				if memory {
					modRM = 0x08
				}
				var code []byte
				if tc.evex {
					w := byte(0)
					if tc.pp != 2 {
						w = 0x80
					}
					code = []byte{0x62, 0xf1, 0x7c | tc.pp | w, 0x08 | tc.length<<5, 0xe6, modRM}
				} else {
					code = []byte{0xc5, 0xf8 | tc.pp | tc.length<<2, 0xe6, modRM}
				}
				fn := Func{}
				for _, value := range code {
					fn.Instrs = append(fn.Instrs, Instr{Op: OpBYTE, Args: []Operand{{Kind: OpImm, Imm: int64(value)}}})
				}
				got, err := decodeX86RawDirectives(fn, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				if len(got.Instrs) != 1 || got.Instrs[0].Op != tc.op || len(got.Instrs[0].Args) != 2 {
					t.Fatalf("decoded %#x as %#v, want %s", code, got.Instrs, tc.op)
				}
				args := got.Instrs[0].Args
				if memory {
					if args[0].Kind != OpMem || args[0].Mem.Base != AX {
						t.Fatalf("memory source %#x = %+v", code, args[0])
					}
				} else if args[0].Kind != OpReg || args[0].Reg != tc.src {
					t.Fatalf("register source %#x = %+v, want %s", code, args[0], tc.src)
				}
				wantDestination := tc.dst
				if memory {
					wantDestination = Reg(string(tc.dst[:1]) + "1")
				}
				if args[1].Reg != wantDestination {
					t.Fatalf("destination %#x = %s, want %s", code, args[1].Reg, wantDestination)
				}
			})
		}
	}
}

func TestX86RawPackedDoubleDwordEncodingAxes(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		op   Op
		args []string
	}{
		{"VEX-W-ignored", []byte{0xc4, 0xe1, 0xfe, 0xe6, 0xc1}, "VCVTDQ2PD", []string{"X1", "Y0"}},
		{"masked", []byte{0x62, 0xf1, 0x7e, 0x09, 0xe6, 0xc1}, "VCVTDQ2PD", []string{"X1", "K1", "X0"}},
		{"masked-broadcast-zero", []byte{0x62, 0xf1, 0x7e, 0x99, 0xe6, 0x00}, "VCVTDQ2PD.BCST.Z", []string{"0(AX)", "K1", "X0"}},
		{"round-down-zero", []byte{0x62, 0xf1, 0xff, 0xb9, 0xe6, 0xd8}, "VCVTPD2DQ.RD_SAE.Z", []string{"Z0", "K1", "Y3"}},
		{"truncate-SAE", []byte{0x62, 0xf1, 0xfd, 0x18, 0xe6, 0xc1}, "VCVTTPD2DQ.SAE", []string{"Z1", "Y0"}},
		{"extended-source-and-destination", []byte{0x62, 0xa1, 0x7e, 0x08, 0xe6, 0xc1}, "VCVTDQ2PD", []string{"X17", "X16"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, length, recognized, err := decodedX86PackedDoubleDwordInstruction(tc.code, 64)
			if !recognized || err != nil || length != len(tc.code) || got.Op != tc.op {
				t.Fatalf("decode %#x = %+v, %d, %v, %v; want %s", tc.code, got, length, recognized, err, tc.op)
			}
			if len(got.Args) != len(tc.args) {
				t.Fatalf("decode %#x operands = %+v, want %v", tc.code, got.Args, tc.args)
			}
			for index, arg := range got.Args {
				if arg.String() != tc.args[index] {
					t.Fatalf("decode %#x operand %d = %s, want %s", tc.code, index, arg.String(), tc.args[index])
				}
			}
		})
	}
	for _, tc := range []struct {
		name string
		code []byte
		off  int64
	}{
		{"dword-Z-disp8", []byte{0x62, 0xf1, 0x7e, 0x48, 0xe6, 0x40, 0x02}, 64},
		{"double-Y-disp8", []byte{0x62, 0xf1, 0xff, 0x28, 0xe6, 0x40, 0x02}, 64},
		{"double-broadcast-disp8", []byte{0x62, 0xf1, 0xff, 0x38, 0xe6, 0x40, 0x02}, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, recognized, err := decodedX86PackedDoubleDwordInstruction(tc.code, 64)
			if !recognized || err != nil || got.Args[0].Kind != OpMem || got.Args[0].Mem.Off != tc.off {
				t.Fatalf("decode %#x = %+v, %v, %v; want offset %d", tc.code, got, recognized, err, tc.off)
			}
		})
	}
	for _, code := range [][]byte{
		{0x62, 0xa1, 0x7e, 0x08, 0xe6, 0xc1}, // X17 -> X16.
		{0x62, 0xa1, 0xff, 0x28, 0xe6, 0xc1}, // Y17 -> X16.
	} {
		if got, _, recognized, err := decodedX86PackedDoubleDwordInstruction(code, 32); !recognized || err != nil || len(got.Args) != 2 {
			t.Fatalf("386 EVEX high X/Y register %#x = %+v, %v, %v", code, got, recognized, err)
		}
	}
	requireX86GoAssemblerResult(t, "386", "TEXT high(SB),4,$0-0\n\tVCVTDQ2PD X17, K1, X16\n\tVCVTPD2DQY Y17, K1, X16\n\tRET\n", true)
}

func TestX86RawPackedDoubleDwordRejectsReservedEncodings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"VEX-vvvv", []byte{0xc5, 0xee, 0xe6, 0xc1}, 64},
		{"EVEX-vvvv", []byte{0x62, 0xf1, 0x6e, 0x08, 0xe6, 0xc1}, 64},
		{"EVEX-zero-without-mask", []byte{0x62, 0xf1, 0x7e, 0x88, 0xe6, 0xc1}, 64},
		{"EVEX-LL3-without-rounding", []byte{0x62, 0xf1, 0x7e, 0x68, 0xe6, 0xc1}, 64},
		{"dword-register-broadcast", []byte{0x62, 0xf1, 0x7e, 0x18, 0xe6, 0xc1}, 64},
		{"address-override", []byte{0x67, 0xc5, 0xfe, 0xe6, 0xc1}, 64},
		{"missing-ModRM", []byte{0xc5, 0xfe, 0xe6}, 64},
		{"extended-386", []byte{0xc4, 0x61, 0x7e, 0xe6, 0xc1}, 32},
		{"Z-destination-386", []byte{0x62, 0xe1, 0x7e, 0x48, 0xe6, 0xc1}, 32},
		{"Z-source-386", []byte{0x62, 0xb1, 0xff, 0x48, 0xe6, 0xc1}, 32},
		{"extended-memory-386", []byte{0x62, 0xb1, 0x7e, 0x08, 0xe6, 0x01}, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86PackedDoubleDwordInstruction(tc.code, tc.mode); !recognized || err == nil {
				t.Fatalf("reserved encoding %#x: recognized=%v error=%v", tc.code, recognized, err)
			}
		})
	}
}

func TestX86RawPackedDoubleDwordCompilesEveryBaseForm(t *testing.T) {
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
			source.WriteString("TEXT rawdoubleconversion(SB),4,$0-0\n")
			encodings := make([][]byte, 0, len(x86RawPackedDoubleDwordBaseForms)+4)
			for _, form := range x86RawPackedDoubleDwordBaseForms {
				modRM := byte(0xc1)
				var code []byte
				if form.evex {
					w := byte(0)
					if form.pp != 2 {
						w = 0x80
					}
					code = []byte{0x62, 0xf1, 0x7c | form.pp | w, 0x08 | form.length<<5, 0xe6, modRM}
				} else {
					code = []byte{0xc5, 0xf8 | form.pp | form.length<<2, 0xe6, modRM}
				}
				encodings = append(encodings, code)
			}
			encodings = append(encodings,
				[]byte{0x62, 0xf1, 0x7e, 0x99, 0xe6, 0x00},       // Dword broadcast, mask, zero.
				[]byte{0x62, 0xf1, 0xff, 0xb9, 0xe6, 0xd8},       // Double embedded rounding.
				[]byte{0x62, 0xf1, 0xff, 0x38, 0xe6, 0x40, 0x02}, // Double broadcast disp8.
				[]byte{0x62, 0xa1, 0x7e, 0x08, 0xe6, 0xc1},       // EVEX high X in 386/amd64.
			)
			for _, code := range encodings {
				for _, value := range code {
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
				Sigs: map[string]FuncSig{"rawdoubleconversion": {Name: "rawdoubleconversion", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-double-conversion.ll", "raw-double-conversion.o", ir)
		})
	}
}
