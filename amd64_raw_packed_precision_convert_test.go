package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

var x86RawPackedPrecisionForms = []struct {
	op     Op
	pp     byte
	length byte
	evex   bool
	src    Reg
	dst    Reg
}{
	{"VCVTPS2PD", 0, 0, false, "X1", "X0"},
	{"VCVTPS2PD", 0, 1, false, "X1", "Y0"},
	{"VCVTPS2PD", 0, 0, true, "X1", "X0"},
	{"VCVTPS2PD", 0, 1, true, "X1", "Y0"},
	{"VCVTPS2PD", 0, 2, true, "Y1", "Z0"},
	{"VCVTPD2PSX", 1, 0, false, "X1", "X0"},
	{"VCVTPD2PSY", 1, 1, false, "Y1", "X0"},
	{"VCVTPD2PSX", 1, 0, true, "X1", "X0"},
	{"VCVTPD2PSY", 1, 1, true, "Y1", "X0"},
	{"VCVTPD2PS", 1, 2, true, "Z1", "Y0"},
}

func rawPackedPrecisionBytes(pp, length byte, evex, memory bool) []byte {
	modRM := byte(0xc1)
	if memory {
		modRM = 0x08
	}
	if evex {
		w := byte(0)
		if pp == 1 {
			w = 0x80
		}
		return []byte{0x62, 0xf1, 0x7c | pp | w, 0x08 | length<<5, 0x5a, modRM}
	}
	return []byte{0xc5, 0xf8 | pp | length<<2, 0x5a, modRM}
}

func TestX86RawPackedPrecisionConvertArrowRegression(t *testing.T) {
	// Arrow emits this VEX.256 VCVTPS2PD as raw bytes. x/arch v0.14
	// incorrectly starts with a legacy POP rather than decoding the vector op.
	code := []byte{0xc5, 0xfc, 0x5a, 0x04, 0xba}
	decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != "VCVTPS2PD" {
		t.Fatalf("raw %#x decoded as %+v", code, decoded.Instrs)
	}
}

func TestX86RawPackedPrecisionConvertCompleteGo127BaseForms(t *testing.T) {
	if len(x86RawPackedPrecisionForms) != 10 {
		t.Fatal("Go 1.27 packed 5A table requires ten VEX/EVEX width forms")
	}
	for _, form := range x86RawPackedPrecisionForms {
		for _, memory := range []bool{false, true} {
			name := fmt.Sprintf("%s/LL=%d/EVEX=%t/memory=%t", form.op, form.length, form.evex, memory)
			t.Run(name, func(t *testing.T) {
				code := rawPackedPrecisionBytes(form.pp, form.length, form.evex, memory)
				decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != form.op {
					t.Fatalf("raw %#x decoded as %+v; want %s", code, decoded.Instrs, form.op)
				}
				args := decoded.Instrs[0].Args
				if len(args) != 2 {
					t.Fatalf("raw %#x operands = %+v", code, args)
				}
				if memory {
					if args[0].Kind != OpMem || args[0].Mem.Base != AX {
						t.Fatalf("raw %#x memory source = %+v", code, args[0])
					}
				} else if args[0].Kind != OpReg || args[0].Reg != form.src {
					t.Fatalf("raw %#x source = %+v; want %s", code, args[0], form.src)
				}
				wantDestination := form.dst
				if memory {
					wantDestination = Reg(string(form.dst[:1]) + "1")
				}
				if args[1].Reg != wantDestination {
					t.Fatalf("raw %#x destination = %s; want %s", code, args[1].Reg, wantDestination)
				}
			})
		}
	}
}

func TestX86RawPackedPrecisionConvertEncodingAxes(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		op   Op
		args []string
	}{
		{"VEX-W-ignored", []byte{0xc4, 0xe1, 0xfc, 0x5a, 0xc1}, "VCVTPS2PD", []string{"X1", "Y0"}},
		{"masked", []byte{0x62, 0xf1, 0x7c, 0x09, 0x5a, 0xc1}, "VCVTPS2PD", []string{"X1", "K1", "X0"}},
		{"broadcast-zero", []byte{0x62, 0xf1, 0x7c, 0x99, 0x5a, 0x00}, "VCVTPS2PD.BCST.Z", []string{"0(AX)", "K1", "X0"}},
		{"single-to-double-SAE", []byte{0x62, 0xf1, 0x7c, 0x18, 0x5a, 0xc1}, "VCVTPS2PD.SAE", []string{"Y1", "Z0"}},
		{"double-to-single-round-down", []byte{0x62, 0xf1, 0xfd, 0x39, 0x5a, 0xd8}, "VCVTPD2PS.RD_SAE", []string{"Z0", "K1", "Y3"}},
		{"extended-registers", []byte{0x62, 0xa1, 0x7c, 0x08, 0x5a, 0xc1}, "VCVTPS2PD", []string{"X17", "X16"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, length, recognized, err := decodedX86PackedPrecisionConvertInstruction(tc.code, 64)
			if !recognized || err != nil || length != len(tc.code) || got.Op != tc.op {
				t.Fatalf("decode %#x = %+v, %d, %v, %v; want %s", tc.code, got, length, recognized, err, tc.op)
			}
			if len(got.Args) != len(tc.args) {
				t.Fatalf("decode %#x operands = %+v; want %v", tc.code, got.Args, tc.args)
			}
			for index, arg := range got.Args {
				if arg.String() != tc.args[index] {
					t.Fatalf("decode %#x operand %d = %s; want %s", tc.code, index, arg.String(), tc.args[index])
				}
			}
		})
	}
	for _, tc := range []struct {
		name string
		code []byte
		off  int64
	}{
		{"single-Z-disp8", []byte{0x62, 0xf1, 0x7c, 0x48, 0x5a, 0x40, 0x02}, 64},
		{"double-Y-disp8", []byte{0x62, 0xf1, 0xfd, 0x28, 0x5a, 0x40, 0x02}, 64},
		{"double-broadcast-disp8", []byte{0x62, 0xf1, 0xfd, 0x38, 0x5a, 0x40, 0x02}, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, recognized, err := decodedX86PackedPrecisionConvertInstruction(tc.code, 64)
			if !recognized || err != nil || got.Args[0].Kind != OpMem || got.Args[0].Mem.Off != tc.off {
				t.Fatalf("decode %#x = %+v, %v, %v; want offset %d", tc.code, got, recognized, err, tc.off)
			}
		})
	}
	for _, code := range [][]byte{
		{0x62, 0xa1, 0x7c, 0x08, 0x5a, 0xc1}, // X17 -> X16.
		{0x62, 0xa1, 0xfd, 0x28, 0x5a, 0xc1}, // Y17 -> X16.
	} {
		if got, _, recognized, err := decodedX86PackedPrecisionConvertInstruction(code, 32); !recognized || err != nil || len(got.Args) != 2 {
			t.Fatalf("386 EVEX high X/Y register %#x = %+v, %v, %v", code, got, recognized, err)
		}
	}
	requireX86GoAssemblerResult(t, "386", "TEXT high(SB),4,$0-0\n\tVCVTPS2PD X17, K1, X16\n\tVCVTPD2PSY Y17, K1, X16\n\tRET\n", true)
}

func TestX86RawPackedPrecisionConvertRejectsReservedEncodings(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		mode int
	}{
		{"VEX-vvvv", []byte{0xc5, 0xe8, 0x5a, 0xc1}, 64},
		{"EVEX-vvvv", []byte{0x62, 0xf1, 0x6c, 0x08, 0x5a, 0xc1}, 64},
		{"EVEX-zero-without-mask", []byte{0x62, 0xf1, 0x7c, 0x88, 0x5a, 0xc1}, 64},
		{"EVEX-LL3-without-control", []byte{0x62, 0xf1, 0x7c, 0x68, 0x5a, 0xc1}, 64},
		{"EVEX-W-mismatch", []byte{0x62, 0xf1, 0xfc, 0x08, 0x5a, 0xc1}, 64},
		{"address-override", []byte{0x67, 0xc5, 0xf8, 0x5a, 0xc1}, 64},
		{"missing-ModRM", []byte{0xc5, 0xf8, 0x5a}, 64},
		{"extended-386", []byte{0xc4, 0x61, 0x78, 0x5a, 0xc1}, 32},
		{"Z-destination-386", []byte{0x62, 0xe1, 0x7c, 0x48, 0x5a, 0xc1}, 32},
		{"Z-source-386", []byte{0x62, 0xb1, 0xfd, 0x48, 0x5a, 0xc1}, 32},
		{"extended-memory-386", []byte{0x62, 0xb1, 0x7c, 0x08, 0x5a, 0x01}, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86PackedPrecisionConvertInstruction(tc.code, tc.mode); !recognized || err == nil {
				t.Fatalf("reserved encoding %#x: recognized=%v error=%v", tc.code, recognized, err)
			}
		})
	}
}

func TestX86RawPackedPrecisionConvertCompilesEveryBaseForm(t *testing.T) {
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
			source.WriteString("TEXT rawprecisionconversion(SB),4,$0-0\n")
			encodings := make([][]byte, 0, len(x86RawPackedPrecisionForms)+5)
			for _, form := range x86RawPackedPrecisionForms {
				encodings = append(encodings, rawPackedPrecisionBytes(form.pp, form.length, form.evex, false))
			}
			encodings = append(encodings,
				[]byte{0x62, 0xf1, 0x7c, 0x99, 0x5a, 0x00},       // PS broadcast, mask, zero.
				[]byte{0x62, 0xf1, 0x7c, 0x18, 0x5a, 0xc1},       // PS suppress exceptions.
				[]byte{0x62, 0xf1, 0xfd, 0x39, 0x5a, 0xd8},       // PD embedded rounding.
				[]byte{0x62, 0xf1, 0xfd, 0x38, 0x5a, 0x40, 0x02}, // PD broadcast disp8.
				[]byte{0x62, 0xa1, 0x7c, 0x08, 0x5a, 0xc1},       // EVEX high X in 386/amd64.
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
				Sigs: map[string]FuncSig{"rawprecisionconversion": {Name: "rawprecisionconversion", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-precision-conversion.ll", "raw-precision-conversion.o", ir)
		})
	}
}

func TestX86RawPackedPrecisionConvertRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const namedSource = `
TEXT packedprecision(SB),4,$0-24
	MOVQ out+0(FP), AX
	MOVQ singles+8(FP), BX
	MOVQ doubles+16(FP), CX
	VCVTPS2PD (BX), Y1
	VMOVUPD Y1, (AX)
	VCVTPD2PSY (CX), X2
	VMOVUPS X2, 32(AX)
	VZEROUPPER
	RET
`
	rawSource := strings.NewReplacer(
		"VCVTPS2PD (BX), Y1", "BYTE $0xc5; BYTE $0xfc; BYTE $0x5a; BYTE $0x0b",
		"VCVTPD2PSY (CX), X2", "BYTE $0xc5; BYTE $0xfd; BYTE $0x5a; BYTE $0x11",
	).Replace(namedSource)
	requireX86GoAssemblerResult(t, "amd64", namedSource, true)
	requireX86GoAssemblerResult(t, "amd64", rawSource, true)

	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	options := Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"packedprecision": {
				Name: "packedprecision", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void packedprecision(uint8_t *, const float *, const double *);
int main(void) {
  const float singles[4] = {1.5f, -2.25f, 3.0f, 4.0f};
  const double doubles[4] = {1.5, -2.25, 3.0, 4.0};
  uint8_t out[48];
  double widened[4];
  float narrowed[4];
  memset(out, 0xcc, sizeof(out));
  packedprecision(out, singles, doubles);
  memcpy(widened, out, sizeof(widened));
  memcpy(narrowed, out + 32, sizeof(narrowed));
  for (int i = 0; i < 4; i++) {
    if (widened[i] != (double)singles[i]) return 10 + i;
    if (narrowed[i] != (float)doubles[i]) return 20 + i;
  }
  return 0;
}
`
	for _, tc := range []struct{ name, source string }{
		{"named", namedSource},
		{"raw", rawSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, tc.source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_precision_"+tc.name, triple, ir, mainC, runPrefix)
		})
	}
}
