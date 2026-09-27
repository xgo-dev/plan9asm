package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

var x86LegacyPackedConversionForms = []struct {
	name string
	code []byte
	op   Op
}{
	{"dword-to-single-X", []byte{0x0f, 0x5b, 0xc1}, "CVTPL2PS"},
	{"dword-to-single-M", []byte{0x0f, 0x2a, 0xc1}, "CVTPL2PS"},
	{"single-to-dword-X", []byte{0x66, 0x0f, 0x5b, 0xc1}, "CVTPS2PL"},
	{"single-to-dword-M", []byte{0x0f, 0x2d, 0xc1}, "CVTPS2PL"},
	{"truncate-single-X", []byte{0xf3, 0x0f, 0x5b, 0xc1}, "CVTTPS2PL"},
	{"truncate-single-M", []byte{0x0f, 0x2c, 0xc1}, "CVTTPS2PL"},
	{"dword-to-double-X", []byte{0xf3, 0x0f, 0xe6, 0xc1}, "CVTPL2PD"},
	{"dword-to-double-M", []byte{0x66, 0x0f, 0x2a, 0xc1}, "CVTPL2PD"},
	{"double-to-dword-X", []byte{0xf2, 0x0f, 0xe6, 0xc1}, "CVTPD2PL"},
	{"double-to-dword-M", []byte{0x66, 0x0f, 0x2d, 0xc1}, "CVTPD2PL"},
	{"truncate-double-X", []byte{0x66, 0x0f, 0xe6, 0xc1}, "CVTTPD2PL"},
	{"truncate-double-M", []byte{0x66, 0x0f, 0x2c, 0xc1}, "CVTTPD2PL"},
}

func TestX86RawLegacyPackedConversionGo127Names(t *testing.T) {
	for _, form := range x86LegacyPackedConversionForms {
		t.Run(form.name, func(t *testing.T) {
			decoded, err := decodeX86RawDirectives(rawX86Function(form.code), "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != form.op {
				t.Fatalf("raw %#x decoded as %+v; want %s", form.code, decoded.Instrs, form.op)
			}
		})
	}
}

func TestX86RawLegacyPackedConversionCompilesEveryForm(t *testing.T) {
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
			sigs := make(map[string]FuncSig, len(x86LegacyPackedConversionForms))
			for index, form := range x86LegacyPackedConversionForms {
				name := fmt.Sprintf("rawlegacyconversion%d", index)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
				for _, value := range form.code {
					fmt.Fprintf(&source, "\tBYTE $%d\n", value)
				}
				source.WriteString("\tRET\n")
				sigs[name] = FuncSig{Name: name, Ret: Void}
			}
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple, Sigs: sigs,
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-legacy-conversion.ll", "raw-legacy-conversion.o", ir)
		})
	}
}

func TestX86RawLegacyPackedConversionRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const namedSource = `
TEXT legacyconvert(SB),4,$0-16
	MOVQ out+0(FP), AX
	MOVQ input+8(FP), BX
	MOVOU (BX), X1
	CVTPS2PL X1, X0
	MOVOU X0, (AX)
	CVTTPS2PL X1, X0
	MOVOU X0, 16(AX)
	CVTPS2PL X1, M0
	MOVQ M0, 32(AX)
	CVTTPS2PL X1, M0
	MOVQ M0, 40(AX)
	EMMS
	RET
`
	rawSource := strings.NewReplacer(
		"CVTPS2PL X1, X0", "BYTE $0x66; BYTE $0x0f; BYTE $0x5b; BYTE $0xc1",
		"CVTTPS2PL X1, X0", "BYTE $0xf3; BYTE $0x0f; BYTE $0x5b; BYTE $0xc1",
		"CVTPS2PL X1, M0", "BYTE $0x0f; BYTE $0x2d; BYTE $0xc1",
		"CVTTPS2PL X1, M0", "BYTE $0x0f; BYTE $0x2c; BYTE $0xc1",
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
			"legacyconvert": {
				Name: "legacyconvert", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void legacyconvert(uint8_t *, const float *);
int main(void) {
  const float input[4] = {1.5f, -2.5f, 3.5f, -4.5f};
  const int32_t nearest[4] = {2, -2, 4, -4};
  const int32_t truncated[4] = {1, -2, 3, -4};
  uint8_t out[48];
  int32_t values[12];
  memset(out, 0xcc, sizeof(out));
  legacyconvert(out, input);
  memcpy(values, out, sizeof(values));
  for (int i = 0; i < 4; i++) {
    if (values[i] != nearest[i]) return 10 + i;
    if (values[4+i] != truncated[i]) return 20 + i;
  }
  for (int i = 0; i < 2; i++) {
    if (values[8+i] != nearest[i]) return 30 + i;
    if (values[10+i] != truncated[i]) return 40 + i;
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
			compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy_conversion_"+tc.name, triple, ir, mainC, runPrefix)
		})
	}
}
