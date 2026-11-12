package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEFloatOpcodeAndSourceFields(t *testing.T) {
	for _, test := range []struct {
		native             string
		kind               arm64RawSVEFloatKind
		first, destination int
	}{
		{"fsub z4.s, p2/m, z4.s, z7.s", arm64RawSVEFloatSub, 7, 4},
		{"fmul z4.d, p7/m, z4.d, z7.d", arm64RawSVEFloatMul, 7, 4},
		{"faddv h3, p1, z7.h", arm64RawSVEFloatFADDV, 7, 3},
	} {
		word := assembleARM64LLVMWords(t, []string{test.native}, "+sve")[0]
		got, ok := decodeARM64RawSVEFloat(word)
		if !ok || got.kind != test.kind || got.first != test.first || got.destination != test.destination {
			t.Errorf("%s: decoded %#08x as %+v, %v", test.native, word, got, ok)
		}
	}
	for _, native := range []string{"fmax z4.s, p2/m, z4.s, z7.s", "fdiv z0.d, p0/m, z0.d, z1.d"} {
		word := assembleARM64LLVMWords(t, []string{native}, "+sve")[0]
		if got, ok := decodeARM64RawSVEFloat(word); ok {
			t.Errorf("unrelated %s must not decode as arithmetic %+v", native, got)
		}
	}
}

func TestARM64RawSVEFloatUsesSharedNamedSemantics(t *testing.T) {
	for _, test := range []struct{ native, want string }{
		{"fsub z4.s, p2/m, z4.s, z7.s", "fsub <vscale x 4 x float>"},
		{"fmul z4.d, p7/m, z4.d, z7.d", "fmul <vscale x 2 x double>"},
		{"faddv h3, p1, z7.h", "call half @llvm.aarch64.sve.faddv.nxv8f16"},
		{"fadda s3, p1, s3, z7.s", "call float @llvm.aarch64.sve.fadda.nxv4f32"},
	} {
		word := assembleARM64LLVMWords(t, []string{test.native}, "+sve")[0]
		source := fmt.Sprintf("TEXT rawfloat(SB),$0-0\nWORD $%#08x\nRET\n", word)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"rawfloat": {Name: "rawfloat", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, test.want) {
			t.Errorf("%s omitted %s", test.native, test.want)
		}
	}
}
