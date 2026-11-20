package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86VectorAliasCase struct {
	name, instructions, expected string
}

var x86VectorAliasCases = []x86VectorAliasCase{
	{"wide_to_narrow", "VMOVDQU64 (SI), Z1\nMOVOU X1, (DI)", "i < 16 ? in[i] : 0"},
	{"legacy_preserves_upper", "VMOVDQU64 (SI), Z1\nMOVOU 64(SI), X1\nVMOVDQU64 Z1, (DI)", "i < 16 ? in[64+i] : in[i]"},
	{"vex128_clears_upper", "VMOVDQU64 (SI), Z1\nMOVOU 64(SI), X2\nVMOVAPS X2, X1\nVMOVDQU64 Z1, (DI)", "i < 16 ? in[64+i] : 0"},
	{"vex256_clears_upper", "VMOVDQU64 (SI), Z1\nVMOVDQU 64(SI), Y1\nVMOVDQU64 Z1, (DI)", "i < 32 ? in[64+i] : 0"},
	{"zero_upper", "VMOVDQU64 (SI), Z1\nVZEROUPPER\nVMOVDQU64 Z1, (DI)", "i < 16 ? in[i] : 0"},
	{"zero_all", "VMOVDQU64 (SI), Z1\nVZEROALL\nVMOVDQU64 Z1, (DI)", "0"},
}

func x86VectorAliasIR(t *testing.T, arch, triple string, tc x86VectorAliasCase) string {
	t.Helper()
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	source := fmt.Sprintf("TEXT ·probe(SB),4,$0-%d\n%s in+0(FP), SI\n%s out+%d(FP), DI\n%s\nRET\n",
		2*word, move, move, word, tc.instructions)
	goAssemblerOracleOutput(t, arch, source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	// Derive the ABI0 slots from the complete first-party declaration, not
	// hand-built offsets. Pointee types do not supply a caller/native-frame
	// certificate. This fixture observes explicitly initialized C buffers.
	pkg := x86AddSubLiteralPackage(t, arch, "func probe(in *[128]byte, out *[64]byte)\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       arch,
		ResolveSym:   resolve,
		Sigs:         sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ll
}

func TestX86VectorRegisterAliasesFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		arch, triple string
	}{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		for _, tc := range x86VectorAliasCases {
			t.Run(target.triple+"/"+tc.name, func(t *testing.T) {
				ll := x86VectorAliasIR(t, target.arch, target.triple, tc)
				compileLLVMToObject(t, llc, target.triple, "alias.ll", "alias.o", ll)
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixAMD64VectorRegisterAliases(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	for _, tc := range x86VectorAliasCases {
		t.Run(tc.name, func(t *testing.T) {
			ll := x86VectorAliasIR(t, "amd64", triple, tc)
			mainC := fmt.Sprintf(`#include <stdio.h>
extern void probe(unsigned char *, unsigned char *);
int main(void) {
    unsigned char in[128], out[66] = {0};
    for (int i = 0; i < 128; ++i)
        in[i] = (unsigned char)(i + 1);
    out[0] = out[65] = 0xa5;
    probe(in, out + 1);
    if (out[0] != 0xa5 || out[65] != 0xa5)
        return 2;
    for (int i = 0; i < 128; ++i)
        if (in[i] != (unsigned char)(i + 1))
            return 3;
    for (int i = 0; i < 64; ++i) {
        unsigned char want = %s;
        if (out[i + 1] != want) {
            fprintf(stderr, "byte %%d: got %%u, want %%u\n", i, out[i + 1], want);
            return 1;
        }
    }
    return 0;
}`, tc.expected)
			compileAndRunRuntimeTestForTarget(t, llc, clang, "vector_alias", triple, ll, mainC, prefix)
		})
	}
}
