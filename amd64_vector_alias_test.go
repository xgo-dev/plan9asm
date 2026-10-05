//go:build !llgo

package plan9asm

import (
	"fmt"
	"runtime"
	"testing"
)

func TestAMD64VectorRegisterAliases(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires amd64 execution")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	for _, tc := range []struct{ name, instructions, expected string }{
		{"wide_to_narrow", "VMOVDQU64 (SI), Z1\nMOVOU X1, (DI)", "i < 16 ? in[i] : 0"},
		{"legacy_preserves_upper", "VMOVDQU64 (SI), Z1\nMOVOU 64(SI), X1\nVMOVDQU64 Z1, (DI)", "i < 16 ? in[64+i] : in[i]"},
		{"vex128_clears_upper", "VMOVDQU64 (SI), Z1\nMOVOU 64(SI), X2\nVMOVAPS X2, X1\nVMOVDQU64 Z1, (DI)", "i < 16 ? in[64+i] : 0"},
		{"vex256_clears_upper", "VMOVDQU64 (SI), Z1\nVMOVDQU 64(SI), Y1\nVMOVDQU64 Z1, (DI)", "i < 32 ? in[64+i] : 0"},
		{"zero_upper", "VMOVDQU64 (SI), Z1\nVZEROUPPER\nVMOVDQU64 Z1, (DI)", "i < 16 ? in[i] : 0"},
		{"zero_all", "VMOVDQU64 (SI), Z1\nVZEROALL\nVMOVDQU64 Z1, (DI)", "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "TEXT probe(SB),NOSPLIT,$0-16\nMOVQ in+0(FP), SI\nMOVQ out+8(FP), DI\n" + tc.instructions + "\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "amd64", Sigs: map[string]FuncSig{"probe": {Name: "probe", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			mainC := fmt.Sprintf(`#include <stdio.h>
extern void probe(unsigned char *, unsigned char *);
int main(void) {
 unsigned char in[128], out[64] = {0};
 for (int i = 0; i < 128; ++i) in[i] = (unsigned char)(i + 1);
 probe(in, out);
 for (int i = 0; i < 64; ++i) {
  unsigned char want = %s;
  if (out[i] != want) { fprintf(stderr, "byte %%d: got %%u, want %%u\n", i, out[i], want); return 1; }
 }
 return 0;
}`, tc.expected)
			compileAndRunRuntimeTestForTarget(t, llc, clang, "vector_alias", triple, ll, mainC, prefix)
		})
	}
}
