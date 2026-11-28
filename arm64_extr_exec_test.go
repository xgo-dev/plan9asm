//go:build !llgo

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func archExtr64(rm, rn uint64, sh uint) uint64 {
	sh &= 63
	if sh == 0 {
		return rm
	}
	return (rn << (64 - sh)) | (rm >> sh)
}

func archExtr32(rm, rn uint32, sh uint) uint32 {
	sh &= 31
	if sh == 0 {
		return rm
	}
	return (rn << (32 - sh)) | (rm >> sh)
}

// TestARM64EXTRMatchesNativeGoAsm verifies ARM64 EXTR and EXTRW operand order
// (EXTR $lsb, Rm, Rn, Rd => extract from Rn:Rm at bit lsb) and shift==0
// semantics against both the architectural spec and Go's native ARM64 assembler
// execution on arm64 hosts.
func TestARM64EXTRMatchesNativeGoAsm(t *testing.T) {
	src := `
TEXT ·extrKernel(SB),NOSPLIT,$0-24
	MOVD out+0(FP), R0
	MOVD rm+8(FP), R22
	MOVD rn+16(FP), R12

	EXTR $35, R22, R12, R8
	MOVD R8, 0(R0)

	EXTR $0, R22, R12, R8
	MOVD R8, 8(R0)

	EXTR $1, R22, R12, R8
	MOVD R8, 16(R0)

	EXTR $63, R22, R12, R8
	MOVD R8, 24(R0)

	EXTRW $17, R22, R12, R8
	MOVD R8, 32(R0)

	EXTRW $0, R22, R12, R8
	MOVD R8, 40(R0)
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"extrKernel": {
				Name: "extrKernel",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Translate failed: %v", err)
	}
	if !strings.Contains(ll, "@llvm.fshr.i64") || !strings.Contains(ll, "@llvm.fshr.i32") {
		t.Fatalf("expected @llvm.fshr.i64 and @llvm.fshr.i32 in EXTR/EXTRW IR:\n%s", ll)
	}
	verifyLLVMWithTargetLLC(t, ll, "aarch64-unknown-linux-gnu")

	rm := uint64(0x1122334455667788)
	rn := uint64(0x99aabbccddeeff01)
	want35 := archExtr64(rm, rn, 35)
	want0 := archExtr64(rm, rn, 0)
	want1 := archExtr64(rm, rn, 1)
	want63 := archExtr64(rm, rn, 63)
	wantW17 := archExtr32(uint32(rm), uint32(rn), 17)
	wantW0 := archExtr32(uint32(rm), uint32(rn), 0)

	if nr35, nr0, nr1, nr63, nw17, nw0, hasNative := nativeARM64ExtrReference(rm, rn); hasNative {
		if nr35 != want35 || nr0 != want0 || nr1 != want1 || nr63 != want63 || nw17 != wantW17 || nw0 != wantW0 {
			t.Fatalf("architectural formula mismatch vs native Go ARM64 asm: got=(%x,%x,%x,%x,%x,%x) native=(%x,%x,%x,%x,%x,%x)",
				want35, want0, want1, want63, wantW17, wantW0, nr35, nr0, nr1, nr63, nw17, nw0)
		}
	}

	llc, clang := requireLlcAndClang(t)
	mainC := fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>
extern void extrKernel(uint64_t *out, uint64_t rm, uint64_t rn);
int main(void) {
    uint64_t out[6] = {0};
    extrKernel(out, 0x%016xULL, 0x%016xULL);
    uint64_t want[6] = {
        0x%016xULL,
        0x%016xULL,
        0x%016xULL,
        0x%016xULL,
        0x%016xULL,
        0x%016xULL,
    };
    for (int i = 0; i < 6; i++) {
        if (out[i] != want[i]) {
            fprintf(stderr, "extr[%%d] got=0x%%016llx want=0x%%016llx\n", i, (unsigned long long)out[i], (unsigned long long)want[i]);
            return i + 1;
        }
    }
    return 0;
}
`, rm, rn, want35, want0, want1, want63, uint64(wantW17), uint64(wantW0))
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "arm64_extr_exec", triple, ll, mainC, nil)
}
