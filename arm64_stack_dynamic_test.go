package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64DynamicStackRuntime(t *testing.T, triple string) (string, string) {
	return arm64DynamicStackRuntimeWithFrame(t, triple, 0)
}

func arm64DynamicStackRuntimeWithFrame(t *testing.T, triple string, frame int64) (string, string) {
	t.Helper()
	source := fmt.Sprintf(`TEXT dynamic_stack(SB),$%d-24
MOVD out+0(FP),R0
MOVD size+8(FP),R1
MOVD value+16(FP),R2
MOVD RSP,R20
ADD $8,RSP,R21
MOVD R2,8(RSP)
SUB R1,RSP
MOVD RSP,R3
ADD R1,R3
SUB R3,R20,R4
MOVD R4,0(R0)
MOVD R2,(RSP)
MOVD 8(R20),R5
MOVD R5,8(R0)
MOVD (RSP),R6
MOVD R6,16(R0)
MOVD (R21),R7
MOVD R7,24(R0)
MOVD R20,RSP
MOVD 8(RSP),R8
MOVD R8,32(R0)
RET
`, frame)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"dynamic_stack": {
			Name: "dynamic_stack", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "alloca i8, i64 %") || !strings.Contains(ir, "@llvm.memcpy.p0.p0.i64") {
		t.Fatal("missing runtime-sized backing or preservation of the original frame")
	}
	const main = `
#include <stdint.h>
extern void dynamic_stack(uint64_t*, uint64_t, uint64_t);
int main(void) {
  const uint64_t sizes[] = {0,16,32,192,512,4096,65536,(uint64_t)-16,(uint64_t)-512};
  uint64_t value = 7;
  for (unsigned i = 0; i < 128; i++) {
    for (unsigned n = 0; n < sizeof(sizes)/sizeof(sizes[0]); n++) {
      uint64_t out[7] = {0x1234,99,0,0,0,0,0x5678};
      dynamic_stack(out+1,sizes[n],value);
      if (out[0] != 0x1234 || out[6] != 0x5678 || out[1] != 0) return 1;
      for (unsigned j = 2; j <= 5; j++) if (out[j] != value) return 2;
    }
    value = value * UINT64_C(6364136223846793005) + 1;
  }
  return 0;
}

`
	return ir, main
}

func TestARM64DynamicStackLargeDeclaredFrameLLVM(t *testing.T) {
	llc, clang := findLLVM22Tool("llc"), findLLVM22Tool("clang")
	if llc == "" || clang == "" {
		t.Fatal("LLVM 22 llc and clang are required")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64DynamicStackRuntimeWithFrame(t, triple, 1<<21)
			if !strings.Contains(ir, "%local_stack = alloca i8, i64 %") {
				t.Fatal("declared backing must itself use the large-frame dynamic allocation path")
			}
			compileLLVMToObject(t, llc, triple, "dynamic-large.ll", "dynamic-large.o", ir)
			native := runtime.GOARCH == "arm64" && ((runtime.GOOS == "darwin" && strings.Contains(triple, "apple")) ||
				(runtime.GOOS == "linux" && strings.Contains(triple, "linux")) ||
				(runtime.GOOS == "freebsd" && strings.Contains(triple, "freebsd")))
			if native {
				compileAndRunRuntimeTestForTarget(t, llc, clang, "dynamic-large", triple, ir, main, nil)
			}
		})
	}
}

func TestARM64DynamicStackLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64DynamicStackRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "dynamic.ll", "dynamic.o", ir)
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "dynamic", triple, ir, main, nil)
			}
		})
	}
}

func TestARM64DynamicStackRejectsUnprovedRelocation(t *testing.T) {
	for _, body := range []string{
		"MOVD $8(RSP),R3\nSUB R1,RSP\nMOVD R2,(RSP)",
		"MOVD RSP,R20\nMOVD $8(R20),R3\nSUB R1,RSP\nMOVD R2,(RSP)",
		"MOVD RSP,R3\nMOVD R3,(R0)\nSUB R1,RSP\nMOVD R2,(RSP)",
		"MOVD RSP,R3\nMOVD R3,8(RSP)\nSUB R1,RSP\nMOVD R2,(RSP)",
		"CMP RSP,R0\nSUB R1,RSP\nMOVD R2,(RSP)",
		"BL callee(SB)\nSUB R1,RSP\nMOVD R2,(RSP)",
		"SUB R1,RSP\nSUB R2,RSP\nMOVD R2,(RSP)",
		"again:\nSUB R1,RSP\nMOVD R2,(RSP)\nCBNZ R0,again",
		"MOVD RSP,R3\nEOR $31,R3\nSUB R1,RSP\nMOVD R2,(RSP)",
	} {
		t.Run(body, func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT dynamic(SB),$0-0\n"+body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"dynamic": {Name: "dynamic", Ret: Void}}}); err == nil {
				t.Fatal("accepted a frame whose pointers cannot be relocated safely")
			}
		})
	}
}
