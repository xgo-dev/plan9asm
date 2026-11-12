package plan9asm

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

const arm64BackwardFlagsSource = `
TEXT delayedFlags(SB),4,$0-24
    MOVD a+0(FP), R0
    MOVD b+8(FP), R1
    JMP compare
use:
    CSET LO, R2
    MOVD R2, ret+16(FP)
    RET
compare:
    CMP R1, R0
    JMP use
`

func arm64BackwardFlagsSig() FuncSig {
	return FuncSig{
		Name: "delayedFlags", Args: []LLVMType{I64, I64}, Ret: I64,
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			},
			Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
		},
	}
}

func TestARM64FlagsFollowControlFlowNotSourceOrder(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64BackwardFlagsSource, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64BackwardFlagsSource)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"delayedFlags": arm64BackwardFlagsSig()},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "flags.ll", "flags.o", ir)
		})
	}
}

func TestARM64FlagsRejectUninitializedControlFlowPaths(t *testing.T) {
	for _, read := range []string{
		"CSET LO, R1",
		"CSEL LO, R1, R2, R3",
		"CCMP LO, R1, R2, $0",
		"BCC done",
	} {
		for _, entry := range []string{
			"JMP use", "CBZ R0, use", "CBNZ R0, use", "CBZW R0, use",
			"CBNZW R0, use", "TBZ $0, R0, use", "TBNZ $0, R0, use",
		} {
			t.Run(entry+"/"+read, func(t *testing.T) {
				// A lexical flag write in another path must not make a read
				// valid on the direct entry -> use path.
				source := "TEXT missing(SB),4,$0-0\n" + entry + "\nCMP $1, R0\nuse:\n" + read + "\ndone:\nRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{
					Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"missing": {Name: "missing", Ret: Void}},
				})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("uninitialized flag path: got %v, want ErrProbeNeedsContext", err)
				}
			})
		}
	}
}

func TestARM64ConformanceBackwardFlagFlow(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !cross {
		t.Skip("arm64 native execution or the required Linux cross-runtime matrix")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compiler := []string{findLLVM22Tool("clang")}
	var runner []string
	if cross {
		triple = "aarch64-unknown-linux-gnu"
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runner = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
	} else if compiler[0] == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	file, err := Parse(ArchARM64, arm64BackwardFlagsSource)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"delayedFlags": arm64BackwardFlagsSig()},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern uint64_t delayedFlags(uint64_t, uint64_t);
int main(void) {
    uint64_t values[] = {0, 1, 2, UINT64_MAX, UINT64_MAX / 2, UINT64_MAX / 2 + 1};
    for (unsigned i = 0; i < 6; i++) {
        for (unsigned j = 0; j < 6; j++) {
            if (delayedFlags(values[i], values[j]) != (values[i] < values[j])) return 1;
        }
    }
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "backward-flags", triple, ir, mainC, runner)
}

func TestARM64FlagsRejectIndirectAndLocalReturnPaths(t *testing.T) {
	for _, source := range []string{
		"TEXT missing(SB),4,$0-0\nADR use, R0\nJMP (R0)\nuse:\nCSET LO, R1\nRET\n",
		"TEXT missing(SB),4,$0-0\nBL helper\nCSET LO, R1\nRET\nhelper:\nRET\n",
	} {
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{
			Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			Sigs: map[string]FuncSig{"missing": {Name: "missing", Ret: Void}},
		})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("indirect flag path: got %v, want ErrProbeNeedsContext", err)
		}
	}
}
