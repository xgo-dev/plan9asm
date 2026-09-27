package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// FEAT_RNG is optional on physical ARM64 hosts. Exercise both random-source
// variants on the required Linux/QEMU CPU=max cross-runtime job.
func TestCrossLinuxRuntimeMatrixARM64RNDR(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("RNDR execution belongs to the required Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime driver requires linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"aarch64-linux-gnu-gcc", "qemu-aarch64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", tool, err)
		}
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir := arm64RNDRStatusFixtureIR(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc"}, "arm64_rndr_status", triple, ir,
		arm64RNDRStatusOracleC,
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func TestARM64RNDRStatusFixtureLLVM22Object(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir := arm64RNDRStatusFixtureIR(t, triple)
	compileLLVMToObject(t, llc, triple, "arm64-rndr-status.ll", "arm64-rndr-status.o", ir)
}

func arm64RNDRStatusFixtureIR(t *testing.T, triple string) string {
	t.Helper()
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range []struct {
		name string
		word uint32
	}{
		{name: "randomStatus", word: 0xd53b2400},
		{name: "reseedStatus", word: 0xd53b2420},
	} {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\n", form.name)
		source.WriteString("MOVD out+0(FP),R10\n")
		fmt.Fprintf(&source, "WORD $%#08x\n", form.word)
		source.WriteString("CSET EQ,R1\nCSET MI,R2\nCSET CS,R3\nCSET VS,R4\n")
		source.WriteString("MOVD R0,0(R10)\nMOVD R1,8(R10)\n")
		source.WriteString("MOVD R2,16(R10)\nMOVD R3,24(R10)\n")
		source.WriteString("MOVD R4,32(R10)\nRET\n")
		sigs[form.name] = FuncSig{
			Name: form.name, Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			}},
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

const arm64RNDRStatusOracleC = `
#include <stdint.h>

extern void randomStatus(uint64_t out[5]);
extern void reseedStatus(uint64_t out[5]);

static int check(void (*read_status)(uint64_t out[5])) {
    unsigned successes = 0;
    for (unsigned i = 0; i < 128; i++) {
        uint64_t out[5] = {0};
        read_status(out);
        // The architecture writes NZCV=0000 on success, 0100 on failure.
        if (out[1] > 1 || out[2] != 0 || out[3] != 0 || out[4] != 0)
            return 1;
        if (out[1] != 0 && out[0] != 0)
            return 2;
        successes += out[1] == 0;
    }
    return successes == 0 ? 3 : 0;
}

int main(void) {
    int result = check(randomStatus);
    if (result != 0)
        return result;
    result = check(reseedStatus);
    return result == 0 ? 0 : result + 3;
}
`
