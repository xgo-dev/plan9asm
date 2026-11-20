package plan9asm

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64NegateCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT negateforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"NEG", "NEGW", "NEGS", "NEGSW"} {
		source.WriteString("\t" + op + " R1, R2\n")
		source.WriteString("\t" + op + " R2\n")
		source.WriteString("\t" + op + " R3<<1, R4\n")
		source.WriteString("\t" + op + " R5>>1, R6\n")
		source.WriteString("\t" + op + " R7->1, R8\n")
	}
	for _, op := range []string{"NGC", "NGCW", "NGCS", "NGCSW"} {
		source.WriteString("\t" + op + " R9, R10\n")
	}
	source.WriteString("\tRET\n")

	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-arm64", triple: "arm64-apple-darwin"},
		{name: "linux-arm64", triple: "aarch64-unknown-linux-gnu"},
		{name: "windows-arm64", triple: "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"negateforms": {Name: "negateforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "arm64-negate-"+target.name+".ll", "arm64-negate-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64NegateRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"NEG $1, R0",
		"NEG 0(R1), R0",
		"NEG RSP, R0",
		"NEG R0, RSP",
		"NEG R0, R1, R2",
		"NEG R1<<64, R2",
		"NEGW R1<<32, R2",
		"NEGS R1@>2, R2",
		"NGC R1",
		"NGC R1<<1, R2",
		"NGCS RSP, R2",
		"NGCSW R1, RSP",
		"NGC.P R1, R2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 NEG/NGC tables", instruction)
			}
		})
	}
}

func TestARM64NegateRuntimeSemantics(t *testing.T) {
	crossLinux := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !crossLinux {
		t.Skip("runtime execution test only runs on an arm64 host")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compiler := []string{}
	var runPrefix []string
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	if crossLinux {
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runPrefix = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
		triple = "aarch64-unknown-linux-gnu"
	} else {
		_, clang, ok := findLlcAndClang(t)
		if !ok {
			t.Fatal("clang not found")
		}
		compiler = []string{clang}
	}

	const source = `
TEXT negatesemantics(SB),NOSPLIT,$0-8
	MOVD out+0(FP), R20
	MOVD $5, R0
	NEGS R0, R1
	CSET CS, R2
	CSET MI, R3
	NGCS R0, R4
	MOVD R1, 0(R20)
	MOVD R2, 8(R20)
	MOVD R3, 16(R20)
	MOVD R4, 24(R20)
	NEGS ZR, R5
	NGC R0, R6
	MOVD R6, 32(R20)
	MOVD $0x80000000, R7
	NEGSW R7, R8
	CSET VS, R9
	MOVD R8, 40(R20)
	MOVD R9, 48(R20)
	NGCW R0, R10
	MOVD R10, 56(R20)
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"negatesemantics": {
				Name: "negatesemantics", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void negatesemantics(uint64_t *);
int main(void) {
  uint64_t got[8] = {0};
  const uint64_t want[8] = {
    UINT64_MAX-4, 0, 1, UINT64_MAX-5,
    UINT64_MAX-4, 0x80000000ULL, 1, 0xfffffffaULL
  };
  negatesemantics(got);
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return i+1;
  return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_negate", triple, ll, mainC, runPrefix)
}
