package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawIntegerPairCompleteMemoryForms(t *testing.T) {
	forms := []struct {
		name string
		word uint32
	}{
		{"LDP offset", 0xa97f0941},
		{"LDP pre-index", 0xa9ff0941},
		{"LDP post-index", 0xa8c10941},
		{"LDPSW offset", 0x697f0941},
		{"LDPSW pre-index", 0x69ff0941},
		{"LDPSW post-index", 0x68c10941},
		{"STPW offset", 0x293f0941},
		{"STPW pre-index", 0x29bf0941},
		{"STPW post-index", 0x28810941},
	}
	var source strings.Builder
	source.WriteString("TEXT rawintegerpairforms(SB),$0-0\n")
	for _, form := range forms {
		fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", form.word, form.name)
		decoded, err := decodeARM64RawWordInstruction(Instr{
			Op:   OpWORD,
			Raw:  fmt.Sprintf("WORD $%#08x", form.word),
			Args: []Operand{{Kind: OpImm, Imm: int64(form.word)}},
		})
		if err != nil {
			t.Fatalf("%s: %v", form.name, err)
		}
		if len(decoded.Args) != 2 {
			t.Fatalf("%s decoded %d operands, want two with a register pair: %q", form.name, len(decoded.Args), decoded.Raw)
		}
		pair := decoded.Args[1]
		if strings.HasPrefix(form.name, "STP") {
			pair = decoded.Args[0]
		}
		if pair.Kind != OpRegList || len(pair.RegList) != 2 {
			t.Fatalf("%s decoded without register pair: %q", form.name, decoded.Raw)
		}
		if pair.RegList[0] != "R1" || pair.RegList[1] != "R2" {
			t.Fatalf("%s decoded pair in wrong memory order: %v", form.name, pair.RegList)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawintegerpairforms": {Name: "rawintegerpairforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-integer-pair.ll", "arm64-raw-integer-pair.o", ir)
		})
	}
}

func TestARM64RawLDPSWRuntimeSignAndPairOrder(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("native ARM64 runtime required")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawldpswruntime(SB),$0-16
	MOVD input+0(FP), R10
	MOVD output+8(FP), R11
	WORD $0x697f0941 // LDPSW R1, R2, -8(R10)
	MOVD R1, (R11)
	MOVD R2, 8(R11)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawldpswruntime": {
			Name: "rawldpswruntime", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawldpswruntime(const int32_t *, int64_t *);
int main(void) {
  const int32_t input[4] = {-7, 9, 11, 13};
  int64_t output[2] = {0};
  rawldpswruntime(input + 2, output);
  return output[0] == -7 && output[1] == 9 ? 0 : 1;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_ldpsw", triple, ir, mainC, nil)
}
