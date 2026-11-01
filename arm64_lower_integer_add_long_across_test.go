package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64AddLongAcrossCompleteTypedFamily(t *testing.T) {
	arrangements := []struct {
		name string
		size uint32
		wide bool
	}{
		{"B8", 0, false},
		{"B16", 0, true},
		{"H4", 1, false},
		{"H8", 1, true},
		{"S4", 2, true},
	}
	var source strings.Builder
	source.WriteString("TEXT addLongAcrossForms(SB),$0-0\n")
	for _, family := range []struct {
		op   Op
		base uint32
	}{
		{op: "VSADDLV", base: 0x0e303800},
		{op: "VUADDLV", base: 0x2e303800},
	} {
		for _, arrangement := range arrangements {
			word := family.base | arrangement.size<<22 | 18<<5 | 1
			if arrangement.wide {
				word |= 1 << 30
			}
			decoded, err := decodeARM64RawWordInstruction(Instr{
				Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}},
			})
			if err != nil || decoded.Op != family.op || len(decoded.Args) != 2 ||
				decoded.Args[0].Reg != Reg("V18."+arrangement.name) || decoded.Args[1].Reg != "V1" {
				t.Fatalf("decode %#08x: %+v, %v", word, decoded, err)
			}
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       "arm64",
				TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"addLongAcrossForms": {Name: "addLongAcrossForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"@llvm.aarch64.neon.saddlv", "@llvm.aarch64.neon.uaddlv"} {
				if !strings.Contains(ir, name) {
					t.Fatalf("missing %s in generated IR:\n%s", name, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-add-long-across.ll", "arm64-add-long-across.o", ir)
		})
	}
}

func TestTranslateARM64NamedUADDLVAllGoForms(t *testing.T) {
	const source = `TEXT namedUADDLV(SB),$0-0
	VUADDLV V2.B8, V1
	VUADDLV V2.B16, V1
	VUADDLV V2.H4, V1
	VUADDLV V2.H8, V1
	VUADDLV V2.S4, V1
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"namedUADDLV": {Name: "namedUADDLV", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"i32.v8i8", "i32.v16i8", "i32.v4i16", "i32.v8i16", "i64.v4i32"} {
		if !strings.Contains(ir, "@llvm.aarch64.neon.uaddlv."+suffix) {
			t.Fatalf("missing typed VUADDLV form %s:\n%s", suffix, ir)
		}
	}
}

func TestARM64RawAddLongAcrossGoAV1RuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT rawSignedAddLongAcross(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V18.S4]
	WORD $0x4eb03a41 // SADDLV D1, V18.4S
	VMOV V1.D[0], R2
	MOVD R2, (R1)
	RET
TEXT rawUnsignedAddLongAcross(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V18.S4]
	WORD $0x6eb03a41 // UADDLV D1, V18.4S
	VMOV V1.D[0], R2
	MOVD R2, (R1)
	RET
TEXT signedByteAddLongAcross(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V18.B8]
	WORD $0x0e303a41 // SADDLV H1, V18.8B
	VMOV V1.D[0], R2
	MOVD R2, (R1)
	RET
TEXT unsignedByteAddLongAcross(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V18.B16]
	VUADDLV V18.B16, V1
	VMOV V1.D[0], R2
	MOVD R2, (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{}
	for _, name := range []string{
		"rawSignedAddLongAcross", "rawUnsignedAddLongAcross",
		"signedByteAddLongAcross", "unsignedByteAddLongAcross",
	} {
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawSignedAddLongAcross(const int32_t *, int64_t *);
extern void rawUnsignedAddLongAcross(const uint32_t *, uint64_t *);
extern void signedByteAddLongAcross(const int8_t *, uint64_t *);
extern void unsignedByteAddLongAcross(const uint8_t *, uint64_t *);
int main(void) {
  const int32_t signedInput[4] = {2147483647, 2147483647, 2, -2};
  const uint32_t unsignedInput[4] = {4294967295u, 4294967295u, 2, 1};
  const int8_t signedBytes[8] = {100, 100, 100, 100, 100, 100, 100, 100};
  const uint8_t unsignedBytes[16] = {200, 200, 200, 200, 200, 200, 200, 200,
                                      200, 200, 200, 200, 200, 200, 200, 200};
  int64_t signedResult = 0;
  uint64_t unsignedResult = 0;
  uint64_t signedByteResult = 0;
  uint64_t unsignedByteResult = 0;
  rawSignedAddLongAcross(signedInput, &signedResult);
  rawUnsignedAddLongAcross(unsignedInput, &unsignedResult);
  signedByteAddLongAcross(signedBytes, &signedByteResult);
  unsignedByteAddLongAcross(unsignedBytes, &unsignedByteResult);
  if (signedResult != 4294967294LL) return 1;
  if (unsignedResult != 8589934593ULL) return 2;
  if (signedByteResult != 800) return 3;
  if (unsignedByteResult != 3200) return 4;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_add_long_across", triple, ir, mainC, nil)
}
