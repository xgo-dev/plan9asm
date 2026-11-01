package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64FPPairFamilyRuntime(t *testing.T, triple string) (string, string, string, string) {
	t.Helper()
	return arm64FPPairFamilyRuntimeWithObservation(t, triple, false)
}

func arm64FPPairFamilyRuntimeWithObservation(t *testing.T, triple string, originalWideObservation bool) (string, string, string, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"LDP", "LDPW", "LDPSW", "STP", "STPW"} {
		for _, shape := range []struct {
			name   string
			typeOf LLVMType
			count  int
			offset int64
		}{
			{name: "scalar64", typeOf: I64, count: 3},
			{name: "partial64", typeOf: I64, count: 3, offset: 4},
			{name: "scalar32", typeOf: I32, count: 4},
			{name: "scalar16", typeOf: I16, count: 12},
			{name: "scalar8", typeOf: I8, count: 24},
		} {
			name := strings.ToLower(op) + "_" + shape.name
			sig := FuncSig{Name: name, Ret: Void}
			var arguments, frameInit, observedChecks strings.Builder
			slotBytes := frameTypeSize(shape.typeOf, 8)
			for i := 0; i < shape.count; i++ {
				sig.Args = append(sig.Args, shape.typeOf)
				sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(i) * slotBytes, Type: shape.typeOf, Index: i, Field: -1})
				if i != 0 {
					arguments.WriteString(", ")
				}
				fmt.Fprintf(&arguments, "uint%d_t a%d", slotBytes*8, i)
				fmt.Fprintf(&frameInit, "    uint%d_t a%d = samples[(iteration + %d) %% 8];\n", slotBytes*8, i, i)
				fmt.Fprintf(&frameInit, "    memcpy(frame + %d, &a%d, %d);\n", int64(i)*slotBytes, i, slotBytes)
			}
			load := strings.HasPrefix(op, "LDP")
			frameBytes := int64(shape.count) * slotBytes
			outOffset := frameBytes
			width := 4
			if op == "LDP" || op == "STP" {
				width = 8
			}
			fmt.Fprintf(&source, "TEXT %s(SB),$0-64\n", name)
			if !load {
				for i := 0; i < 2; i++ {
					index := len(sig.Args)
					sig.Args = append(sig.Args, I64)
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: frameBytes + int64(i)*8, Type: I64, Index: index, Field: -1})
				}
				fmt.Fprintf(&source, "MOVD left+%d(FP), R3\nMOVD right+%d(FP), R4\n", frameBytes, frameBytes+8)
				arguments.WriteString(", uint64_t left, uint64_t right")
				outOffset += 16
			}
			sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: outOffset, Type: Ptr, Index: len(sig.Args), Field: -1})
			sig.Args = append(sig.Args, Ptr)
			arguments.WriteString(", uint64_t *out")
			fmt.Fprintf(&source, "MOVD out+%d(FP), R10\n", outOffset)
			if load {
				fmt.Fprintf(&source, "%s frame+%d(FP), (R3, R4)\nMOVD R3, 0(R10)\nMOVD R4, 8(R10)\n", op, shape.offset)
				for i := 0; i < 2; i++ {
					fmt.Fprintf(&observedChecks, "    uint64_t want%d = 0;\n    memcpy(&want%d, frame + %d, %d);\n", i, i, shape.offset+int64(i*width), width)
					if op == "LDPSW" {
						fmt.Fprintf(&observedChecks, "    want%d = (uint64_t)(int64_t)(int32_t)want%d;\n", i, i)
					}
					fmt.Fprintf(&observedChecks, "    if (out[%d] != want%d) return %d;\n", i, i, i+1)
				}
			} else {
				fmt.Fprintf(&source, "%s (R3, R4), frame+%d(FP)\n", op, shape.offset)
				var move string
				switch slotBytes {
				case 1:
					move = "MOVBU"
				case 2:
					move = "MOVHU"
				case 4:
					move = "MOVWU"
				case 8:
					move = "MOVD"
				default:
					t.Fatalf("unregistered FP scalar observation width %d", slotBytes)
				}
				// Retain the original source for the real-Go stale-reference
				// regression; it is not the canonical numerical fixture.
				if originalWideObservation && slotBytes < 4 {
					move = "MOVD"
				}
				for i := 0; i < shape.count; i++ {
					fmt.Fprintf(&source, "%s frame+%d(FP), R5\nMOVD R5, %d(R10)\n", move, int64(i)*slotBytes, i*8)
					fmt.Fprintf(&observedChecks, "    uint64_t want%d = 0;\n    memcpy(&want%d, frame + %d, %d);\n", i, i, int64(i)*slotBytes, slotBytes)
					fmt.Fprintf(&observedChecks, "    if (out[%d] != want%d) return %d;\n", i, i, i+1)
				}
			}
			source.WriteString("RET\n")
			sigs[name] = sig
			fmt.Fprintf(&declarations, "extern void %s(%s);\n", name, arguments.String())
			outCount := shape.count
			if outCount < 2 {
				outCount = 2
			}
			fmt.Fprintf(&declarations, "static int check_%s(void) {\n  for (unsigned iteration = 0; iteration < 8; iteration++) {\n    unsigned char frame[%d];\n    uint64_t out[%d] = {UINT64_MAX, UINT64_MAX};\n", name, frameBytes, outCount)
			declarations.WriteString(frameInit.String())
			if !load {
				declarations.WriteString("    uint64_t left = samples[(iteration + 5) % 8], right = samples[(iteration + 7) % 8];\n")
				fmt.Fprintf(&declarations, "    memcpy(frame + %d, &left, %d);\n    memcpy(frame + %d, &right, %d);\n", shape.offset, width, shape.offset+int64(width), width)
			}
			fmt.Fprintf(&declarations, "    %s(", name)
			for i := 0; i < shape.count; i++ {
				fmt.Fprintf(&declarations, "a%d, ", i)
			}
			if !load {
				declarations.WriteString("left, right, ")
			}
			declarations.WriteString("out);\n" + observedChecks.String() + "  }\n  return 0;\n}\n")
			fmt.Fprintf(&checks, "  if (check_%s()) { fprintf(stderr, \"%s failed\\n\"); return %d; }\n", name, name, len(sigs))
		}
	}

	const resultsSource = `TEXT result64(SB),$0-32
	MOVD left+0(FP), R3
	MOVD right+8(FP), R4
	STP (R3, R4), ret+16(FP)
	RET
TEXT result32(SB),$0-24
	MOVD left+0(FP), R3
	MOVD right+8(FP), R4
	STPW (R3, R4), ret+16(FP)
	RET
TEXT resultPartial(SB),$0-48
	MOVD original0+0(FP), R7
	MOVD original1+8(FP), R8
	MOVD R7, ret0+32(FP)
	MOVD R8, ret1+40(FP)
	MOVD left+16(FP), R3
	MOVD right+24(FP), R4
	STPW (R3, R4), ret+36(FP)
	RET
TEXT mixedResult(SB),$0-32
	MOVD value+0(FP), R7
	MOVD R7, ret+24(FP)
	MOVD out+16(FP), R10
	LDP out+16(FP), (R3, R4)
	MOVD R3, 0(R10)
	MOVD R4, 8(R10)
	RET
`
	source.WriteString(resultsSource)
	for _, name := range []string{"result64", "result32", "resultPartial", "mixedResult"} {
		sig := FuncSig{Name: name, Args: []LLVMType{I64, I64}, Ret: LLVMType("{ i64, i64 }")}
		if name == "result32" {
			sig.Ret = I64
		} else if name == "resultPartial" {
			sig.Args = []LLVMType{I64, I64, I64, I64}
		} else if name == "mixedResult" {
			sig.Args = []LLVMType{I64, I64, Ptr}
			sig.Ret = I64
		}
		for i, ty := range sig.Args {
			sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(i * 8), Type: ty, Index: i, Field: -1})
		}
		count := 2
		if sig.Ret == I64 {
			count = 1
		}
		for i := 0; i < count; i++ {
			sig.Frame.Results = append(sig.Frame.Results, FrameSlot{Offset: int64((len(sig.Args) + i) * 8), Type: I64, Index: i, Field: -1})
		}
		sigs[name] = sig
	}
	const resultsOracle = `
typedef struct { uint64_t first, second; } pair64;
extern pair64 result64(uint64_t, uint64_t);
extern uint64_t result32(uint64_t, uint64_t);
extern pair64 resultPartial(uint64_t, uint64_t, uint64_t, uint64_t);
extern uint64_t mixedResult(uint64_t, uint64_t, uint64_t *);
static int check_results(void) {
	for (unsigned i = 0; i < 8; i++) {
		uint64_t a = samples[i], b = samples[(i + 3) % 8];
		pair64 p = result64(a, b);
		if (p.first != a || p.second != b) return 1;
		if (result32(a, b) != ((uint64_t)(uint32_t)a | ((uint64_t)(uint32_t)b << 32))) return 2;
		p = resultPartial(UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210), a, b);
		if (p.first != (UINT64_C(0x89abcdef) | ((uint64_t)(uint32_t)a << 32))) return 3;
		if (p.second != (UINT64_C(0xfedcba9800000000) | (uint32_t)b)) return 4;
		uint64_t out[2] = {0, 0};
		if (mixedResult(a, b, out) != a || out[0] != (uintptr_t)out || out[1] != a) return 5;
	}
	return 0;
}
`
	const vectorSource = `TEXT fmovqLoad(SB),$0-32
	MOVD out+24(FP), R10
	FMOVQ value+4(FP), F0
	FMOVQ F0, (R10)
	RET
TEXT fmovqStore(SB),$0-40
	MOVD in+24(FP), R9
	MOVD out+32(FP), R10
	FMOVQ (R9), F0
	FMOVQ F0, value+4(FP)
	MOVD value+0(FP), R3
	MOVD R3, 0(R10)
	MOVD value+8(FP), R3
	MOVD R3, 8(R10)
	MOVD value+16(FP), R3
	MOVD R3, 16(R10)
	RET
TEXT fmovqFloats(SB),$0-24
	MOVD out+16(FP), R10
	FMOVQ value+0(FP), F0
	FMOVQ F0, (R10)
	RET
`
	source.WriteString(vectorSource)
	for _, name := range []string{"fmovqLoad", "fmovqStore", "fmovqFloats"} {
		sig := FuncSig{Name: name, Args: []LLVMType{I64, I64, I64, Ptr}, Ret: Void}
		if name == "fmovqStore" {
			sig.Args = append(sig.Args, Ptr)
		} else if name == "fmovqFloats" {
			sig.Args = []LLVMType{"float", "float", "float", "float", Ptr}
		}
		offset := int64(0)
		for i, ty := range sig.Args {
			sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: offset, Type: ty, Index: i, Field: -1})
			offset += frameTypeSize(ty, 8)
		}
		sigs[name] = sig
	}
	const vectorOracle = `
extern void fmovqLoad(uint64_t, uint64_t, uint64_t, unsigned char *);
extern void fmovqStore(uint64_t, uint64_t, uint64_t, const unsigned char *, uint64_t *);
extern void fmovqFloats(float, float, float, float, uint32_t *);
static int check_vectors(void) {
	for (unsigned i = 0; i < 8; i++) {
		uint64_t original[3] = {samples[i], samples[(i + 2) % 8], samples[(i + 5) % 8]};
		unsigned char packed[16];
		fmovqLoad(original[0], original[1], original[2], packed);
		if (memcmp(packed, (unsigned char *)original + 4, 16)) return 1;
		for (unsigned j = 0; j < 16; j++) packed[j] = (unsigned char)(i * 29 + j * 17);
		uint64_t out[3] = {0, 0, 0}, expected[3];
		memcpy(expected, original, sizeof expected);
		memcpy((unsigned char *)expected + 4, packed, sizeof packed);
		fmovqStore(original[0], original[1], original[2], packed, out);
		if (memcmp(out, expected, sizeof expected)) return 2;
	}
	const uint32_t bits[4] = {UINT32_C(0x3f800000), UINT32_C(0x80000000), UINT32_C(0x40490fdb), UINT32_C(0xc1200000)};
	float values[4];
	uint32_t out[4] = {0, 0, 0, 0};
	memcpy(values, bits, sizeof values);
	fmovqFloats(values[0], values[1], values[2], values[3], out);
	if (memcmp(out, bits, sizeof bits)) return 3;
	return 0;
}
`
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
static const uint64_t samples[8] = {0, 1, UINT64_MAX, UINT64_C(0x8000000000000000),
	UINT64_C(0x7fffffff80000000), UINT64_C(0x800000007fffffff),
	UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)};
` + declarations.String() + resultsOracle + vectorOracle + "int main(void) {\n" + checks.String() + "  if (check_results()) return 90;\n  return check_vectors();\n}\n"
	var goDeclarations strings.Builder
	goTypes := map[LLVMType]string{
		I8: "uint8", I16: "uint16", I32: "uint32", I64: "uint64",
		Ptr: "*byte", LLVMType("float"): "float32",
	}
	for _, function := range file.Funcs {
		sig, found := sigs[function.Sym]
		if !found {
			t.Fatalf("missing first-party fixture signature for %q", function.Sym)
		}
		fmt.Fprintf(&goDeclarations, "func %s(", function.Sym)
		for i, arg := range sig.Args {
			goType, found := goTypes[arg]
			if !found {
				t.Fatalf("unregistered first-party fixture Go input type %q", arg)
			}
			if i != 0 {
				goDeclarations.WriteString(", ")
			}
			fmt.Fprintf(&goDeclarations, "a%d %s", i, goType)
		}
		goDeclarations.WriteString(")")
		switch sig.Ret {
		case Void:
		case I64:
			goDeclarations.WriteString(" uint64")
		case LLVMType("{ i64, i64 }"):
			goDeclarations.WriteString(" (uint64, uint64)")
		default:
			t.Fatalf("unregistered first-party fixture Go result type %q", sig.Ret)
		}
		goDeclarations.WriteByte('\n')
	}
	return ir, main, source.String(), goDeclarations.String()
}

func TestCrossLinuxRuntimeMatrixARM64FPPairFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	ir, main, source, declarations := arm64FPPairFamilyRuntime(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "fp_pair_family", triple, ir, main, runner)
	for api, apiIR := range arm64ScalarMemoryIRs(t, source, declarations, triple) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("fp_pair_api_%d", api), triple, apiIR, main, runner)
	}
	t.Log("unchanged 25 pair/width/partial shapes, four result and three vector cases; initialized C reference through manual transport and all three typed APIs")
}

func TestARM64FPPairFamilyLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		t.Run(triple, func(t *testing.T) {
			ir, _, source, declarations := arm64FPPairFamilyRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "fp-pair-family.ll", "fp-pair-family.o", ir)
			for api, apiIR := range arm64ScalarMemoryIRs(t, source, declarations, triple) {
				compileLLVMToObject(t, llc, triple, fmt.Sprintf("fp-pair-api-%d.ll", api), fmt.Sprintf("fp-pair-api-%d.o", api), apiIR)
			}
		})
	}
}
