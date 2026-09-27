package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64ConformanceNativeGo(t *testing.T) {
	if runtime.GOARCH != "amd64" && !(runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()) {
		t.Skip("native Go assembler oracle requires an amd64 host")
	}
	cmd := exec.Command("go", "test", "-count=1", "./testdata/conformance/amd64")
	if runtime.GOARCH != "amd64" {
		cmd.Env = append(os.Environ(), "GOARCH=amd64", "PLAN9ASM_ROSETTA=1")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go conformance failed: %v\n%s", err, out)
	}
}

func TestAMD64ConformanceLLVMRuntime(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("llc/clang not found")
	}

	src, err := os.ReadFile(filepath.Join("testdata", "conformance", "amd64", "conformance_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	ptrParams := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		ResolveSym:   resolve,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"byteMemory": {
				Name: "byteMemory",
				Args: []LLVMType{Ptr, I8},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I8, Index: 1, Field: -1},
				}},
			},
			"unpackLowQWords": {
				Name:  "unpackLowQWords",
				Args:  []LLVMType{Ptr, Ptr},
				Ret:   Void,
				Frame: ptrParams,
			},
			"byteFlags": {
				Name:  "byteFlags",
				Args:  []LLVMType{Ptr, Ptr},
				Ret:   Void,
				Frame: ptrParams,
			},
			"unpackDuplicateLowQWord": {
				Name: "unpackDuplicateLowQWord",
				Args: []LLVMType{Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				}},
			},
			"shiftLegacyThreeOperand": {
				Name: "shiftLegacyThreeOperand",
				Args: []LLVMType{I32, I32, I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: -1},
						{Offset: 4, Type: I32, Index: 1, Field: -1},
						{Offset: 8, Type: I32, Index: 2, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: I32, Index: 0, Field: -1},
					},
				},
			},
			"clearTopBit": {
				Name: "clearTopBit",
				Args: []LLVMType{I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
			"doubleShift32": {
				Name: "doubleShift32",
				Args: []LLVMType{Ptr, I32, I32, I32},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I32, Index: 1, Field: -1},
					{Offset: 12, Type: I32, Index: 2, Field: -1},
					{Offset: 16, Type: I32, Index: 3, Field: -1},
				}},
			},
			"doubleShift64": {
				Name: "doubleShift64",
				Args: []LLVMType{Ptr, I64, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
					{Offset: 24, Type: I64, Index: 3, Field: -1},
				}},
			},
			"scalarShiftRotateSemantics": {
				Name: "scalarShiftRotateSemantics",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
			"incDecSemantics": {
				Name: "incDecSemantics",
				Args: []LLVMType{Ptr, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				}},
			},
			"scalarAddSubSemantics": {
				Name: "scalarAddSubSemantics",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
			"compareExchangeScalarSemantics": {
				Name: "compareExchangeScalarSemantics",
				Args: []LLVMType{Ptr, Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
					{Offset: 24, Type: I64, Index: 3, Field: -1},
				}},
			},
			"compareExchangePairSemantics": {
				Name: "compareExchangePairSemantics",
				Args: []LLVMType{Ptr, Ptr, I64, I64, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
					{Offset: 24, Type: I64, Index: 3, Field: -1},
					{Offset: 32, Type: I64, Index: 4, Field: -1},
					{Offset: 40, Type: I64, Index: 5, Field: -1},
				}},
			},
			"parallelBitSemantics": {
				Name: "parallelBitSemantics",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
			"bitTestRegisterSemantics": {
				Name: "bitTestRegisterSemantics",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
			"bitTestMemorySemantics": {
				Name: "bitTestMemorySemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"packedWordMultiplyAddSemantics": {
				Name: "packedWordMultiplyAddSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedUnsignedSignedByteMultiplyAddSemantics": {
				Name: "packedUnsignedSignedByteMultiplyAddSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedDotProductSemantics": {
				Name: "packedDotProductSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
					{Offset: 32, Type: Ptr, Index: 4, Field: -1},
					{Offset: 40, Type: Ptr, Index: 5, Field: -1},
				}},
			},
			"packedIntegerMinMaxSemantics": {
				Name: "packedIntegerMinMaxSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedWordMultiplySemantics": {
				Name: "packedWordMultiplySemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedFloatShuffleSemantics": {
				Name: "packedFloatShuffleSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"inLaneFloatingPermuteSemantics": {
				Name: "inLaneFloatingPermuteSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"immediatePackedBlendSemantics": {
				Name: "immediatePackedBlendSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedUnpackSemantics": {
				Name: "packedUnpackSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"qwordPermuteSemantics": {
				Name: "qwordPermuteSemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"qwordVariablePermuteSemantics": {
				Name: "qwordVariablePermuteSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedFloatMoveVEXSemantics": {
				Name: "packedFloatMoveVEXSemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"packedFloatMoveMaskSemantics": {
				Name: "packedFloatMoveMaskSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"packedSignExtendMoveVEXSemantics": {
				Name: "packedSignExtendMoveVEXSemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"packedSignExtendMoveMaskSemantics": {
				Name: "packedSignExtendMoveMaskSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"goHexVectorOps": {
				Name: "goHexVectorOps",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"goHexWordOps": {
				Name: "goHexWordOps",
				Args: []LLVMType{I64, I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
					},
					Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
				},
			},
			"packedArithmeticShift32": {
				Name:  "packedArithmeticShift32",
				Args:  []LLVMType{Ptr, Ptr},
				Ret:   Void,
				Frame: ptrParams,
			},
			"packedSubtractSemantics": {
				Name: "packedSubtractSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"expandedEcosystemVectors": {
				Name: "expandedEcosystemVectors",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"parityBranches": {
				Name: "parityBranches",
				Args: []LLVMType{I8},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I8, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
			"unorderedBranch": {
				Name: "unorderedBranch",
				Args: []LLVMType{LLVMType("double")},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
			"packedFloatToDwordModes": {
				Name: "packedFloatToDwordModes",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"sameWidthPackedConversionSemantics": {
				Name: "sameWidthPackedConversionSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
					{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				}},
			},
			"packedSingleToDouble": {
				Name: "packedSingleToDouble",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"conditionalMoveCodes": {
				Name: "conditionalMoveCodes",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"fma3Semantics": {
				Name: "fma3Semantics",
				Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
					{Offset: 32, Type: Ptr, Index: 4, Field: -1},
					{Offset: 40, Type: Ptr, Index: 5, Field: -1},
					{Offset: 48, Type: Ptr, Index: 6, Field: -1},
				}},
			},
			"binaryFloatingSemantics": {
				Name: "binaryFloatingSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
					{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				}},
			},
			"horizontalFloatingSemantics": {
				Name: "horizontalFloatingSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
					{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void byteMemory(uint8_t *p, uint8_t value);
extern void byteFlags(uint8_t *p, uint8_t *flags);
extern void unpackLowQWords(uint64_t *dst, uint64_t *src);
extern void unpackDuplicateLowQWord(uint64_t *dst);
extern uint32_t shiftLegacyThreeOperand(uint32_t src, uint32_t dst, uint32_t amount);
extern uint64_t clearTopBit(uint64_t value);
extern void doubleShift32(uint32_t *out, uint32_t src, uint32_t dst, uint32_t amount);
extern void doubleShift64(uint64_t *out, uint64_t src, uint64_t dst, uint64_t amount);
extern void scalarShiftRotateSemantics(uint64_t *out, uint64_t value, uint64_t count);
extern void incDecSemantics(uint64_t *out, uint64_t value);
extern void scalarAddSubSemantics(uint64_t *out, uint64_t value, uint64_t source);
extern void compareExchangeScalarSemantics(uint64_t *out, uint64_t *memory, uint64_t expected, uint64_t desired);
extern void compareExchangePairSemantics(uint64_t *out, uint64_t *memory, uint64_t expected_low, uint64_t expected_high, uint64_t desired_low, uint64_t desired_high);
extern void parallelBitSemantics(uint64_t *out, uint64_t mask, uint64_t source);
extern void bitTestRegisterSemantics(uint64_t *out, uint64_t value, uint64_t index);
extern void bitTestMemorySemantics(uint8_t *out, uint64_t *data);
extern void packedWordMultiplyAddSemantics(int32_t *out, int16_t *a, int16_t *b);
extern void packedUnsignedSignedByteMultiplyAddSemantics(int16_t *out, int8_t *signed_input, uint8_t *unsigned_input);
extern void packedDotProductSemantics(int32_t *out, int8_t *signed_bytes, uint8_t *unsigned_bytes, int16_t *words_a, int16_t *words_b, int32_t *accumulator);
extern void packedIntegerMinMaxSemantics(uint8_t *out, uint8_t *a, uint8_t *b);
extern void packedWordMultiplySemantics(uint16_t *out, int16_t *a, int16_t *b);
extern void packedFloatShuffleSemantics(uint8_t *out, uint8_t *a, uint8_t *b);
extern void inLaneFloatingPermuteSemantics(uint8_t *out, uint8_t *data, uint8_t *control);
extern void immediatePackedBlendSemantics(uint8_t *out, uint8_t *a, uint8_t *b);
extern void packedUnpackSemantics(uint8_t *out, uint8_t *a, uint8_t *b);
extern void qwordPermuteSemantics(uint64_t *out, uint64_t *data);
extern void qwordVariablePermuteSemantics(uint64_t *out, uint64_t *data, uint64_t *control);
extern void packedFloatMoveVEXSemantics(uint8_t *out, uint8_t *src);
extern void packedFloatMoveMaskSemantics(uint8_t *out, uint8_t *src, uint8_t *old);
extern void packedSignExtendMoveVEXSemantics(uint8_t *out, uint8_t *src);
extern void packedSignExtendMoveMaskSemantics(uint8_t *out, uint8_t *src, uint8_t *old);
extern void goHexVectorOps(uint8_t *out, uint8_t *a, uint8_t *b);
extern uint64_t goHexWordOps(uint64_t value, uint64_t count);
extern void packedArithmeticShift32(int32_t *out, int32_t *src);
extern void packedSubtractSemantics(uint8_t *out, uint8_t *a, uint8_t *b);
extern void expandedEcosystemVectors(uint8_t *out, uint8_t *a, uint8_t *b);
extern uint64_t parityBranches(uint8_t value);
extern uint64_t unorderedBranch(double value);
extern void packedFloatToDwordModes(int32_t *out, float *src);
extern void sameWidthPackedConversionSemantics(uint8_t *out, int32_t *ints, float *floats, float *squares32, double *squares64);
extern void packedSingleToDouble(double *out, float *src);
extern void conditionalMoveCodes(uint64_t *out, uint64_t *src);
extern void fma3Semantics(uint8_t *out, double *a64, double *b64, double *c64, float *a32, float *b32, float *c32);
extern void binaryFloatingSemantics(uint8_t *out, double *a64, double *b64, float *a32, float *b32);
extern void horizontalFloatingSemantics(uint8_t *out, float *a32, float *b32, double *a64, double *b64);

static uint16_t load16(const uint8_t *p) {
	return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}
static uint32_t load32(const uint8_t *p) {
	return (uint32_t)load16(p) | (uint32_t)load16(p + 2) << 16;
}
static uint64_t load64(const uint8_t *p) {
	return (uint64_t)load32(p) | (uint64_t)load32(p + 4) << 32;
}
static float loadf32(const uint8_t *p) {
	union { uint32_t bits; float value; } converted = {load32(p)};
	return converted.value;
}
static double loadf64(const uint8_t *p) {
	union { uint64_t bits; double value; } converted = {load64(p)};
	return converted.value;
}

static uint32_t shld32(uint32_t src, uint32_t dst, uint32_t count) {
	count &= 31;
	return count == 0 ? dst : (dst << count) | (src >> (32 - count));
}
static uint32_t shrd32(uint32_t src, uint32_t dst, uint32_t count) {
	count &= 31;
	return count == 0 ? dst : (dst >> count) | (src << (32 - count));
}
static uint64_t shld64(uint64_t src, uint64_t dst, uint64_t count) {
	count &= 63;
	return count == 0 ? dst : (dst << count) | (src >> (64 - count));
}
static uint64_t shrd64(uint64_t src, uint64_t dst, uint64_t count) {
	count &= 63;
	return count == 0 ? dst : (dst >> count) | (src << (64 - count));
}
static uint64_t rol(uint64_t value, unsigned bits, uint64_t count) {
	uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
	count %= bits;
	value &= mask;
	return count == 0 ? value : ((value << count) | (value >> (bits - count))) & mask;
}
static uint64_t ror(uint64_t value, unsigned bits, uint64_t count) {
	return rol(value, bits, bits - count % bits);
}
static uint64_t replace_low(uint64_t value, uint64_t low, unsigned bits) {
	uint64_t mask = (UINT64_C(1) << bits) - 1;
	return (value & ~mask) | (low & mask);
}

static uint64_t reference_scalar_add_sub(int add, unsigned bits, uint64_t value, uint64_t source,
	int register_destination, uint64_t *flags) {
	uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
	uint64_t destination_low = value & mask, source_low = source & mask;
	uint64_t result_low = add ? (destination_low + source_low) & mask : (destination_low - source_low) & mask;
	uint64_t carry = add ? result_low < destination_low : destination_low < source_low;
	uint64_t sign_bit = UINT64_C(1) << (bits - 1);
	uint64_t overflow = add
		? ((~(destination_low ^ source_low) & (destination_low ^ result_low) & sign_bit) != 0)
		: (((destination_low ^ source_low) & (destination_low ^ result_low) & sign_bit) != 0);
	uint8_t low_byte = (uint8_t)result_low;
	uint64_t parity = 1;
	while (low_byte != 0) {
		parity ^= 1;
		low_byte &= low_byte - 1;
	}
	*flags = carry | overflow << 8 | (result_low == 0) << 16 |
		((result_low & sign_bit) != 0) << 24 | parity << 32;
	if (bits == 64 || (register_destination && bits == 32)) return result_low;
	return (value & ~mask) | result_low;
}

static uint64_t reference_pdep(uint64_t mask, uint64_t source) {
	uint64_t result = 0;
	while (mask != 0) {
		uint64_t lowest = mask & (0 - mask);
		if (source & 1) result |= lowest;
		source >>= 1;
		mask &= mask - 1;
	}
	return result;
}

static uint64_t reference_pext(uint64_t mask, uint64_t source) {
	uint64_t result = 0, output_bit = 1;
	while (mask != 0) {
		uint64_t lowest = mask & (0 - mask);
		if (source & lowest) result |= output_bit;
		output_bit <<= 1;
		mask &= mask - 1;
	}
	return result;
}

static uint64_t reference_bit_test_register(int operation, unsigned bits, uint64_t value, uint64_t index, uint64_t *carry) {
	uint64_t bit = index & (bits - 1);
	*carry = (value >> bit) & 1;
	if (operation == 0) return value;
	uint64_t mask = UINT64_C(1) << bit;
	uint64_t low = value;
	if (operation == 1) low ^= mask;
	if (operation == 2) low &= ~mask;
	if (operation == 3) low |= mask;
	if (bits == 16) return (value & ~UINT64_C(0xffff)) | (low & UINT64_C(0xffff));
	if (bits == 32) return (uint32_t)low;
	return low;
}

int main(void) {
	uint8_t bytes[4] = {0x10, 0xf0, 0x5a, 0xa0};
	byteMemory(bytes, 0x0f);
	if (bytes[0] != 0x1f || bytes[1] != 0xff || bytes[2] != 0x0a || bytes[3] != 0xaf)
		return 11;
	uint8_t flag_values[4] = {0xff, 0xff, 0x7f, 0};
	uint8_t flags[8] = {0};
	byteFlags(flag_values, flags);
	uint8_t want_values[4] = {0, 0, 0, 0x80};
	uint8_t want_flags[8] = {1, 1, 0, 1, 0, 1, 0, 1};
	for (int i = 0; i < 4; i++)
		if (flag_values[i] != want_values[i])
			return 13 + i;
	for (int i = 0; i < 8; i++)
		if (flags[i] != want_flags[i])
			return 20 + i;
	uint64_t dst[2] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
	uint64_t src[2] = {0x1122334455667788ULL, 0x8877665544332211ULL};
	unpackLowQWords(dst, src);
	if (dst[0] != 0x0123456789abcdefULL || dst[1] != 0x1122334455667788ULL)
		return 12;
	uint64_t duplicate[2] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
	unpackDuplicateLowQWord(duplicate);
	if (duplicate[0] != 0x0123456789abcdefULL || duplicate[1] != 0x0123456789abcdefULL)
		return 30;
	if (shiftLegacyThreeOperand(0x12345678U, 0x89abcdefU, 5) != 0x3579bde2U)
		return 31;
	if (clearTopBit(UINT64_MAX) != 0x7fffffffffffffffULL ||
		clearTopBit(0x0123456789abcdefULL) != 0x0123456789abcdefULL)
		return 32;
	const uint32_t pairs32[][2] = {
		{0x12345678U, 0x89abcdefU}, {0, UINT32_MAX},
		{UINT32_MAX, 0}, {0x80000001U, 0x7ffffffeU},
	};
	for (unsigned p = 0; p < sizeof(pairs32) / sizeof(pairs32[0]); p++) {
		for (uint32_t count = 0; count < 128; count++) {
			uint32_t src = pairs32[p][0], dst_value = pairs32[p][1], out[8] = {0};
			doubleShift32(out, src, dst_value, count);
			uint32_t want[8] = {
				shld32(src, dst_value, count), shld32(src, dst_value, 7),
				shld32(src, dst_value, count), shld32(src, dst_value, 7),
				shrd32(src, dst_value, count), shrd32(src, dst_value, 7),
				shrd32(src, dst_value, count), shrd32(src, dst_value, 7),
			};
			for (int i = 0; i < 8; i++)
				if (out[i] != want[i])
					return 40 + i;
		}
	}
	const uint64_t pairs64[][2] = {
		{0x0123456789abcdefULL, 0xfedcba9876543210ULL}, {0, UINT64_MAX},
		{UINT64_MAX, 0}, {0x8000000000000001ULL, 0x7ffffffffffffffeULL},
	};
	for (unsigned p = 0; p < sizeof(pairs64) / sizeof(pairs64[0]); p++) {
		for (uint64_t count = 0; count < 256; count++) {
			uint64_t src = pairs64[p][0], dst_value = pairs64[p][1], out[8] = {0};
			doubleShift64(out, src, dst_value, count);
			uint64_t want[8] = {
				shld64(src, dst_value, count), shld64(src, dst_value, 7),
				shld64(src, dst_value, count), shld64(src, dst_value, 7),
				shrd64(src, dst_value, count), shrd64(src, dst_value, 7),
				shrd64(src, dst_value, count), shrd64(src, dst_value, 7),
			};
			for (int i = 0; i < 8; i++)
				if (out[i] != want[i])
					return 50 + i;
		}
	}
	const uint64_t scalar_value = UINT64_C(0x8123456789abcdef);
	const uint64_t word_dst = UINT64_C(0xfedcba9876543210);
	for (uint64_t count = 0; count < 16; count++) {
		uint64_t out[14] = {0}, want[14] = {0};
		scalarShiftRotateSemantics(out, scalar_value, count);
		uint64_t hardware_count = count & 31;
		uint64_t byte_logical = hardware_count < 8 ? (uint8_t)scalar_value >> hardware_count : 0;
		uint64_t byte_arithmetic = hardware_count < 8 ? (uint8_t)((int8_t)scalar_value >> hardware_count) : UINT8_MAX;
		uint64_t word_count = count & 15;
		uint16_t shldw = (uint16_t)word_dst, shrdw = (uint16_t)word_dst;
		if (word_count != 0) {
			shldw = (uint16_t)(((uint16_t)word_dst << word_count) | ((uint16_t)scalar_value >> (16 - word_count)));
			shrdw = (uint16_t)(((uint16_t)word_dst >> word_count) | ((uint16_t)scalar_value << (16 - word_count)));
		}
		want[0] = replace_low(scalar_value, rol(scalar_value, 8, count), 8);
		want[1] = replace_low(scalar_value, ror(scalar_value, 8, count), 8);
		want[2] = replace_low(scalar_value, byte_arithmetic, 8);
		want[3] = replace_low(scalar_value, byte_logical, 8);
		want[4] = replace_low(scalar_value, rol(scalar_value, 16, count), 16);
		want[5] = replace_low(scalar_value, (uint16_t)((int16_t)scalar_value >> hardware_count), 16);
		want[6] = (uint32_t)scalar_value << hardware_count;
		want[7] = ror(scalar_value, 64, count);
		want[8] = replace_low(scalar_value, byte_logical, 8);
		want[9] = replace_low(scalar_value, rol(scalar_value, 16, count), 16);
		want[10] = replace_low(word_dst, shldw, 16);
		want[11] = replace_low(word_dst, shrdw, 16);
		want[12] = replace_low(scalar_value, (uint8_t)scalar_value << 3, 8);
		want[13] = (uint32_t)((int32_t)scalar_value >> 3);
		for (int i = 0; i < 14; i++)
			if (out[i] != want[i]) return 196 + i;
	}
	const uint64_t inc_values[] = {0, 1, 0x7f, 0xff, 0xffff, 0xffffffff, UINT64_C(0x8123456789abcdef)};
	for (unsigned v = 0; v < sizeof(inc_values) / sizeof(inc_values[0]); v++) {
		uint64_t value = inc_values[v], out[12] = {0};
		incDecSemantics(out, value);
		uint64_t want[12] = {
			replace_low(value, (uint8_t)value + 1, 8),
			replace_low(value, (uint8_t)value - 1, 8),
			replace_low(value, (uint16_t)value + 1, 16),
			replace_low(value, (uint16_t)value - 1, 16),
			(uint32_t)value + 1, (uint32_t)value - 1, value + 1, value - 1,
			replace_low(value, (uint8_t)value + 1, 8),
			replace_low(value, (uint16_t)value - 1, 16),
			UINT64_C(0x0000000000010101), UINT64_C(0x0000000101000001),
		};
		for (int i = 0; i < 12; i++)
			if (out[i] != want[i]) return 220 + i;
	}
	const uint64_t scalar_add_sub_cases[][2] = {
		{0, 0}, {UINT64_MAX, 1}, {0x7f, 1}, {0x7fff, 1},
		{0x7fffffff, 1}, {UINT64_C(0x7fffffffffffffff), 1},
		{UINT64_C(0x8123456789abcdef), UINT64_C(0xfedcba9876543210)},
	};
	const unsigned scalar_add_sub_widths[] = {8, 16, 32, 64};
	for (unsigned v = 0; v < sizeof(scalar_add_sub_cases) / sizeof(scalar_add_sub_cases[0]); v++) {
		uint64_t value = scalar_add_sub_cases[v][0], source = scalar_add_sub_cases[v][1];
		uint64_t out[16] = {0}, want[16] = {0};
		scalarAddSubSemantics(out, value, source);
		for (unsigned width_index = 0; width_index < 4; width_index++) {
			unsigned bits = scalar_add_sub_widths[width_index];
			want[width_index * 4] = reference_scalar_add_sub(1, bits, value, source, 1, &want[width_index * 4 + 1]);
			want[width_index * 4 + 2] = reference_scalar_add_sub(0, bits, value, UINT64_MAX, 0, &want[width_index * 4 + 3]);
		}
		for (int i = 0; i < 16; i++)
			if (out[i] != want[i]) return 232 + i;
	}
	const uint64_t cmpxchg_expected_values[] = {
		0, UINT64_MAX, 0x7f, 0x7fff, 0x7fffffff,
		UINT64_C(0x7fffffffffffffff), UINT64_C(0x8123456789abcdef),
	};
	const uint64_t cmpxchg_desired = UINT64_C(0xfedcba9876543210);
	for (unsigned v = 0; v < sizeof(cmpxchg_expected_values) / sizeof(cmpxchg_expected_values[0]); v++) {
		uint64_t expected = cmpxchg_expected_values[v], memory[8] = {0}, initial[8] = {0};
		uint64_t out[24] = {0}, want[24] = {0};
		for (unsigned width_index = 0; width_index < 4; width_index++) {
			unsigned bits = scalar_add_sub_widths[width_index];
			uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
			uint64_t base = UINT64_C(0xa5a5a5a5a5a5a5a5) & ~mask;
			memory[width_index * 2] = base | (expected & mask);
			memory[width_index * 2 + 1] = base | ((expected ^ (UINT64_C(1) << (bits - 1))) & mask);
			initial[width_index * 2] = memory[width_index * 2];
			initial[width_index * 2 + 1] = memory[width_index * 2 + 1];
		}
		compareExchangeScalarSemantics(out, memory, expected, cmpxchg_desired);
		for (unsigned width_index = 0; width_index < 4; width_index++) {
			unsigned bits = scalar_add_sub_widths[width_index];
			uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
			uint64_t success_initial = initial[width_index * 2];
			uint64_t failure_initial = initial[width_index * 2 + 1];
			unsigned output_index = width_index * 6;
			want[output_index] = (success_initial & ~mask) | (cmpxchg_desired & mask);
			want[output_index + 1] = expected;
			reference_scalar_add_sub(0, bits, success_initial, expected, 1, &want[output_index + 2]);
			want[output_index + 3] = failure_initial;
			if (bits == 8 || bits == 16) want[output_index + 4] = (expected & ~mask) | (failure_initial & mask);
			if (bits == 32) want[output_index + 4] = (uint32_t)failure_initial;
			if (bits == 64) want[output_index + 4] = failure_initial;
			reference_scalar_add_sub(0, bits, expected, failure_initial, 1, &want[output_index + 5]);
		}
		for (int i = 0; i < 24; i++)
			if (out[i] != want[i]) return 248 + i;
	}
	const uint64_t cmpxchg_expected_low = UINT64_C(0xaaaaaaaa11223344);
	const uint64_t cmpxchg_expected_high = UINT64_C(0xbbbbbbbb55667788);
	const uint64_t cmpxchg_desired_low = UINT64_C(0x0123456789abcdef);
	const uint64_t cmpxchg_desired_high = UINT64_C(0xfedcba9876543210);
	for (int success = 0; success <= 1; success++) {
		_Alignas(16) uint64_t memory[4] = {0}, out[9] = {0}, want[9] = {0};
		if (success) {
			memory[0] = cmpxchg_expected_low;
			memory[1] = cmpxchg_expected_high;
			memory[2] = (cmpxchg_expected_low & UINT32_MAX) | (cmpxchg_expected_high & UINT32_MAX) << 32;
		} else {
			memory[0] = UINT64_C(0x1020304050607080);
			memory[1] = UINT64_C(0x90a0b0c0d0e0f001);
			memory[2] = UINT64_C(0x8877665544332211);
		}
		uint64_t old16_low = memory[0], old16_high = memory[1], old8 = memory[2];
		compareExchangePairSemantics(out, memory, cmpxchg_expected_low, cmpxchg_expected_high,
			cmpxchg_desired_low, cmpxchg_desired_high);
		if (success) {
			want[0] = (cmpxchg_desired_low & UINT32_MAX) | (cmpxchg_desired_high & UINT32_MAX) << 32;
			want[1] = cmpxchg_expected_low;
			want[2] = cmpxchg_expected_high;
			want[3] = 1;
			want[4] = cmpxchg_desired_low;
			want[5] = cmpxchg_desired_high;
			want[6] = cmpxchg_expected_low;
			want[7] = cmpxchg_expected_high;
			want[8] = 1;
		} else {
			want[0] = old8;
			want[1] = (uint32_t)old8;
			want[2] = (uint32_t)(old8 >> 32);
			want[4] = old16_low;
			want[5] = old16_high;
			want[6] = old16_low;
			want[7] = old16_high;
		}
		for (int i = 0; i < 9; i++)
			if (out[i] != want[i]) return 272 + i;
	}
	const uint64_t parallel_cases[][2] = {
		{0, UINT64_C(0x0123456789abcdef)},
		{UINT64_MAX, UINT64_C(0x0123456789abcdef)},
		{UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x0123456789abcdef)},
		{UINT64_C(0x8040201008040201), UINT64_C(0xfedcba9876543210)},
		{UINT64_C(0x8000000100000081), UINT64_MAX},
	};
	for (unsigned v = 0; v < sizeof(parallel_cases) / sizeof(parallel_cases[0]); v++) {
		uint64_t mask = parallel_cases[v][0], source = parallel_cases[v][1], out[8] = {0};
		parallelBitSemantics(out, mask, source);
		uint64_t mask32 = (uint32_t)mask, source32 = (uint32_t)source;
		uint64_t want[8] = {
			reference_pdep(mask, source), reference_pdep(mask, source),
			reference_pext(mask, source), reference_pext(mask, source),
			reference_pdep(mask32, source32), reference_pdep(mask32, source32),
			reference_pext(mask32, source32), reference_pext(mask32, source32),
		};
		for (int i = 0; i < 8; i++)
			if (out[i] != want[i]) return 124;
	}
	const uint64_t bit_test_value = UINT64_C(0xfedcba9876543210);
	const uint64_t bit_test_index = 21;
	uint64_t bit_test_out[24] = {0};
	bitTestRegisterSemantics(bit_test_out, bit_test_value, bit_test_index);
	const unsigned bit_test_widths[3] = {16, 32, 64};
	for (int width_index = 0; width_index < 3; width_index++) {
		unsigned bits = bit_test_widths[width_index];
		for (int operation = 0; operation < 4; operation++) {
			uint64_t operand_index = bit_test_index;
			if (operation == 0) operand_index = bits - 1;
			if (operation == 2) operand_index = 4;
			uint64_t carry = 0;
			uint64_t result = reference_bit_test_register(operation, bits, bit_test_value, operand_index, &carry);
			int output_index = 2 * (width_index * 4 + operation);
			if (bit_test_out[output_index] != result || bit_test_out[output_index + 1] != carry) return 125;
		}
	}
	uint64_t bit_test_data[9] = {
		UINT64_MAX, UINT64_C(1) << 17, 0,
		UINT64_MAX, UINT64_C(1) << 33, 0,
		UINT64_MAX, 0, UINT64_C(1) << 1,
	};
	uint8_t bit_test_carry[12] = {0};
	bitTestMemorySemantics(bit_test_carry, bit_test_data);
	const uint8_t bit_test_want_carry[12] = {1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
	const uint64_t bit_test_want_data[9] = {
		UINT64_C(0x7fffffffffffffff), 1, 0,
		UINT64_C(0x7fffffffffffffff), 1, 0,
		UINT64_C(0x7fffffffffffffff), 1, 0,
	};
	for (int i = 0; i < 12; i++)
		if (bit_test_carry[i] != bit_test_want_carry[i]) return 126;
	for (int i = 0; i < 9; i++)
		if (bit_test_data[i] != bit_test_want_data[i]) return 127;
	int16_t word_madd_a[16] = {
		INT16_MIN, INT16_MIN, -30000, -1, 0, 1, 12345, INT16_MAX,
		7, -11, 1000, -2000, 22222, -12345, INT16_MAX, INT16_MAX,
	};
	int16_t word_madd_b[16] = {
		INT16_MIN, INT16_MIN, -23456, INT16_MAX, -1, INT16_MAX, -2345, INT16_MAX,
		-9, 13, -3000, 4000, -11111, 23456, INT16_MAX, INT16_MAX,
	};
	int32_t word_madd_out[18] = {0}, word_madd_reference[8] = {0}, word_madd_want[18] = {0};
	for (int i = 0; i < 8; i++) {
		int64_t sum = (int64_t)word_madd_a[2*i] * word_madd_b[2*i] +
			(int64_t)word_madd_a[2*i+1] * word_madd_b[2*i+1];
		word_madd_reference[i] = (int32_t)(uint32_t)sum;
	}
	for (int i = 0; i < 2; i++) word_madd_want[i] = word_madd_reference[i];
	for (int i = 0; i < 4; i++) {
		word_madd_want[2+i] = word_madd_reference[i];
		word_madd_want[6+i] = word_madd_reference[i];
	}
	for (int i = 0; i < 8; i++) word_madd_want[10+i] = word_madd_reference[i];
	packedWordMultiplyAddSemantics(word_madd_out, word_madd_a, word_madd_b);
	for (int i = 0; i < 18; i++)
		if (word_madd_out[i] != word_madd_want[i]) return 128;
	int8_t byte_madd_signed[32] = {
		127, 127, -128, -128, 100, -100, 1, -1,
		64, -64, 11, 12, -13, 14, 15, -16,
		31, -32, 33, -34, 35, -36, 37, -38,
		39, -40, 41, -42, 43, -44, 45, -46,
	};
	uint8_t byte_madd_unsigned[32] = {
		255, 255, 255, 255, 200, 3, 255, 128,
		250, 249, 17, 19, 23, 29, 31, 37,
		41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107,
	};
	int16_t byte_madd_out[32] = {0}, byte_madd_reference[16] = {0}, byte_madd_want[32] = {0};
	for (int i = 0; i < 16; i++) {
		int32_t sum = (int32_t)byte_madd_signed[2*i] * byte_madd_unsigned[2*i] +
			(int32_t)byte_madd_signed[2*i+1] * byte_madd_unsigned[2*i+1];
		if (sum > INT16_MAX) sum = INT16_MAX;
		if (sum < INT16_MIN) sum = INT16_MIN;
		byte_madd_reference[i] = (int16_t)sum;
	}
	for (int i = 0; i < 8; i++) {
		byte_madd_want[i] = byte_madd_reference[i];
		byte_madd_want[8+i] = byte_madd_reference[i];
	}
	for (int i = 0; i < 16; i++) byte_madd_want[16+i] = byte_madd_reference[i];
	packedUnsignedSignedByteMultiplyAddSemantics(byte_madd_out, byte_madd_signed, byte_madd_unsigned);
	for (int i = 0; i < 32; i++)
		if (byte_madd_out[i] != byte_madd_want[i]) return 129;
	int8_t dot_signed_bytes[64];
	uint8_t dot_unsigned_bytes[64];
	int16_t dot_words_a[32], dot_words_b[32];
	int32_t dot_accumulator[16], dot_out[64] = {0};
	for (int i = 0; i < 64; i++) {
		dot_signed_bytes[i] = (i / 4) & 1 ? -128 : 127;
		dot_unsigned_bytes[i] = (uint8_t)(255 - (i & 3));
	}
	for (int i = 0; i < 32; i++) {
		dot_words_a[i] = (i / 2) & 1 ? INT16_MIN : INT16_MAX;
		dot_words_b[i] = (i & 1) ? INT16_MAX : INT16_MIN;
	}
	for (int i = 0; i < 16; i++) {
		switch (i & 3) {
		case 0: dot_accumulator[i] = INT32_MAX - 10; break;
		case 1: dot_accumulator[i] = INT32_MIN + 10; break;
		case 2: dot_accumulator[i] = 123456789; break;
		default: dot_accumulator[i] = -987654321; break;
		}
	}
	packedDotProductSemantics(dot_out, dot_signed_bytes, dot_unsigned_bytes, dot_words_a, dot_words_b, dot_accumulator);
	for (int lane = 0; lane < 16; lane++) {
		int64_t byte_sum = dot_accumulator[lane];
		for (int item = 0; item < 4; item++) byte_sum += (int64_t)dot_signed_bytes[4*lane+item] * dot_unsigned_bytes[4*lane+item];
		int64_t byte_sat = byte_sum;
		if (byte_sat > INT32_MAX) byte_sat = INT32_MAX;
		if (byte_sat < INT32_MIN) byte_sat = INT32_MIN;
		int64_t word_sum = dot_accumulator[lane];
		for (int item = 0; item < 2; item++) word_sum += (int64_t)dot_words_a[2*lane+item] * dot_words_b[2*lane+item];
		int64_t word_sat = word_sum;
		if (word_sat > INT32_MAX) word_sat = INT32_MAX;
		if (word_sat < INT32_MIN) word_sat = INT32_MIN;
		if ((uint32_t)dot_out[lane] != (uint32_t)byte_sum) return 930 + lane;
		if (dot_out[16+lane] != (int32_t)byte_sat) return 950 + lane;
		if ((uint32_t)dot_out[32+lane] != (uint32_t)word_sum) return 970 + lane;
		if (dot_out[48+lane] != (int32_t)word_sat) return 990 + lane;
	}
	uint8_t minmax_a[64], minmax_b[64], minmax_out[1024] = {0};
	for (int i = 0; i < 64; i++) {
		minmax_a[i] = (uint8_t)(0x80 + 73*i);
		minmax_b[i] = (uint8_t)(0xff - 29*i);
	}
	packedIntegerMinMaxSemantics(minmax_out, minmax_a, minmax_b);
	for (int lane = 0; lane < 64; lane++) {
		int8_t a = (int8_t)minmax_a[lane], b = (int8_t)minmax_b[lane];
		if ((int8_t)minmax_out[lane] != (a < b ? a : b)) return 1010 + lane;
		if (minmax_out[64+lane] != (minmax_a[lane] < minmax_b[lane] ? minmax_a[lane] : minmax_b[lane])) return 1080 + lane;
		if ((int8_t)minmax_out[128+lane] != (a > b ? a : b)) return 1150 + lane;
		if (minmax_out[192+lane] != (minmax_a[lane] > minmax_b[lane] ? minmax_a[lane] : minmax_b[lane])) return 1220 + lane;
	}
	for (int lane = 0; lane < 32; lane++) {
		uint16_t au = load16(minmax_a + 2*lane), bu = load16(minmax_b + 2*lane);
		int16_t as = (int16_t)au, bs = (int16_t)bu;
		if ((int16_t)load16(minmax_out + 256 + 2*lane) != (as < bs ? as : bs)) return 1290 + lane;
		if (load16(minmax_out + 320 + 2*lane) != (au < bu ? au : bu)) return 1330 + lane;
		if ((int16_t)load16(minmax_out + 384 + 2*lane) != (as > bs ? as : bs)) return 1370 + lane;
		if (load16(minmax_out + 448 + 2*lane) != (au > bu ? au : bu)) return 1410 + lane;
	}
	for (int lane = 0; lane < 16; lane++) {
		uint32_t au = load32(minmax_a + 4*lane), bu = load32(minmax_b + 4*lane);
		int32_t as = (int32_t)au, bs = (int32_t)bu;
		if ((int32_t)load32(minmax_out + 512 + 4*lane) != (as < bs ? as : bs)) return 1450 + lane;
		if (load32(minmax_out + 576 + 4*lane) != (au < bu ? au : bu)) return 1470 + lane;
		if ((int32_t)load32(minmax_out + 640 + 4*lane) != (as > bs ? as : bs)) return 1490 + lane;
		if (load32(minmax_out + 704 + 4*lane) != (au > bu ? au : bu)) return 1510 + lane;
	}
	for (int lane = 0; lane < 8; lane++) {
		uint64_t au = load64(minmax_a + 8*lane), bu = load64(minmax_b + 8*lane);
		int64_t as = (int64_t)au, bs = (int64_t)bu;
		if ((int64_t)load64(minmax_out + 768 + 8*lane) != (as < bs ? as : bs)) return 1530 + lane;
		if (load64(minmax_out + 832 + 8*lane) != (au < bu ? au : bu)) return 1540 + lane;
		if ((int64_t)load64(minmax_out + 896 + 8*lane) != (as > bs ? as : bs)) return 1550 + lane;
		if (load64(minmax_out + 960 + 8*lane) != (au > bu ? au : bu)) return 1560 + lane;
	}
	int16_t word_a[8] = {INT16_MIN, INT16_MIN, -30000, -1, 0, 1, 12345, INT16_MAX};
	int16_t word_b[8] = {INT16_MIN, INT16_MAX, -23456, INT16_MAX, -1, INT16_MAX, -2345, INT16_MAX};
	uint16_t word_mul_out[64] = {0}, word_mul_want[64] = {0};
	packedWordMultiplySemantics(word_mul_out, word_a, word_b);
	for (int i = 0; i < 8; i++) {
		int32_t product = (int32_t)word_a[i] * (int32_t)word_b[i];
		uint32_t unsigned_product = (uint32_t)(uint16_t)word_a[i] * (uint32_t)(uint16_t)word_b[i];
		int32_t rounded = (product + 0x4000) >> 15;
		uint16_t values[4] = {(uint16_t)product, (uint16_t)(product >> 16), (uint16_t)(unsigned_product >> 16), (uint16_t)rounded};
		for (int mode = 0; mode < 4; mode++) {
			word_mul_want[mode*8+i] = values[mode];
			word_mul_want[(mode+4)*8+i] = values[mode];
		}
	}
	for (int i = 0; i < 64; i++)
		if (word_mul_out[i] != word_mul_want[i]) return 240 + i;
	uint32_t shuffle_a[8], shuffle_b[8];
	uint8_t shuffle_out[96] = {0};
	for (int i = 0; i < 8; i++) {
		shuffle_a[i] = 0xa0 + i;
		shuffle_b[i] = 0xb0 + i;
	}
	packedFloatShuffleSemantics(shuffle_out, (uint8_t *)shuffle_a, (uint8_t *)shuffle_b);
	const uint32_t shuffle_ps[12] = {
		0xb3, 0xb2, 0xa1, 0xa0,
		0xb3, 0xb2, 0xa1, 0xa0,
		0xb7, 0xb6, 0xa5, 0xa4,
	};
	for (int i = 0; i < 4; i++)
		if (load32(shuffle_out + 4*i) != shuffle_ps[i]) return 310 + i;
	if (load64(shuffle_out + 16) != UINT64_C(0x000000b1000000b0) ||
		load64(shuffle_out + 24) != UINT64_C(0x000000a3000000a2)) return 314;
	for (int i = 0; i < 8; i++)
		if (load32(shuffle_out + 32 + 4*i) != shuffle_ps[4+i]) return 315 + i;
	const uint64_t shuffle_pd[4] = {
		UINT64_C(0x000000b1000000b0), UINT64_C(0x000000a3000000a2),
		UINT64_C(0x000000b5000000b4), UINT64_C(0x000000a7000000a6),
	};
	for (int i = 0; i < 4; i++)
		if (load64(shuffle_out + 64 + 8*i) != shuffle_pd[i]) return 323 + i;
	uint32_t in_lane_data[8] = {0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107};
	uint32_t in_lane_control[8] = {3, 2, 1, 0, 4, 5, 6, 7};
	uint8_t in_lane_out[144] = {0};
	inLaneFloatingPermuteSemantics(in_lane_out, (uint8_t *)in_lane_data, (uint8_t *)in_lane_control);
	for (int lane = 0; lane < 4; lane++)
		if (load32(in_lane_out + 4*lane) != in_lane_data[3-lane]) return 324;
	for (int lane = 0; lane < 8; lane++) {
		uint32_t immediate_value = in_lane_data[(lane/4)*4 + 3-(lane%4)];
		uint32_t variable_value = in_lane_data[(lane/4)*4 + (in_lane_control[lane]&3)];
		if (load32(in_lane_out + 16 + 4*lane) != immediate_value) return 325;
		if (load32(in_lane_out + 48 + 4*lane) != variable_value) return 326;
	}
	for (int lane = 0; lane < 4; lane++) {
		uint64_t data_q[4], control_q[4];
		for (int i = 0; i < 4; i++) {
			data_q[i] = (uint64_t)in_lane_data[2*i] | (uint64_t)in_lane_data[2*i+1] << 32;
			control_q[i] = (uint64_t)in_lane_control[2*i] | (uint64_t)in_lane_control[2*i+1] << 32;
		}
		uint64_t immediate_value = data_q[(lane/2)*2 + ((0x05 >> lane)&1)];
		uint64_t variable_value = data_q[(lane/2)*2 + ((control_q[lane] >> 1)&1)];
		if (load64(in_lane_out + 80 + 8*lane) != immediate_value) return 327;
		if (load64(in_lane_out + 112 + 8*lane) != variable_value) return 328;
	}
	uint8_t blend_a[32], blend_b[32], blend_out[240] = {0};
	for (int i = 0; i < 32; i++) {
		blend_a[i] = (uint8_t)(0x20 + i);
		blend_b[i] = (uint8_t)(0xc0 + i);
	}
	immediatePackedBlendSemantics(blend_out, blend_a, blend_b);
	const int blend_offsets[11] = {0, 16, 32, 48, 64, 96, 112, 144, 160, 192, 208};
	const int blend_widths[11] = {16, 16, 16, 16, 32, 16, 32, 16, 32, 16, 32};
	const int blend_lane_bytes[11] = {2, 4, 8, 2, 2, 4, 4, 4, 4, 8, 8};
	for (int block = 0; block < 11; block++) {
		for (int i = 0; i < blend_widths[block]; i++) {
			int bit = (i / blend_lane_bytes[block]) % 8;
			uint8_t want = (0xa5 & (1 << bit)) ? blend_a[i] : blend_b[i];
			if (blend_out[blend_offsets[block] + i] != want) return 327 + block;
		}
	}
	uint8_t unpack_out[384] = {0};
	packedUnpackSemantics(unpack_out, blend_a, blend_b);
	const int unpack_offsets[16] = {0,16,32,48,64,80,96,112,128,160,192,224,256,288,320,352};
	const int unpack_widths[16] = {16,16,16,16,16,16,16,16,32,32,32,32,32,32,32,32};
	const int unpack_lane_bytes[16] = {1,1,2,2,4,4,8,8,1,1,2,2,4,4,8,8};
	for (int block = 0; block < 16; block++) {
		int output = unpack_offsets[block];
		int high = block & 1;
		for (int group = 0; group < unpack_widths[block]; group += 16) {
			int lanes_per_group = 16 / unpack_lane_bytes[block];
			int start = high ? lanes_per_group / 2 : 0;
			for (int lane = start; lane < start + lanes_per_group / 2; lane++) {
				int input = group + lane * unpack_lane_bytes[block];
				for (int byte = 0; byte < unpack_lane_bytes[block]; byte++) {
					if (unpack_out[output++] != blend_b[input + byte]) return 338 + block;
				}
				for (int byte = 0; byte < unpack_lane_bytes[block]; byte++) {
					if (unpack_out[output++] != blend_a[input + byte]) return 354 + block;
				}
			}
		}
	}
	uint64_t permute_data[4] = {0x10, 0x21, 0x32, 0x43};
	uint64_t permute_control[4] = {3, 0, 5, 2};
	uint64_t permute_out[8] = {0}, variable_permute_out[8] = {0};
	const uint64_t permute_immediate[4] = {0x10, 0x32, 0x21, 0x43};
	const uint64_t permute_variable[4] = {0x43, 0x10, 0x21, 0x32};
	qwordPermuteSemantics(permute_out, permute_data);
	qwordVariablePermuteSemantics(variable_permute_out, permute_data, permute_control);
	for (int block = 0; block < 2; block++) {
		for (int lane = 0; lane < 4; lane++)
			if (permute_out[4*block+lane] != permute_immediate[lane]) return 370 + block;
	}
	for (int block = 0; block < 2; block++) {
		for (int lane = 0; lane < 4; lane++)
			if (variable_permute_out[4*block+lane] != permute_variable[lane]) return 372 + block;
	}
	uint8_t move_src[64], move_old[64], move_vex_out[128] = {0}, move_mask_out[688] = {0};
	for (int i = 0; i < 64; i++) {
		move_src[i] = (uint8_t)(3 + 17*i);
		move_old[i] = (uint8_t)(0xf0 - 3*i);
	}
	packedFloatMoveVEXSemantics(move_vex_out, move_src);
	for (int block = 0; block < 4; block++)
		for (int i = 0; i < 32; i++)
			if (move_vex_out[32*block+i] != move_src[i]) return 374 + block;
	packedFloatMoveMaskSemantics(move_mask_out, move_src, move_old);
	const int move_offsets[14] = {0,16,32,48,64,80,96,112,144,176,208,240,272,304};
	const int move_widths[14] = {16,16,16,16,16,16,16,32,32,32,32,32,32,64};
	const int move_lane_bytes[14] = {4,4,4,4,8,8,8,4,4,4,8,8,8,4};
	const int move_zero[14] = {0,1,0,0,0,1,0,0,1,0,0,1,0,0};
	for (int block = 0; block < 14; block++) {
		for (int i = 0; i < move_widths[block]; i++) {
			int active = (0xa55a >> (i / move_lane_bytes[block])) & 1;
			uint8_t want = active ? move_src[i] : (move_zero[block] ? 0 : move_old[i]);
			if (move_mask_out[move_offsets[block]+i] != want) return 378 + block;
		}
	}
	const int move_z_offsets[5] = {368,432,496,560,624};
	const int move_z_lane_bytes[5] = {4,4,8,8,8};
	const int move_z_zero[5] = {1,0,0,1,0};
	for (int block = 0; block < 5; block++) {
		for (int i = 0; i < 64; i++) {
			int active = (0xa55a >> (i / move_z_lane_bytes[block])) & 1;
			uint8_t want = active ? move_src[i] : (move_z_zero[block] ? 0 : move_old[i]);
			if (move_mask_out[move_z_offsets[block]+i] != want) return 392 + block;
		}
	}
	uint8_t extend_src[32] = {
		0x00,0x01,0x7f,0x80,0xff,0x55,0xaa,0x40,
		0xc0,0x11,0xee,0x33,0xcc,0x66,0x99,0x22,
		0xdd,0x44,0xbb,0x77,0x88,0x10,0xf0,0x20,
		0xe0,0x30,0xd0,0x50,0xb0,0x60,0xa0,0x70,
	};
	uint8_t extend_vex_out[288] = {0};
	const int extend_input_bits[6] = {8,8,8,16,16,32};
	const int extend_output_bits[6] = {16,32,64,32,64,64};
	packedSignExtendMoveVEXSemantics(extend_vex_out, extend_src);
	for (int op = 0; op < 6; op++) {
		for (int form = 0; form < 2; form++) {
			int width = form ? 32 : 16;
			int offset = form ? 96 + 32*op : 16*op;
			int lanes = width * 8 / extend_output_bits[op];
			for (int lane = 0; lane < lanes; lane++) {
				const uint8_t *p = extend_src + lane * extend_input_bits[op] / 8;
				int64_t expected = extend_input_bits[op] == 8 ? (int64_t)(int8_t)p[0] :
					extend_input_bits[op] == 16 ? (int64_t)(int16_t)load16(p) : (int64_t)(int32_t)load32(p);
				const uint8_t *actual = extend_vex_out + offset + lane * extend_output_bits[op] / 8;
				uint64_t actual_bits = extend_output_bits[op] == 16 ? load16(actual) :
					extend_output_bits[op] == 32 ? load32(actual) : load64(actual);
				uint64_t mask = extend_output_bits[op] == 16 ? UINT64_C(0xffff) :
					extend_output_bits[op] == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
				if (actual_bits != ((uint64_t)expected & mask)) return 397 + op;
			}
		}
	}
	uint8_t extend_old[64], extend_mask_out[768] = {0};
	for (int i = 0; i < 64; i++) extend_old[i] = (uint8_t)(0xe7 - 5*i);
	packedSignExtendMoveMaskSemantics(extend_mask_out, extend_src, extend_old);
	for (int op = 0; op < 6; op++) {
		int lanes = 512 / extend_output_bits[op];
		for (int zero = 0; zero < 2; zero++) {
			int offset = 128*op + 64*zero;
			for (int lane = 0; lane < lanes; lane++) {
				const uint8_t *input = extend_src + lane * extend_input_bits[op] / 8;
				int64_t extended = extend_input_bits[op] == 8 ? (int64_t)(int8_t)input[0] :
					extend_input_bits[op] == 16 ? (int64_t)(int16_t)load16(input) : (int64_t)(int32_t)load32(input);
				const uint8_t *actual = extend_mask_out + offset + lane * extend_output_bits[op] / 8;
				uint64_t actual_bits = extend_output_bits[op] == 16 ? load16(actual) :
					extend_output_bits[op] == 32 ? load32(actual) : load64(actual);
				const uint8_t *old = extend_old + lane * extend_output_bits[op] / 8;
				uint64_t old_bits = extend_output_bits[op] == 16 ? load16(old) :
					extend_output_bits[op] == 32 ? load32(old) : load64(old);
				uint64_t width_mask = extend_output_bits[op] == 16 ? UINT64_C(0xffff) :
					extend_output_bits[op] == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
				uint64_t expected = (UINT64_C(0xa55aa55a) >> lane) & 1 ? (uint64_t)extended & width_mask : (zero ? 0 : old_bits);
				if (actual_bits != expected) return 403 + op;
			}
		}
	}
	uint8_t a[16], b[16], vector_out[160] = {0};
	const uint8_t or_mask[16] = {
		0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
		0xff, 0x00, 0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc,
	};
	for (int i = 0; i < 16; i++) {
		a[i] = (uint8_t)(i * 29 + 3);
		b[i] = (uint8_t)(i * 17 + 0x70);
	}
	goHexVectorOps(vector_out, a, b);
	for (int i = 0; i < 16; i++) {
		if (vector_out[i] != (uint8_t)(a[i] | or_mask[i])) return 70;
		if (vector_out[16+i] != (uint8_t)(a[i] | b[i])) return 71;
		uint8_t gt = (int8_t)a[i] > (int8_t)b[i] ? 0xff : 0;
		if (vector_out[32+i] != gt || vector_out[48+i] != gt) return 72;
		if (vector_out[64+i] != (uint8_t)(a[i] - b[i])) return 73;
		if (vector_out[144+i] != (uint8_t)(a[i] & b[i])) return 74;
	}
	for (int i = 0; i < 8; i++) {
		uint16_t word = (uint16_t)a[2*i] | (uint16_t)a[2*i+1] << 8;
		uint16_t left = (uint16_t)(word << 4), right = (uint16_t)(word >> 4);
		if (vector_out[80+2*i] != (uint8_t)left || vector_out[80+2*i+1] != (uint8_t)(left >> 8)) return 75;
		if (vector_out[96+2*i] != (uint8_t)right || vector_out[96+2*i+1] != (uint8_t)(right >> 8)) return 76;
		if (vector_out[112+2*i] != a[8+i] || vector_out[112+2*i+1] != b[8+i]) return 77;
		if (vector_out[128+2*i] != a[8+i] || vector_out[128+2*i+1] != b[8+i]) return 78;
	}
	const uint64_t word_values[][2] = {
		{0x123456789abcdef0ULL, 0},
		{0x123456789abcdef0ULL, 4},
		{0xfedcba9876543210ULL, 12},
	};
	for (unsigned i = 0; i < sizeof(word_values) / sizeof(word_values[0]); i++) {
		uint64_t value = word_values[i][0], count = word_values[i][1];
		uint16_t shifted = (uint16_t)value >> (count & 31);
		unsigned first = 0;
		while (((shifted >> first) & 1) == 0) first++;
		uint64_t want = (value & ~0xffffULL) | shifted | ((uint64_t)first << 16);
		if (goHexWordOps(value, count) != want) return 79;
	}
	int32_t packed_src[4] = {0, 1, -1, INT32_MIN};
	int32_t packed_out[8] = {0};
	const int32_t packed_want[8] = {0, 0, -1, -1, 0, 0, -1, -1};
	packedArithmeticShift32(packed_out, packed_src);
	for (int i = 0; i < 8; i++)
		if (packed_out[i] != packed_want[i]) return 80 + i;

	uint8_t subtract_a[16] = {0x7f, 0x80, 0x64, 0x9c, 0x32, 0xce, 0x00, 0x01, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80, 0xff, 0x7f};
	uint8_t subtract_b[16] = {0xff, 0x01, 0x9c, 0x64, 0xce, 0x32, 0x01, 0x00, 0x01, 0xff, 0x78, 0x56, 0xff, 0x7f, 0x01, 0x80};
	uint8_t subtract_out[80] = {0};
	packedSubtractSemantics(subtract_out, subtract_a, subtract_b);
	for (int i = 0; i < 16; i++) {
		int signed_value = (int)(int8_t)subtract_a[i] - (int)(int8_t)subtract_b[i];
		if (signed_value < -128) signed_value = -128;
		if (signed_value > 127) signed_value = 127;
		if (subtract_out[i] != (uint8_t)(int8_t)signed_value) return 190;
		int unsigned_value = (int)subtract_a[i] - (int)subtract_b[i];
		if (unsigned_value < 0) unsigned_value = 0;
		if (subtract_out[32+i] != (uint8_t)unsigned_value) return 191;
	}
	for (int i = 0; i < 8; i++) {
		int signed_value = (int)(int16_t)load16(subtract_a + 2*i) - (int)(int16_t)load16(subtract_b + 2*i);
		if (signed_value < -32768) signed_value = -32768;
		if (signed_value > 32767) signed_value = 32767;
		if (load16(subtract_out + 16 + 2*i) != (uint16_t)(int16_t)signed_value) return 192;
		int unsigned_value = (int)load16(subtract_a + 2*i) - (int)load16(subtract_b + 2*i);
		if (unsigned_value < 0) unsigned_value = 0;
		if (load16(subtract_out + 48 + 2*i) != (uint16_t)unsigned_value) return 193;
	}
	for (int i = 0; i < 2; i++)
		if (load64(subtract_out + 64 + 8*i) != load64(subtract_a + 8*i) - load64(subtract_b + 8*i)) return 194;

	uint8_t ecosystem_a[16] = {
		0x00, 0x7f, 0x80, 0xff, 0x34, 0x12, 0xfe, 0xff,
		0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x80,
	};
	uint8_t ecosystem_b[16] = {
		0xff, 0x80, 0x7f, 0x00, 0x78, 0x56, 0x02, 0x00,
		0xef, 0xcd, 0xab, 0x90, 0xff, 0xff, 0xff, 0x7f,
	};
	uint8_t ecosystem_out[816] = {0};
	expandedEcosystemVectors(ecosystem_out, ecosystem_a, ecosystem_b);
	for (int i = 0; i < 16; i++) {
		uint8_t min_u = ecosystem_a[i] < ecosystem_b[i] ? ecosystem_a[i] : ecosystem_b[i];
		uint8_t max_u = ecosystem_a[i] > ecosystem_b[i] ? ecosystem_a[i] : ecosystem_b[i];
		int8_t as = (int8_t)ecosystem_a[i], bs = (int8_t)ecosystem_b[i];
		if (ecosystem_out[i] != min_u || ecosystem_out[16+i] != (uint8_t)(as < bs ? as : bs)) return 100;
		if (ecosystem_out[96+i] != max_u || ecosystem_out[112+i] != (uint8_t)(as > bs ? as : bs)) return 101;
	}
	for (int i = 0; i < 8; i++) {
		uint16_t au = load16(ecosystem_a + 2*i), bu = load16(ecosystem_b + 2*i);
		int16_t as = (int16_t)au, bs = (int16_t)bu;
		if (load16(ecosystem_out + 32 + 2*i) != (au < bu ? au : bu)) return 102;
		if ((int16_t)load16(ecosystem_out + 48 + 2*i) != (as < bs ? as : bs)) return 103;
		if (load16(ecosystem_out + 128 + 2*i) != (au > bu ? au : bu)) return 104;
		if ((int16_t)load16(ecosystem_out + 144 + 2*i) != (as > bs ? as : bs)) return 105;
	}
	for (int i = 0; i < 4; i++) {
		uint32_t au = load32(ecosystem_a + 4*i), bu = load32(ecosystem_b + 4*i);
		int32_t as = (int32_t)au, bs = (int32_t)bu;
		if (load32(ecosystem_out + 64 + 4*i) != (au < bu ? au : bu)) return 106;
		if ((int32_t)load32(ecosystem_out + 80 + 4*i) != (as < bs ? as : bs)) return 107;
		if (load32(ecosystem_out + 160 + 4*i) != (au > bu ? au : bu)) return 108;
		if ((int32_t)load32(ecosystem_out + 176 + 4*i) != (as > bs ? as : bs)) return 109;
	}
	for (int i = 0; i < 2; i++)
		if (load64(ecosystem_out + 192 + 8*i) != (load64(ecosystem_a + 8*i) << 13)) return 110;
	for (int i = 208; i < 224; i++)
		if (ecosystem_out[i] != 0) return 111;
	if (load64(ecosystem_out + 224) != 0x0123456789abcdefULL) return 112;
	if (load64(ecosystem_out + 232) != 0x0000000089abcdefULL) return 113;
	if (load32(ecosystem_out + 240) != 0x89abcdefU) return 119;
	for (int i = 244; i < 256; i++) if (ecosystem_out[i] != 0) return 121;
	if (load64(ecosystem_out + 256) != load64(ecosystem_a)) return 122;
	if (load64(ecosystem_out + 264) != 0) return 123;
	for (int i = 0; i < 16; i++)
		if (ecosystem_out[272+i] != (uint8_t)(((uint16_t)ecosystem_a[i] + ecosystem_b[i] + 1) >> 1)) return 124;
	for (int i = 0; i < 8; i++)
		if (load16(ecosystem_out + 288 + 2*i) != (uint16_t)(((uint32_t)load16(ecosystem_a + 2*i) + load16(ecosystem_b + 2*i) + 1) >> 1)) return 125;
	for (int i = 0; i < 16; i++)
		if (ecosystem_out[304+i] != ((int8_t)ecosystem_a[i] > (int8_t)ecosystem_b[i] ? 0xff : 0)) return 126;
	for (int i = 0; i < 8; i++)
		if (load16(ecosystem_out + 320 + 2*i) != ((int16_t)load16(ecosystem_a + 2*i) > (int16_t)load16(ecosystem_b + 2*i) ? 0xffff : 0)) return 127;
	for (int i = 0; i < 4; i++)
		if (load32(ecosystem_out + 336 + 4*i) != ((int32_t)load32(ecosystem_a + 4*i) > (int32_t)load32(ecosystem_b + 4*i) ? 0xffffffffU : 0)) return 128;
	for (int i = 0; i < 2; i++)
		if (load64(ecosystem_out + 352 + 8*i) != ((int64_t)load64(ecosystem_a + 8*i) > (int64_t)load64(ecosystem_b + 8*i) ? ~0ULL : 0)) return 129;
	for (int i = 0; i < 8; i++) {
		int16_t value = (int16_t)load16(ecosystem_a + 2*i);
		if ((int16_t)load16(ecosystem_out + 368 + 2*i) != (int16_t)(value >> 3)) return 150;
		if ((int16_t)load16(ecosystem_out + 384 + 2*i) != (int16_t)(value >> 15)) return 151;
	}
	for (int i = 0; i < 2; i++) {
		if (load32(ecosystem_out + 400 + 8*i) != load32(ecosystem_a + 4*i)) return 152;
		if (load32(ecosystem_out + 404 + 8*i) != load32(ecosystem_b + 4*i)) return 153;
		if (load32(ecosystem_out + 416 + 8*i) != load32(ecosystem_a + 8 + 4*i)) return 154;
		if (load32(ecosystem_out + 420 + 8*i) != load32(ecosystem_b + 8 + 4*i)) return 155;
	}
	if (load64(ecosystem_out + 432) != load64(ecosystem_a) || load64(ecosystem_out + 440) != load64(ecosystem_b)) return 156;
	if (load64(ecosystem_out + 448) != load64(ecosystem_a + 8) || load64(ecosystem_out + 456) != load64(ecosystem_b + 8)) return 157;
	for (int i = 0; i < 8; i++) if (load16(ecosystem_out + 464 + 2*i) != ecosystem_a[i]) return 158;
	for (int i = 0; i < 4; i++) if (load32(ecosystem_out + 480 + 4*i) != ecosystem_a[i]) return 159;
	for (int i = 0; i < 2; i++) if (load64(ecosystem_out + 496 + 8*i) != ecosystem_a[i]) return 160;
	for (int i = 0; i < 4; i++) if (load32(ecosystem_out + 512 + 4*i) != load16(ecosystem_a + 2*i)) return 161;
	for (int i = 0; i < 2; i++) if (load64(ecosystem_out + 528 + 8*i) != load16(ecosystem_a + 2*i)) return 162;
	for (int i = 0; i < 2; i++) if (load64(ecosystem_out + 544 + 8*i) != load32(ecosystem_a + 4*i)) return 163;
	for (int i = 0; i < 2; i++) {
		if (load32(ecosystem_out + 560 + 4*i) != load32(ecosystem_a + 8*i) + load32(ecosystem_a + 8*i + 4)) return 164;
		if (load32(ecosystem_out + 568 + 4*i) != load32(ecosystem_b + 8*i) + load32(ecosystem_b + 8*i + 4)) return 165;
		if (load32(ecosystem_out + 608 + 4*i) != load32(ecosystem_a + 8*i) - load32(ecosystem_a + 8*i + 4)) return 166;
		if (load32(ecosystem_out + 616 + 4*i) != load32(ecosystem_b + 8*i) - load32(ecosystem_b + 8*i + 4)) return 167;
	}
	for (int i = 0; i < 4; i++) {
		int32_t aa = (int16_t)load16(ecosystem_a + 4*i) + (int16_t)load16(ecosystem_a + 4*i + 2);
		int32_t ba = (int16_t)load16(ecosystem_b + 4*i) + (int16_t)load16(ecosystem_b + 4*i + 2);
		int32_t as = (int16_t)load16(ecosystem_a + 4*i) - (int16_t)load16(ecosystem_a + 4*i + 2);
		int32_t bs = (int16_t)load16(ecosystem_b + 4*i) - (int16_t)load16(ecosystem_b + 4*i + 2);
		if (aa < -32768) aa = -32768; if (aa > 32767) aa = 32767;
		if (ba < -32768) ba = -32768; if (ba > 32767) ba = 32767;
		if (as < -32768) as = -32768; if (as > 32767) as = 32767;
		if (bs < -32768) bs = -32768; if (bs > 32767) bs = 32767;
		if ((int16_t)load16(ecosystem_out + 576 + 2*i) != (int16_t)aa) return 168;
		if ((int16_t)load16(ecosystem_out + 584 + 2*i) != (int16_t)ba) return 169;
		if (load16(ecosystem_out + 592 + 2*i) != (uint16_t)(load16(ecosystem_a + 4*i) + load16(ecosystem_a + 4*i + 2))) return 170;
		if (load16(ecosystem_out + 600 + 2*i) != (uint16_t)(load16(ecosystem_b + 4*i) + load16(ecosystem_b + 4*i + 2))) return 171;
		if ((int16_t)load16(ecosystem_out + 624 + 2*i) != (int16_t)as) return 172;
		if ((int16_t)load16(ecosystem_out + 632 + 2*i) != (int16_t)bs) return 173;
		if (load16(ecosystem_out + 640 + 2*i) != (uint16_t)(load16(ecosystem_a + 4*i) - load16(ecosystem_a + 4*i + 2))) return 174;
		if (load16(ecosystem_out + 648 + 2*i) != (uint16_t)(load16(ecosystem_b + 4*i) - load16(ecosystem_b + 4*i + 2))) return 175;
	}
	uint16_t minimum = 0xffff, minimum_index = 0;
	for (int i = 0; i < 8; i++) {
		uint16_t value = load16(ecosystem_a + 2*i);
		if (value < minimum) { minimum = value; minimum_index = (uint16_t)i; }
	}
	if (load16(ecosystem_out + 656) != minimum || load16(ecosystem_out + 658) != minimum_index) return 176;
	for (int i = 660; i < 672; i++) if (ecosystem_out[i] != 0) return 177;
	for (int block = 0; block < 2; block++)
		for (int i = 0; i < 16; i++) {
			uint8_t want_masked = (int8_t)ecosystem_b[i] < 0 ? ecosystem_a[i] : ecosystem_b[i];
			if (ecosystem_out[672 + 16*block + i] != want_masked) return 178 + block;
		}
	for (int i = 0; i < 8; i++) {
		if (load16(ecosystem_out + 704 + 2*i) != (uint16_t)(load16(ecosystem_a + 2*i) << 3)) return 180;
		if (load16(ecosystem_out + 752 + 2*i) != (uint16_t)(load16(ecosystem_a + 2*i) >> 3)) return 181;
	}
	for (int i = 0; i < 4; i++) {
		if (load32(ecosystem_out + 720 + 4*i) != load32(ecosystem_a + 4*i) << 3) return 182;
		if (load32(ecosystem_out + 768 + 4*i) != load32(ecosystem_a + 4*i) >> 3) return 183;
	}
	for (int i = 0; i < 2; i++) {
		if (load64(ecosystem_out + 736 + 8*i) != load64(ecosystem_a + 8*i) << 3) return 184;
		if (load64(ecosystem_out + 784 + 8*i) != load64(ecosystem_a + 8*i) >> 3) return 185;
	}
	if (load64(ecosystem_out + 800) != 3 || load64(ecosystem_out + 808) != 0) return 186;
	uint64_t parity0 = parityBranches(0x00);
	if (parity0 != 1) return 120 + (int)parity0;
	if (parityBranches(0x03) != 1) return 114;
	if (parityBranches(0x01) != 2) return 115;
	if (parityBranches(0x07) != 2) return 116;
	volatile double zero = 0.0;
	if (unorderedBranch(1.25) != 0) return 117;
	if (unorderedBranch(zero / zero) != 1) return 118;
	float conversion_src[4] = {1.5f, -1.5f, 2.75f, -2.75f};
	int32_t conversion_out[20] = {0};
	int32_t conversion_want[20] = {
		2, -2, 3, -3,
		1, -2, 2, -3,
		2, -1, 3, -2,
		1, -1, 2, -2,
		1, -1, 2, -2,
	};
	packedFloatToDwordModes(conversion_out, conversion_src);
	for (int i = 0; i < 20; i++)
		if (conversion_out[i] != conversion_want[i]) return 130 + i;
	int32_t same_width_ints[16];
	float same_width_floats[16] = {
		1.5f, -1.5f, 2.75f, -2.75f, 0.5f, -0.5f, 3.25f, -3.25f,
		4.5f, -4.5f, 5.75f, -5.75f, 6.5f, -6.5f, 7.25f, -7.25f,
	};
	float same_width_squares32[16];
	double same_width_squares64[8];
	for (int i = 0; i < 16; i++) {
		same_width_ints[i] = i - 8;
		same_width_squares32[i] = (float)((i + 1) * (i + 1));
	}
	for (int i = 0; i < 8; i++) same_width_squares64[i] = (double)((i + 1) * (i + 1));
	int32_t same_width_nearest[16] = {2,-2,3,-3,0,0,3,-3,4,-4,6,-6,6,-6,7,-7};
	int32_t same_width_trunc[16] = {1,-1,2,-2,0,0,3,-3,4,-4,5,-5,6,-6,7,-7};
	int32_t same_width_down[16] = {1,-2,2,-3,0,-1,3,-4,4,-5,5,-6,6,-7,7,-8};
	int32_t same_width_up[16] = {2,-1,3,-2,1,0,4,-3,5,-4,6,-5,7,-6,8,-7};
	uint8_t same_width_out[576] = {0};
	sameWidthPackedConversionSemantics(same_width_out, same_width_ints, same_width_floats, same_width_squares32, same_width_squares64);
	for (int i = 0; i < 16; i++) {
		if (loadf32(same_width_out + 4*i) != (float)same_width_ints[i]) return 760 + i;
		if ((int32_t)load32(same_width_out + 64 + 4*i) != same_width_nearest[i]) return 780 + i;
		if ((int32_t)load32(same_width_out + 128 + 4*i) != same_width_trunc[i]) return 800 + i;
		if (loadf32(same_width_out + 192 + 4*i) != (float)(i + 1)) return 820 + i;
		if ((int32_t)load32(same_width_out + 320 + 4*i) != same_width_nearest[i]) return 840 + i;
		if ((int32_t)load32(same_width_out + 384 + 4*i) != same_width_down[i]) return 860 + i;
		if ((int32_t)load32(same_width_out + 448 + 4*i) != same_width_up[i]) return 880 + i;
		if ((int32_t)load32(same_width_out + 512 + 4*i) != same_width_trunc[i]) return 900 + i;
	}
	for (int i = 0; i < 8; i++)
		if (loadf64(same_width_out + 256 + 8*i) != (double)(i + 1)) return 920 + i;
	double widening_out[4] = {0};
	double widening_want[4] = {1.5, -1.5, 2.75, -2.75};
	packedSingleToDouble(widening_out, conversion_src);
	for (int i = 0; i < 4; i++)
		if (widening_out[i] != widening_want[i]) return 180 + i;
	uint64_t cmov_src[16];
	uint64_t cmov_out[16] = {0};
	for (int i = 0; i < 16; i++) cmov_src[i] = 101 + (uint64_t)i;
	conditionalMoveCodes(cmov_out, cmov_src);
	int cmov_taken[16] = {1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1};
	for (int i = 0; i < 16; i++) {
		uint64_t want = cmov_taken[i] ? cmov_src[i] : UINT64_MAX;
		if (cmov_out[i] != want) return 160 + i;
	}
	double fma_a64[2] = {2, -3}, fma_b64[2] = {5, 7}, fma_c64[2] = {11, -13};
	float fma_a32[4] = {2, -3, 4, -5};
	float fma_b32[4] = {5, 7, -11, -13};
	float fma_c32[4] = {17, -19, 23, -29};
	uint8_t fma_out[288] = {0};
	fma3Semantics(fma_out, fma_a64, fma_b64, fma_c64, fma_a32, fma_b32, fma_c32);
	for (int lane = 0; lane < 2; lane++) {
		double a = fma_a64[lane], b = fma_b64[lane], c = fma_c64[lane];
		double want[8] = {
			c*a+b, b*c+a, b*a+c, c*a-b, -(b*c)+a, -(b*a)-c,
			lane % 2 == 0 ? c*a-b : c*a+b,
			lane % 2 == 0 ? b*a+c : b*a-c,
		};
		for (int block = 0; block < 8; block++)
			if (loadf64(fma_out + 16*block + 8*lane) != want[block]) return 500 + 2*block + lane;
	}
	for (int lane = 0; lane < 4; lane++) {
		float a = fma_a32[lane], b = fma_b32[lane], c = fma_c32[lane];
		float want[6] = {
			c*a+b, b*c-a, -(b*a)+c, -(c*a)-b,
			lane % 2 == 0 ? b*c-a : b*c+a,
			lane % 2 == 0 ? b*a+c : b*a-c,
		};
		for (int block = 0; block < 6; block++)
			if (loadf32(fma_out + 128 + 16*block + 4*lane) != want[block]) return 520 + 4*block + lane;
	}
	if (loadf64(fma_out + 224) != fma_c64[0]*fma_a64[0]+fma_b64[0] ||
		loadf64(fma_out + 232) != fma_c64[1]) return 550;
	if (loadf64(fma_out + 240) != fma_b64[0]*fma_c64[0]-fma_a64[0] ||
		loadf64(fma_out + 248) != fma_c64[1]) return 551;
	if (loadf32(fma_out + 256) != -(fma_b32[0]*fma_a32[0])+fma_c32[0] ||
		loadf32(fma_out + 260) != fma_c32[1] ||
		loadf32(fma_out + 264) != fma_c32[2] ||
		loadf32(fma_out + 268) != fma_c32[3]) return 552;
	if (loadf32(fma_out + 272) != -(fma_c32[0]*fma_a32[0])-fma_b32[0] ||
		loadf32(fma_out + 276) != fma_c32[1] ||
		loadf32(fma_out + 280) != fma_c32[2] ||
		loadf32(fma_out + 284) != fma_c32[3]) return 553;
	double binary_a64[2] = {2, -3}, binary_b64[2] = {20, 30};
	float binary_a32[4] = {2, -3, 4, -5}, binary_b32[4] = {20, 30, -40, -50};
	double binary_want64[6][2] = {
		{22, 27}, {18, 33}, {40, -90}, {10, -10}, {20, 30}, {2, -3},
	};
	float binary_want32[6][4] = {
		{22, 27, -36, -55},
		{18, 33, -44, -45},
		{40, -90, -160, 250},
		{10, -10, -10, 10},
		{20, 30, 4, -5},
		{2, -3, -40, -50},
	};
	uint8_t binary_out[384] = {0};
	binaryFloatingSemantics(binary_out, binary_a64, binary_b64, binary_a32, binary_b32);
	for (int operation = 0; operation < 6; operation++) {
		for (int lane = 0; lane < 2; lane++)
			if (loadf64(binary_out + 16*operation + 8*lane) != binary_want64[operation][lane]) return 600 + 2*operation + lane;
		for (int lane = 0; lane < 4; lane++)
			if (loadf32(binary_out + 96 + 16*operation + 4*lane) != binary_want32[operation][lane]) return 620 + 4*operation + lane;
		for (int lane = 0; lane < 2; lane++) {
			double want = lane == 0 ? binary_want64[operation][0] : binary_b64[lane];
			if (loadf64(binary_out + 192 + 16*operation + 8*lane) != want) return 650 + 2*operation + lane;
		}
		for (int lane = 0; lane < 4; lane++) {
			float want = lane == 0 ? binary_want32[operation][0] : binary_b32[lane];
			if (loadf32(binary_out + 288 + 16*operation + 4*lane) != want) return 670 + 4*operation + lane;
		}
	}
	float horizontal_a32[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	float horizontal_b32[8] = {10, 20, 30, 40, 50, 60, 70, 80};
	double horizontal_a64[4] = {1, 2, 3, 4};
	double horizontal_b64[4] = {10, 20, 30, 40};
	float horizontal_want32[4][8] = {
		{30, 70, 3, 7, 110, 150, 11, 15},
		{-10, -10, -1, -1, -10, -10, -1, -1},
		{30, 70, 3, 7, 0, 0, 0, 0},
		{-10, -10, -1, -1, 0, 0, 0, 0},
	};
	double horizontal_want64[4][4] = {
		{30, 3, 70, 7},
		{-10, -1, -10, -1},
		{30, 3, 0, 0},
		{-10, -1, 0, 0},
	};
	uint8_t horizontal_out[192] = {0};
	horizontalFloatingSemantics(horizontal_out, horizontal_a32, horizontal_b32, horizontal_a64, horizontal_b64);
	for (int block = 0; block < 2; block++)
		for (int lane = 0; lane < 8; lane++)
			if (loadf32(horizontal_out + 32*block + 4*lane) != horizontal_want32[block][lane]) return 700 + 8*block + lane;
	for (int block = 0; block < 2; block++)
		for (int lane = 0; lane < 4; lane++)
			if (loadf64(horizontal_out + 64 + 32*block + 8*lane) != horizontal_want64[block][lane]) return 720 + 4*block + lane;
	for (int block = 0; block < 2; block++)
		for (int lane = 0; lane < 4; lane++)
			if (loadf32(horizontal_out + 128 + 16*block + 4*lane) != horizontal_want32[2+block][lane]) return 740 + 4*block + lane;
	for (int block = 0; block < 2; block++)
		for (int lane = 0; lane < 2; lane++)
			if (loadf64(horizontal_out + 160 + 16*block + 8*lane) != horizontal_want64[2+block][lane]) return 750 + 2*block + lane;
	return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "amd64_conformance", triple, ll, mainC, runPrefix)
}

func rosettaAvailable() bool {
	return exec.Command("/usr/bin/arch", "-x86_64", "/usr/bin/true").Run() == nil
}
