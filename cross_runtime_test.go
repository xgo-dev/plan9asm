package plan9asm

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrix(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 to run the Linux cross-execution matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatalf("cross-execution driver requires a linux/amd64 host, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("llc not found")
	}
	t.Run("amd64_text_continuations", func(t *testing.T) {
		runX86ContinuationGo(t)
		clang := findLLVM22Tool("clang")
		if clang == "" {
			t.Fatal("LLVM 22 clang not found")
		}
		ir := x86ContinuationIR(t, "x86_64-unknown-linux-gnu", x86ContinuationSource)
		runX86Continuation(t, llc, clang, "x86_64-unknown-linux-gnu", ir)
	})
	t.Run("386_text_continuations", func(t *testing.T) {
		ir := x86Continuation386IR(t, "i386-unknown-linux-gnu")
		main := strings.NewReplacer("uint64_t", "uint32_t", "UINT64_MAX", "UINT32_MAX").Replace(x86ContinuationMain)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc", "-no-pie"},
			"continuation386", "i386-unknown-linux-gnu", ir, main, []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
	})
	t.Run("amd64_integer_broadcast_views", func(t *testing.T) {
		clang := findLLVM22Tool("clang")
		if clang == "" {
			t.Fatal("LLVM 22 clang not found")
		}
		ir, main := integerBroadcastViews(t, "x86_64-unknown-linux-gnu")
		compileAndRunRuntimeTestForTarget(t, llc, clang, "integer_broadcast", "x86_64-unknown-linux-gnu", ir, main, nil)
	})
	t.Run("arm64_raw_sve_count_index", func(t *testing.T) {
		testARM64RawSVECountIndexRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_float", func(t *testing.T) {
		testARM64RawSVEFloatRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_float_compare", func(t *testing.T) {
		testARM64RawSVEFloatCompareRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_predicate_permute", func(t *testing.T) {
		testARM64RawSVEPredicatePermuteRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_compact", func(t *testing.T) {
		testARM64RawSVECompactRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_copy", func(t *testing.T) {
		testARM64RawSVECopyRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_integer_unary", func(t *testing.T) {
		testARM64RawSVEIntegerUnaryRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_predicate_memory", func(t *testing.T) {
		testARM64RawSVEPredicateMemoryRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_structured_memory", func(t *testing.T) {
		testARM64RawSVEStructuredMemoryRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_integer_dot", func(t *testing.T) {
		testARM64RawSVEIntegerDotRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_xar", func(t *testing.T) {
		testARM64RawSVEXARRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_splice", func(t *testing.T) {
		testARM64RawSVESpliceRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_integer_reduction", func(t *testing.T) {
		testARM64RawSVEIntegerReductionRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_ternary_bitwise", func(t *testing.T) {
		testARM64RawSVETernaryBitwiseRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_multiply_accumulate", func(t *testing.T) {
		testARM64RawSVEMultiplyAccumulateRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_extra_shift", func(t *testing.T) {
		testARM64RawSVEExtraShiftRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_signed_load", func(t *testing.T) {
		testARM64RawSVESignedLoadRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_unsigned_load", func(t *testing.T) {
		testARM64RawSVEUnsignedLoadRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_extended_load", func(t *testing.T) {
		testARM64RawSVEExtendedLoadRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_add_sub_wide", func(t *testing.T) {
		testARM64RawSVEAddSubWideRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_multiply_high", func(t *testing.T) {
		testARM64RawSVEMultiplyHighRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_saturating_add_sub", func(t *testing.T) {
		testARM64RawSVESaturatingAddSubRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_float_arithmetic", func(t *testing.T) {
		testARM64RawSVEFloatArithmeticRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_float_divide_scale", func(t *testing.T) {
		testARM64RawSVEFloatDivideScaleRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_float_immediate", func(t *testing.T) {
		testARM64RawSVEFloatImmediateRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_address_generation", func(t *testing.T) {
		testARM64RawSVEAddressGenerationRuntime(t, llc)
	})
	t.Run("arm64_raw_sve_vector_count", func(t *testing.T) {
		testARM64RawSVEVectorCountRuntime(t, llc)
	})
	t.Run("arm64_sve_ordinary_memory_offset", func(t *testing.T) {
		testARM64SVEMemoryOffsetRuntime(t, llc, false)
	})
	t.Run("arm64_sve_non_faulting_memory_offset", func(t *testing.T) {
		testARM64SVEMemoryOffsetRuntime(t, llc, true)
	})
	t.Run("arm64_raw_pool_control_flow", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolControlFlowIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "branchpool", triple, ir,
			arm64RawPoolControlFlowMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_void_return", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawVoidPoolIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "voidpool", triple, ir,
			arm64RawVoidPoolMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_register_effects", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolRegisterEffectsIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_effects", triple, ir,
			arm64RawPoolRegisterEffectsMain, []string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_result_contract", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolResultIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_result", triple, ir,
			arm64RawPoolResultMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_bounded_offsets", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolOffsetIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_offset", triple, ir,
			arm64RawPoolOffsetMain, []string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_bounded_indexes", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolIndexedIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_index", triple, ir,
			arm64RawPoolIndexedMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_aliases", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolAliasesIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_alias", triple, ir,
			arm64RawPoolAliasesMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_guarded_indexes", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolGuardIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_guard", triple, ir,
			arm64RawPoolGuardMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_affine_indexes", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolAffineIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_affine", triple, ir,
			arm64RawPoolAffineMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_multiply_accumulate", func(t *testing.T) {
		t.Run("native_go", TestARM64MultiplyAccumulateNativeGo)
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64MultiplyAccumulateIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "multiply", triple, ir,
			main, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_stack_bounds", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64StackBoundsRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "stack", triple, ir,
			main, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_sve_pool_aliases", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64RawPoolSVEAliasesRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "pool_sve", triple, ir, main,
			[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_dynamic_stack", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64DynamicStackRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "dynamic", triple, ir,
			main, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_sve_pool_values", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64RawPoolSVEValuesRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "pool_sve_values", triple, ir, main,
			[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_sve_pool_memory", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64RawPoolSVEMemoryRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "pool_sve_memory", triple, ir, main,
			[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_sve_pool_flags", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64RawPoolSVEFlagsRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "pool_sve_flags", triple, ir, main,
			[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_pool_counter_loops", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir := arm64RawPoolLoopIR(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "pool_loop", triple, ir,
			arm64RawPoolLoopMain, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_fixed_gp_float", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64FixedGPFloatRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "fixed_gp", triple, ir,
			main, []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
	})
	t.Run("arm64_raw_scalar_abd_mul", func(t *testing.T) {
		const triple = "aarch64-unknown-linux-gnu"
		ir, main := arm64ScalarABDMulRuntime(t, triple)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+fp16"},
			"scalar_abd_mul", triple, ir, main, []string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
	})

	type target struct {
		goarch    string
		arch      Arch
		triple    string
		asm       string
		sig       FuncSig
		compiler  []string
		runPrefix []string
		mainC     string
	}
	targets := []target{
		{
			goarch:   "amd64",
			arch:     ArchAMD64,
			triple:   "x86_64-unknown-linux-gnu",
			asm:      "TEXT add2(SB),NOSPLIT,$0-24\nMOVQ a+0(FP), AX\nADDQ b+8(FP), AX\nMOVQ AX, ret+16(FP)\nRET\n\nTEXT isneg(SB),NOSPLIT,$0-16\nMOVQ x+0(FP), AX\nCMPQ AX, $0\nJL V1\nMOVQ $0, AX\nMOVQ AX, ret+8(FP)\nRET\nV1:\nMOVQ $1, AX\nMOVQ AX, ret+8(FP)\nRET\n",
			sig:      crossAddSig("amd64"),
			compiler: []string{"cc"},
			mainC:    "extern long long add2(long long, long long); extern long long isneg(long long); int main(void) { if (add2(19, 23) != 42) return 11; if (isneg(-1) != 1 || isneg(1) != 0) return 21; return 0; }\n",
		},
		{
			goarch:    "386",
			arch:      ArchAMD64,
			triple:    "i386-unknown-linux-gnu",
			asm:       "TEXT add2(SB),NOSPLIT,$0-12\nMOVL a+0(FP), AX\nADDL b+4(FP), AX\nMOVL AX, ret+8(FP)\nRET\n\nTEXT isneg(SB),NOSPLIT,$0-8\nMOVL x+0(FP), AX\nCMPL AX, $0\nJL V1\nMOVL $0, AX\nMOVL AX, ret+4(FP)\nRET\nV1:\nMOVL $1, AX\nMOVL AX, ret+4(FP)\nRET\n",
			sig:       crossAddSig("386"),
			compiler:  []string{"i686-linux-gnu-gcc"},
			runPrefix: []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"},
			mainC:     "extern int add2(int, int); extern int isneg(int); int main(void) { if (add2(19, 23) != 42) return 12; if (isneg(-1) != 1 || isneg(1) != 0) return 22; return 0; }\n",
		},
		{
			goarch:    "arm",
			arch:      ArchARM,
			triple:    "armv7-unknown-linux-gnueabihf",
			asm:       "TEXT add2(SB),NOSPLIT,$0-12\nMOVW a+0(FP), R0\nADD b+4(FP), R0\nMOVW R0, ret+8(FP)\nRET\n\nTEXT isneg(SB),NOSPLIT,$0-8\nMOVW x+0(FP), R0\nCMP $0, R0\nBLT V1\nMOVW $0, R0\nMOVW R0, ret+4(FP)\nRET\nV1:\nMOVW $1, R0\nMOVW R0, ret+4(FP)\nRET\n",
			sig:       crossAddSig("arm"),
			compiler:  []string{"arm-linux-gnueabihf-gcc"},
			runPrefix: []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"},
			mainC:     "extern int add2(int, int); extern int isneg(int); int main(void) { if (add2(19, 23) != 42) return 13; if (isneg(-1) != 1 || isneg(1) != 0) return 23; return 0; }\n",
		},
		{
			goarch:    "arm64",
			arch:      ArchARM64,
			triple:    "aarch64-unknown-linux-gnu",
			asm:       "TEXT add2(SB),NOSPLIT,$0-24\nMOVD a+0(FP), R0\nMOVD b+8(FP), R1\nADD R1, R0\nMOVD R0, ret+16(FP)\nRET\n\nTEXT isneg(SB),NOSPLIT,$0-16\nMOVD x+0(FP), R0\nCMP $0, R0\nBLT V1\nMOVD $0, R0\nMOVD R0, ret+8(FP)\nRET\nV1:\nMOVD $1, R0\nMOVD R0, ret+8(FP)\nRET\n",
			sig:       crossAddSig("arm64"),
			compiler:  []string{"aarch64-linux-gnu-gcc"},
			runPrefix: []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"},
			mainC:     "extern long long add2(long long, long long); extern long long isneg(long long); int main(void) { if (add2(19, 23) != 42) return 14; if (isneg(-1) != 1 || isneg(1) != 0) return 24; return 0; }\n",
		},
	}

	for _, tc := range targets {
		t.Run(tc.goarch, func(t *testing.T) {
			tools := []string{tc.compiler[0]}
			if len(tc.runPrefix) != 0 {
				tools = append(tools, tc.runPrefix[0])
			}
			for _, tool := range tools {
				if _, err := exec.LookPath(tool); err != nil {
					t.Fatalf("required cross-execution tool %q not found", tool)
				}
			}
			file, err := Parse(tc.arch, tc.asm)
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{
				"add2":  tc.sig,
				"isneg": crossUnarySig(tc.goarch, "isneg"),
			}
			ll, err := Translate(file, Options{
				TargetTriple: tc.triple,
				Goarch:       tc.goarch,
				Sigs:         sigs,
			})
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, tc.compiler, "cross_add2_"+tc.goarch, tc.triple, ll, tc.mainC, tc.runPrefix)
		})
	}
}

func crossUnarySig(goarch, name string) FuncSig {
	word := I32
	result := int64(4)
	if goarch == "amd64" || goarch == "arm64" {
		word = I64
		result = 8
	}
	return FuncSig{
		Name: name,
		Args: []LLVMType{word},
		Ret:  word,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: word, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: result, Type: word, Index: 0, Field: -1}},
		},
	}
}

func crossAddSig(goarch string) FuncSig {
	word := I32
	second := int64(4)
	result := int64(8)
	if goarch == "amd64" || goarch == "arm64" {
		word = I64
		second = 8
		result = 16
	}
	return FuncSig{
		Name: "add2",
		Args: []LLVMType{word, word},
		Ret:  word,
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: word, Index: 0, Field: -1},
				{Offset: second, Type: word, Index: 1, Field: -1},
			},
			Results: []FrameSlot{{Offset: result, Type: word, Index: 0, Field: -1}},
		},
	}
}
