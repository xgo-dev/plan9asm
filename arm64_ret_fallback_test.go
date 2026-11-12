package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"
)

const arm64RetArgSource = `
TEXT ·RetArg<ABIInternal>(SB),NOSPLIT,$0-16
	RET
`

func TestCrossLinuxRuntimeMatrixARM64ReturnFallbackGoOracle(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	// This trusted assembler identity permits the explicit source selector;
	// the ordinary Go compiler still uses the real declaration and symabis.
	runARM64GoInternalOracle(t, "#include \"textflag.h\"\n"+arm64RetArgSource, `package main
func RetArg(uint64) uint64
func main() {
	for _, input := range []uint64{0, 1, 123, 0x8000000000000000, ^uint64(0)} {
		if RetArg(input) != input {
			panic("ABIInternal unmodified R0 result mismatch")
		}
	}
}
`, len(runner) != 0)
	const main = `#include <stdint.h>
extern uint64_t retArg(uint64_t);
int main(void) {
	uint64_t inputs[] = {0, 1, 123, UINT64_C(0x8000000000000000), UINT64_MAX};
	for (unsigned i = 0; i < 5; i++) {
		if (retArg(inputs[i]) != inputs[i]) return 1;
	}
	return 0;
}
`
	const shim = `
define i64 @retArg(i64 %input) {
  %result = call i64 @test.RetArg(i64 %input)
  ret i64 %result
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "ret_arg_internal", triple, translateARM64RetArgWithGoContract(t, triple)+shim, main, runner)
}

func translateARM64RetArgWithGoContract(t *testing.T, triple string) string {
	t.Helper()
	pkg := mustGoPackage(t, "test", "package test\nfunc RetArg(uint64) uint64\n")
	tr, err := TranslateGoModule(pkg, []byte(arm64RetArgSource), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(sym string) string { return "test." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
	})
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	defer tr.Module.Dispose()
	sig := tr.Signatures["test.RetArg"]
	if sig.ARM64GoRegisterABI == nil {
		t.Fatal("source ABIInternal selector and real declaration did not derive an entry contract")
	}
	if len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != 8 {
		t.Fatalf("expected the declaration-backed, unwritten result slot at FP+8: %+v", sig.Frame)
	}
	return tr.Module.String()
}

func TestARM64ReturnFallbackToRegisterWhenResultSlotNotWritten(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		t.Run(target, func(t *testing.T) {
			ll := translateARM64RetArgWithGoContract(t, target)
			if strings.Contains(ll, "ret i64 0") {
				t.Fatalf("unexpected zero return when result slot is not written:\n%s", ll)
			}
			if !strings.Contains(ll, "ret i64 %") {
				t.Fatalf("expected register-based non-constant return:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target, "ret_arg.ll", "ret_arg.o", ll)
		})
	}
}

func TestARM64ReturnFallbackNeedsCompleteEntryContract(t *testing.T) {
	pkg := mustGoPackage(t, "test", "package test\nfunc RetArg(uint64) uint64\n")
	for _, declared := range []bool{false, true} {
		sig := FuncSig{
			Name: "test.RetArg", Args: []LLVMType{I64}, Ret: I64,
			Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
			},
		}
		if declared {
			var err error
			sig, err = goFuncSigForDeclaredFunc("test.RetArg", pkg.Types.Scope().Lookup("RetArg").(*types.Func), "arm64", nil, nil, true)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, target := range []string{
			"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
			"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
		} {
			file, err := Parse(ArchARM64, arm64RetArgSource)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				Goarch: "arm64", TargetTriple: target,
				ResolveSym: func(sym string) string { return "test." + strings.TrimPrefix(goStripABISuffix(sym), "·") },
				Sigs:       map[string]FuncSig{"test.RetArg": sig},
			})
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "complete typed register contract") {
				t.Errorf("%s declared=%t: missing entry contract must remain Context, got %v", target, declared, err)
			}
		}
	}
}
