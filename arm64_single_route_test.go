package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64TinyFunctionsCannotBypassCallerLinkProof(t *testing.T) {
	pkg := mustGoPackage(t, "test/tinycontrol", "package tinycontrol\nfunc F()\n")
	for _, body := range []string{
		"MOVD $0,R30\nRET",
		"MOVD R0,R30\nRET",
		"MOVD R30,R0\nMOVD R1,R30\nRET",
	} {
		source := "TEXT ·F(SB),4,$0-0\n" + body + "\n"
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
			"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
		} {
			options := Options{Goarch: "arm64", TargetTriple: triple,
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
				Sigs:       map[string]FuncSig{"F": {Name: "F", Ret: Void}}}
			_, err := Translate(file, options)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("text / %s / %s accepted changed caller LR: %v", triple, body, err)
			}
			ctx := llvm.NewContext()
			mod, err := TranslateModuleInContext(ctx, file, options)
			if err == nil {
				mod.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("module / %s / %s accepted changed caller LR: %v", triple, body, err)
			}
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: triple, ResolveSym: options.ResolveSym,
			})
			if err == nil {
				translated.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("Go module / %s / %s accepted changed caller LR: %v", triple, body, err)
			}
		}
	}
}

func TestARM64TinyDirectPrototypeRequiresArchitectureProof(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT F(SB),4,$0-0\nMOVD $7,R0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := translateModuleDirect(file, Options{Goarch: "arm64",
		Sigs: map[string]FuncSig{"F": {Name: "F", Ret: I64}}})
	if err == nil {
		mod.Dispose()
	}
	if !errors.Is(err, errDirectModuleUnsupported) {
		t.Fatalf("legacy direct ARM64 prototype must request architecture-aware fallback: %v", err)
	}
}

func TestCrossLinuxRuntimeMatrixARM64TinyCallerLinkRoundTrip(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·tinyRoundTrip(SB),4,$0-16
MOVD a+0(FP),R0
MOVD R30,R9
MOVD R9,R30
MOVD R0,ret+8(FP)
RET
`
	const goMain = `package main
func tinyRoundTrip(uint64) uint64
func main() {
    for _, a := range []uint64{0, 1, 123, 0x8000000000000000, ^uint64(0)} {
        if tinyRoundTrip(a) != a { panic("tiny caller link round trip") }
    }
}
`
	runARM64LocalRegisterGoOracle(t, source, goMain, len(runner) != 0)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "tinyRoundTrip", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		}}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
		Sigs:       map[string]FuncSig{"tinyRoundTrip": sig}})
	if err != nil {
		t.Fatal(err)
	}
	const cMain = `#include <stdint.h>
extern uint64_t tinyRoundTrip(uint64_t);
int main(void) {
    const uint64_t values[] = {0, 1, 123, UINT64_C(0x8000000000000000), UINT64_MAX};
    for (unsigned i = 0; i < 5; i++) {
        if (tinyRoundTrip(values[i]) != values[i]) return 1;
    }
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "tiny_caller_link", triple, ir, cMain, runner)
}
