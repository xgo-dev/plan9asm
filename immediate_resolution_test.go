package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestUnresolvedImmediateProbeRequiresContextButTranslationFails(t *testing.T) {
	for _, target := range []struct {
		arch   Arch
		goarch string
		body   string
	}{
		{ArchAMD64, "amd64", "ADDQ $const_stackGuard, AX"},
		{ArchAMD64, "386", "ADDL $const_stackGuard, AX"},
		{ArchARM64, "arm64", "ADD $(16 + frame__size), R0"},
		{ArchARM, "arm", "ADD $const_stackGuard, R0"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			file, err := Parse(target.arch, "TEXT context(SB),$0-0\n"+target.body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			if err := ProbeInstruction(target.arch, target.goarch, instruction); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unresolved single-instruction probe = %v, want context", err)
			}
			if err := ProbeInstructionSequence(target.arch, target.goarch, []Instr{instruction}); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unresolved instruction-sequence probe = %v, want context", err)
			}
		})
	}
}

func TestTranslationRejectsUnresolvedImmediateInsteadOfInventingZero(t *testing.T) {
	for _, target := range []struct {
		arch   Arch
		goarch string
		triple string
		move   string
	}{
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "MOVQ %s, AX"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "MOVL %s, AX"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "MOVD %s, R0"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", "MOVW %s, R0"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "I64Const %s\nDrop"},
	} {
		for _, operand := range []string{"$missing_constant", "$(16 + missing_constant)"} {
			for _, module := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/module=%v", target.goarch, operand, module), func(t *testing.T) {
					source := "TEXT unresolved(SB),$0-0\n" + fmt.Sprintf(target.move, operand) + "\nRET\n"
					file, err := Parse(target.arch, source)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: target.goarch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"unresolved": {Name: "unresolved", Ret: Void}},
					}
					if module {
						ctx := llvm.NewContext()
						mod, moduleErr := TranslateModuleInContext(ctx, file, options)
						if moduleErr == nil {
							mod.Dispose()
						}
						ctx.Dispose()
						err = moduleErr
					} else {
						_, err = Translate(file, options)
					}
					if err == nil || !strings.Contains(err.Error(), "unresolved symbolic immediate") {
						t.Fatalf("unresolved %s became a successful/fabricated value: %v", operand, err)
					}
				})
			}
		}
	}
}

func TestTranslationChecksRawDirectiveImmediatesBeforeDecoding(t *testing.T) {
	for _, target := range []struct {
		arch   Arch
		goarch string
		body   string
	}{
		{ArchAMD64, "amd64", "BYTE $(0x90 + missing_byte)"},
		{ArchAMD64, "386", "BYTE $(0x90 + missing_byte)"},
		{ArchARM64, "arm64", "WORD $(0xd503201f + missing_word)"},
		{ArchARM, "arm", "WORD $(0xe320f000 + missing_word)"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			file, err := Parse(target.arch, "TEXT raw_unknown(SB),$0-0\n"+target.body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.goarch,
				Sigs: map[string]FuncSig{"raw_unknown": {Name: "raw_unknown", Ret: Void}},
			}
			_, err = Translate(file, options)
			if err == nil || !strings.Contains(err.Error(), "unresolved symbolic immediate") {
				t.Fatalf("raw unknown immediate reached decoding: %v", err)
			}
			ctx := llvm.NewContext()
			mod, moduleErr := TranslateModuleInContext(ctx, file, options)
			if moduleErr == nil {
				mod.Dispose()
			}
			ctx.Dispose()
			if moduleErr == nil || !strings.Contains(moduleErr.Error(), "unresolved symbolic immediate") {
				t.Fatalf("raw unknown immediate reached module decoding: %v", moduleErr)
			}
		})
	}
}

func TestResolvedImmediateGrammarPreservesConstantsAndAddresses(t *testing.T) {
	for _, text := range []string{
		"$0", "$33", "$(16 + 17)", "$1.5", "$global(SB)", "$global+8(SB)",
		"$slot+0(FP)", "$8(AX)", "$(-64*1024+104)(R13)", "$global(SB)(AX*8)",
	} {
		t.Run(text, func(t *testing.T) {
			operand, err := parseOperand(text)
			if err != nil {
				t.Fatal(err)
			}
			if err := unresolvedSymbolicImmediateError(operand); err != nil {
				t.Fatalf("resolved constant/address rejected: %v", err)
			}
		})
	}
}

func TestTranslationCompilesExpandedImmediateOnEveryArchitecture(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		arch   Arch
		goarch string
		triple string
		body   string
		ret    LLVMType
		size   int
	}{
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu", "MOVQ $PRESENT, AX\nMOVQ AX, ret+0(FP)\nRET", I64, 8},
		{ArchAMD64, "386", "i386-unknown-linux-gnu", "MOVL $PRESENT, AX\nMOVL AX, ret+0(FP)\nRET", I32, 4},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "MOVD $PRESENT, R0\nMOVD R0, ret+0(FP)\nRET", I64, 8},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", "MOVW $PRESENT, R0\nMOVW R0, ret+0(FP)\nRET", I32, 4},
		{ArchWASM, "wasm", "wasm32-unknown-unknown", "I64Const $PRESENT\nReturn", I64, 8},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			source := fmt.Sprintf("#define PRESENT (16+17)\nTEXT known(SB),$0-%d\n%s\n", target.size, target.body)
			file, err := Parse(target.arch, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"known": {Name: "known", Ret: target.ret, Frame: FrameLayout{
					Results: []FrameSlot{{Offset: 0, Type: target.ret, Index: 0, Field: -1}},
				}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, string(target.ret)+" 33") {
				t.Fatalf("expanded constant 33 missing from translated semantics:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "known.ll", "known.o", ir)
		})
	}
}
