package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestGoAMD64FrameSourceConditionalMacrosMatchActualObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for targetIndex, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		for _, profile := range []string{"v1", "v2", "v3", "v4"} {
			t.Run(target+"/"+profile, func(t *testing.T) {
				pkg, request := goAMD64FrameSourceFixture(t)
				request.Target = target
				request.Environment = append(request.Environment, "GOAMD64="+profile)
				assembly := filepath.Join(request.Directory, request.AssemblyFile)
				original, err := os.ReadFile(assembly)
				if err != nil {
					t.Fatal(err)
				}
				header := `#ifndef PROFILE_GUARD
#define PROFILE_GUARD
#ifdef GOAMD64_v2
#define PROFILE_VALUE 7
#else
#define PROFILE_VALUE 11
#endif
#ifdef GOOS_linux
#define TARGET_VALUE 1
#else
#ifdef GOOS_darwin
#define TARGET_VALUE 2
#else
#define TARGET_VALUE 3
#endif
#endif
#endif
`
				headerFile := filepath.Join(request.Directory, "profile.h")
				if err := os.WriteFile(headerFile, []byte(header), 0600); err != nil {
					t.Fatal(err)
				}
				prefix := `#include "profile.h"
#include "profile.h"
#ifdef UNDEFINED_EXTERNAL_MACRO
#include "missing_generated.h"
#endif
`
				text := prefix + strings.Replace(string(original), "MOVQ AX,ret+8(FP)", "MOVQ $(PROFILE_VALUE+TARGET_VALUE),AX\nMOVQ AX,ret+8(FP)", 1)
				if err := os.WriteFile(assembly, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				source := requireGoAMD64FrameCapture(t, pkg, request)
				function, found := source.functions[pkg.Path+".Value"]
				if !found {
					t.Fatal("complete original function is missing")
				}
				want := int64(11 + targetIndex + 1)
				if profile == "v2" {
					want -= 4
				}
				matched := 0
				for code := function.code; len(code) != 0; {
					instruction, err := x86asm.Decode(code, 64)
					if err != nil || instruction.Len == 0 {
						t.Fatal("decode actual conditional Go object", err)
					}
					_, immediate := instruction.Args[1].(x86asm.Imm)
					// Current Go encodes these small MOVQ constants as a
					// zero-extending EAX write; Go 1.20 retains RAX's prefix.
					valueRegister := instruction.Args[0] == x86asm.RAX || instruction.Args[0] == x86asm.EAX
					if instruction.Op == x86asm.MOV && valueRegister && immediate {
						if instruction.Args[1] != x86asm.Imm(want) {
							t.Fatal("conditional branch differs from independent profile/target", instruction, want)
						}
						matched++
					}
					code = code[instruction.Len:]
				}
				if matched != 1 {
					t.Fatal("missing or repeated independently observed conditional result", matched)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				expanded, err := source.preprocess(request.AssemblyFile, []byte(text))
				if err != nil {
					t.Fatal(err)
				}
				file, err := Parse(ArchAMD64, expanded)
				if err != nil {
					t.Fatal(err)
				}
				triple := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}[targetIndex]
				options := Options{Goarch: "amd64", TargetTriple: triple,
					ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
					Sigs:       map[string]FuncSig{function.signature.Name: function.signature},
				}
				bound, err := source.BindFixedLocal(ctx, pkg, file, options)
				if err != nil {
					t.Fatal(err)
				}
				fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, triple, "conditional.ll", "conditional.o", ir)
					compileLLVMToObject(t, llc, triple, "conditional-opt.ll", "conditional-opt.o", x86MulDivRoundOptimize(t, ir))
				})
				if err := source.Verify(ctx); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(headerFile, []byte(header+"// late mutation\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := source.Verify(ctx); err == nil {
					t.Fatal("changed conditional header retained source authority")
				}
				if err := os.WriteFile(headerFile, []byte(header), 0600); err != nil {
					t.Fatal(err)
				}
				if err := source.Verify(ctx); err == nil {
					t.Fatal("restored header revived a revoked observation")
				}
				t.Logf("actual %s/%s selected MOVQ $%d,AX", target, profile, want)
			})
		}
	}
}

func TestGoAMD64FrameSourceConditionalMacrosGrantNoNumericEffects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, operand := range []string{"$7", "R11"} {
		t.Run(operand, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			name := filepath.Join(request.Directory, request.AssemblyFile)
			text, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			// Retain the original ADDQ $7 source as a positive now that its
			// typed family is implemented. Macro selection still cannot supply
			// the missing numerical bytes of an uninitialized register.
			body := "#ifdef GOARCH_amd64\n" + strings.Replace(string(text), "MOVQ AX,ret+8(FP)",
				"ADDQ "+operand+",AX\nMOVQ AX,ret+8(FP)", 1) + "#endif\n"
			if err := os.WriteFile(name, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			source := requireGoAMD64FrameCapture(t, pkg, request)
			expanded, err := source.preprocess(request.AssemblyFile, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			sig := source.functions[pkg.Path+".Value"].signature
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
				Sigs:       map[string]FuncSig{sig.Name: sig},
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if operand == "R11" {
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "ADDQ") {
					t.Fatal("macro selection supplied missing ADDQ input bytes", err)
				}
				return
			}
			if err != nil {
				t.Fatal("initialized ADDQ frame binding failed", err)
			}
			ir, err := Translate(file, bound)
			if err != nil || ir == "" {
				t.Fatal("original initialized ADDQ lost its independently bound translation", err)
			}
		})
	}
}

func TestGoAMD64FrameSourceCPPRequiresActualRegistration(t *testing.T) {
	source := newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: t.TempDir()})
	source.env = map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v2"}
	if _, err := source.preprocess("value.s", []byte("#ifdef GOAMD64_v2\nTEXT value(SB),4,$0-0\nRET\n#endif\n")); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("environment strings impersonated registered actual macro sources", err)
	}
}
