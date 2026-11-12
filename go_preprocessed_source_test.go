package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestGoModulePreprocessedSourceDoesNotInventDefinitions(t *testing.T) {
	t.Setenv("GOAMD64", "v4")
	pkg := mustGoPackage(t, "example.com/preprocessed", "package preprocessed\nconst Value = 42\nfunc Read() uint64\n")
	for _, definition := range []struct {
		name, source, value string
	}{
		{"ambient feature", "GOAMD64_v4", "1"},
		{"unincluded generated constant", "const_Value", "42"},
	} {
		t.Run(definition.name, func(t *testing.T) {
			source := []byte("TEXT ·Read(SB),4,$0-8\nMOVQ $" + definition.source + ",AX\nMOVQ AX,ret+0(FP)\nRET\n")
			options := GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym: testResolveSym(pkg.Path)}
			// The default API keeps its historical expansion contract. It is
			// not the entry used by an independently preprocessed compiler.
			legacy, err := TranslateGoModule(pkg, source, options)
			if err != nil {
				t.Fatal("default GoModule expansion changed", err)
			}
			ir := legacy.Module.String()
			legacy.Module.Dispose()
			if !strings.Contains(ir, "i64 "+definition.value) {
				t.Fatal("default control did not expand its definition", ir)
			}
			options.SourcePreprocessed = true
			if result, err := TranslateGoModule(pkg, source, options); err == nil || result != nil {
				if result != nil {
					result.Module.Dispose()
				}
				t.Fatal("preprocessed source borrowed an ambient/generated definition", err)
			}
			resolved := []byte(strings.Replace(string(source), definition.source, definition.value, 1))
			result, err := TranslateGoModule(pkg, resolved, options)
			if err != nil {
				t.Fatal("complete independently expanded source rejected", err)
			}
			result.Module.Dispose()
		})
	}
}

func TestGoModulePreprocessedSourceRejectsResidualCPP(t *testing.T) {
	pkg := mustGoPackage(t, "example.com/preprocessed", "package preprocessed\nfunc Read() uint64\n")
	const body = "TEXT ·Read(SB),4,$0-8\nMOVQ $42,AX\nMOVQ AX,ret+0(FP)\nRET\n"
	for _, source := range []string{
		"#include \"missing.h\"\n" + body,
		"#define UNUSED 1\n" + body,
		"#ifdef GOARCH_amd64\n" + body + "#endif\n",
		"#line 1 \"other.s\"\n" + body,
	} {
		result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOOS: "linux", GOARCH: "amd64",
			TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path), SourcePreprocessed: true})
		if err == nil || result != nil {
			if result != nil {
				result.Module.Dispose()
			}
			t.Fatal("preprocessed input silently reprocessed a remaining directive", source, err)
		}
	}
}

func TestGoModulePreprocessedSourceCannotReplaceCapturedAuthorities(t *testing.T) {
	for _, authority := range []string{"numerical", "TLS", "ARM64 byte carrier", "mixed"} {
		t.Run(authority, func(t *testing.T) {
			options := GoModuleOptions{SourcePreprocessed: true,
				ResolveSym: func(string) string { t.Fatal("incompatible authority reached resolver"); return "" },
				KeepFunc:   func(string, string) bool { t.Fatal("incompatible authority reached filter"); return true },
				ManualSig: func(string) (FuncSig, bool) {
					t.Fatal("incompatible authority reached signature callback")
					return FuncSig{}, false
				}}
			if authority == "numerical" || authority == "mixed" {
				options.NumericalReads = new(GoX86NumericalReadBinding)
			}
			if authority == "TLS" || authority == "mixed" {
				options.X86TLSMoves = new(GoX86TLSMoveBinding)
			}
			if authority == "ARM64 byte carrier" || authority == "mixed" {
				options.ARM64ByteCarrierSource = new(GoARM64ByteCarrierSource)
			}
			result, err := TranslateGoModule(GoPackage{}, nil, options)
			if !errors.Is(err, ErrProbeNeedsContext) || result != nil {
				if result != nil {
					result.Module.Dispose()
				}
				t.Fatal("preprocessed flag replaced or consumed a captured source authority", result, err)
			}
		})
	}
}
