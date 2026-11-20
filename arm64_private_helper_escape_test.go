package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func requireARM64PrivateHelperContext(t *testing.T, source string, keep func(string, string) bool) {
	t.Helper()
	pkg := mustGoPackage(t, "test/review", "package review\nfunc Run(uint64) uint64\nfunc Escape()\n")
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
		"aarch64-unknown-linux-musl",
	} {
		ctx := llvm.NewContext()
		tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple,
			ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") },
			KeepFunc:   keep,
		})
		if tr != nil {
			tr.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s lacks a complete private continuation contract: %v", triple, err)
		}
	}
}

func TestARM64PrivateHelperPlatform18NeedsContext(t *testing.T) {
	base := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)")
	for _, instruction := range []string{
		"MOVD $42,R18_PLATFORM", "MOVW $42,R18_PLATFORM",
		"MOVD R18_PLATFORM,R20", "ADD $1,R18_PLATFORM,R20",
	} {
		for _, site := range []string{"helper", "caller"} {
			t.Run(site+"/"+instruction, func(t *testing.T) {
				anchor := "ADC $0,R9,R20"
				if site == "caller" {
					anchor = "MOVD $291,R0"
				}
				source := strings.Replace(base, anchor, instruction+"\n"+anchor, 1)
				requireARM64GoAssemblerResult(t, source, true)
				requireARM64PrivateHelperContext(t, source, nil)
			})
		}
	}
	for _, instruction := range []string{
		"MOVD (R18_PLATFORM),R3", "MOVD R3,(R18_PLATFORM)",
		"MOVD $0(R18_PLATFORM),R3", "ADD R18_PLATFORM<<1,R3,R3",
	} {
		t.Run("caller-address-or-shift/"+instruction, func(t *testing.T) {
			source := strings.Replace(base, "MOVD $291,R0", instruction+"\nMOVD $291,R0", 1)
			requireARM64GoAssemblerResult(t, source, true)
			requireARM64PrivateHelperContext(t, source, nil)
		})
	}
	for _, name := range []string{"R18_PLATFORM", "R18", "W18"} {
		reg, ok := parseReg(name)
		if !ok || reg != "R18" || arm64PrivateDataGP(reg) {
			t.Errorf("physical platform register %s lost its constraint: %q, %v", name, reg, ok)
		}
	}
}

func TestARM64PrivateHelperHidden26EntryIsNotGuessed(t *testing.T) {
	source := strings.Replace(arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)"), "ADC $0,R9,R20", "MOVD R26,R20", 1)
	requireARM64GoAssemblerResult(t, source, true)
	requireARM64PrivateHelperContext(t, source, nil)
}

func TestARM64PrivateHelperEscapeSourceAudit(t *testing.T) {
	base := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)")
	for _, test := range []struct {
		name, suffix string
		goRejected   bool
	}{
		{"pc-escape", "TEXT ·Escape(SB),4,$0-0\nADR -3(PC),R0\nRET\n", false},
		// Go diagnoses and then panics for this out-of-TEXT branch. Its
		// separate defect observation is not a source-rejection proof.
		{"pc-branch", "TEXT ·Escape(SB),4,$0-0\nB -3(PC)\n", true},
		{"raw-layout", "TEXT ·Escape(SB),4,$0-0\nWORD $0x17ffffff\nRET\n", false},
		{"raw-doubleword-layout", "TEXT ·Escape(SB),4,$0-0\nDWORD $0x17ffffff\nRET\n", false},
		{"pc-alignment", "TEXT ·Escape(SB),4,$0-0\nPCALIGN $16\nRET\n", false},
		{"local-code-address", "TEXT ·Escape(SB),4,$0-0\nADR done,R0\ndone:\nRET\n", false},
		{"mem-sym-read", "TEXT ·Escape(SB),4,$0-0\nMOVD mix<>(SB)(R3),R0\nRET\n", false},
		{"mem-sym-offset", "TEXT ·Escape(SB),4,$0-0\nMOVD mix<>+4(SB)(R3),R0\nRET\n", false},
		{"mem-sym-write", "TEXT ·Escape(SB),4,$0-0\nMOVD R0,mix<>(SB)(R3)\nRET\n", false},
		{"indexed-symbol-address", "TEXT ·Escape(SB),4,$0-0\nMOVD $mix<>(SB)(R3),R0\nRET\n", false},
		{"symbol-address", "TEXT ·Escape(SB),4,$0-0\nMOVD $mix<>(SB),R0\nRET\n", false},
		{"data-symbol-alias", "DATA mix<>+0(SB)/8,$0\n", false},
		{"data-relocation", "DATA saved<>+0(SB)/8,$mix<>(SB)\nGLOBL saved<>(SB),8,$8\n", false},
		// Go rejects the redeclared symbol, but a directly parsed File must
		// still not invent a closed helper when it contains this collision.
		{"globl-symbol-alias", "GLOBL mix<>(SB),8,$8\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := base + test.suffix
			if test.name != "pc-branch" {
				requireARM64GoAssemblerResult(t, source, !test.goRejected)
			}
			requireARM64PrivateHelperContext(t, source, func(text, _ string) bool {
				return text == "·Run" || text == "mix<>"
			})
		})
	}
}
