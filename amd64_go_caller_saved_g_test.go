package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86GoCallerPrivateSavedGOriginalRawPushPop(t *testing.T) {
	for _, form := range []struct{ name, body string }{
		// The original dot_byte_256 / hamming_512 two-byte raw words.
		{"original raw", "WORD $0x5641\nMOVL $7,R14\nMOVL R14,AX\nWORD $0x5e41"},
		{"named", "PUSHQ R14\nMOVL $7,R14\nMOVL R14,AX\nPOPQ R14"},
		{"nested numerical", "PUSHQ R14\nMOVQ $19,R14\nPUSHQ R14\nMOVL $7,R14\nPOPQ R14\nMOVL R14,AX\nPOPQ R14"},
		{"nested original", "PUSHQ R14\nPUSHQ R14\nMOVL $7,R14\nPOPQ R14\nPOPQ R14\nMOVL $7,AX"},
		{"defined byte", "PUSHQ R14\nMOVL $0,AX\nMOVB $7,R14\nMOVB R14,AX\nPOPQ R14"},
		{"defined word", "PUSHQ R14\nMOVL $0,AX\nMOVW $7,R14\nMOVW R14,AX\nPOPQ R14"},
		{"defined zero", "PUSHQ R14\nXORQ R14,R14\nMOVL R14,AX\nPOPQ R14"},
		{"actual caller pointer", "PUSHQ R14\nMOVQ DI,R14\nMOVL (R14),AX\nPOPQ R14"},
		{"identical joins", "PUSHQ R14\nMOVL $7,R14\nCMPQ R14,$0\nJE joined\nMOVL $7,R14\njoined:\nMOVL R14,AX\nPOPQ R14"},
		{"both CFG arms restore", "WORD $0x5641\nMOVL $7,R14\nCMPQ R14,$0\nJE other\nWORD $0x5e41\nJMP joined\nother:\nWORD $0x5e41\njoined:\nMOVL $7,AX"},
	} {
		t.Run(form.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX", form.body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestX86GoCallerPrivateSavedGDoesNotExposeOpaqueIdentity(t *testing.T) {
	for _, form := range []struct{ name, body string }{
		{"entry number", "MOVL R14,AX"},
		{"entry address", "MOVL (R14),AX"},
		{"entry flags", "CMPQ R14,$0\nMOVL $7,AX"},
		{"no restoration", "MOVL $7,R14\nMOVL R14,AX"},
		{"zero is not g", "XORQ R14,R14\nMOVL R14,AX"},
		{"saved then discarded", "PUSHQ R14\nMOVL $7,R14\nMOVL R14,AX\nADDQ $8,SP"},
		{"saved token to ordinary GP", "PUSHQ R14\nPOPQ BX\nMOVL $7,AX"},
		{"restored token read", "PUSHQ R14\nMOVL $7,R14\nPOPQ R14\nMOVL R14,AX"},
		{"restored token address", "PUSHQ R14\nMOVQ DI,R14\nPOPQ R14\nMOVL (R14),AX"},
		{"narrow original save", "PUSHW R14\nMOVW $7,R14\nMOVW R14,AX\nPOPW R14"},
		{"narrow restoration", "PUSHQ R14\nMOVL $7,R14\nMOVL R14,AX\nPOPW R14\nADDQ $6,SP"},
		{"unknown upper numerical bytes", "PUSHQ R14\nMOVW $7,R14\nMOVQ R14,AX\nPOPQ R14"},
		{"byte copy cannot define full result", "PUSHQ R14\nMOVB $7,R14\nMOVB R14,AX\nPOPQ R14"},
		{"word copy cannot define full result", "PUSHQ R14\nMOVW $7,R14\nMOVW R14,AX\nPOPQ R14"},
		{"opaque saved stack read", "PUSHQ R14\nMOVQ 0(SP),AX\nPOPQ R14"},
		{"opaque saved stack overwrite", "PUSHQ R14\nMOVQ $0,0(SP)\nPOPQ R14\nMOVL $7,AX"},
		{"unknown native call", "PUSHQ R14\nCALL ·unknown(SB)\nPOPQ R14\nMOVL $7,AX"},
		{"one unbalanced CFG arm", "PUSHQ R14\nMOVL $7,R14\nCMPQ R14,$0\nJE joined\nPOPQ R14\njoined:\nMOVL $7,AX"},
		{"one CFG arm loses g", "WORD $0x5641\nMOVL $7,R14\nCMPQ R14,$0\nJE other\nWORD $0x5e41\nJMP joined\nother:\nADDQ $8,SP\njoined:\nMOVL $7,AX"},
		{"g is not the input pointer", "PUSHQ R14\nMOVQ DI,R14\nMOVQ R14,(DX)\nPOPQ R14\nMOVL $7,AX"},
	} {
		t.Run(form.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX", form.body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("opaque or unrestored g acquired source continuation: %v", err)
			}
		})
	}
}

func TestX86GoCallerPrivateSavedGRequiresActualCallerSelection(t *testing.T) {
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX",
		"PUSHQ R14\nMOVL $7,R14\nMOVL R14,AX\nPOPQ R14", 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	pkg.SourceSelection = nil
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("bare declaration acquired numerical g permission: %v", err)
	}
}

func TestX86GoCallerPrivateSavedGRejectsUnprovedLeafFallback(t *testing.T) {
	for _, body := range []string{
		"MOVQ R14,AX",
		"MOVQ $7,R14\nMOVQ R14,AX",
		"XORQ R14,R14\nMOVQ R14,AX",
	} {
		t.Run(body, func(t *testing.T) {
			source, sig, pkg := x86SourceStackNumericalFixture("amd64",
				body+"\nMOVQ AX,ret+8(FP)\nBYTE $0xc3")
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := x86SourceStackOptions("amd64", "x86_64-unknown-linux-gnu", sig)
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("text API trusted unproved incoming/clobbered g: %v", err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if module != (llvm.Module{}) {
				module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("module API trusted unproved incoming/clobbered g: %v", err)
			}
			translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			})
			if translation != nil {
				translation.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("declaration API trusted unproved incoming/clobbered g: %v", err)
			}
		})
	}
}
