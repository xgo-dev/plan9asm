package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerPackedSignExtendIndependentInitializedNamedRole(t *testing.T) {
	// This exact body was the old "signed not inherited" negative. With the
	// independently registered named SX family it is a valid initialized
	// program, not permission inherited from the still-disjoint ZX registry.
	const body = "VMOVUPS (DI),X0\nVPMOVSXBD X0,Y1\nVMOVSS X1,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	ins := x86ScalarLaneInstruction(t, "VPMOVSXBD X0,Y1")
	if _, known, _ := x86PackedZeroExtendProperties(ins, "amd64"); known || x86RawZeroExtendSource(ins, "amd64") {
		t.Fatal("genuine named SX silently entered the ZX membership or raw identity")
	}
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal("original complete initialized signed caller program rejected", err)
	}
}

func TestX86GoCallerPackedSignExtendPartialSignByteKnowledge(t *testing.T) {
	for _, ratio := range x86PackedSignExtendOracleRatios {
		for _, mode := range []string{"signed-known", "signed-missing", "zero-known-independent"} {
			t.Run(ratio.suffix+"/"+mode, func(t *testing.T) {
				at, stem := ratio.input-1, "VPMOVSX"
				if mode != "signed-known" {
					at++ // Only an unrelated byte is available; the first lane's sign byte is absent.
				}
				if mode == "zero-known-independent" {
					stem = "VPMOVZX"
				}
				// Observe only the first lane's first extension byte. SX depends
				// on its actual last input byte even when lower bytes are absent;
				// ZX defines the same extension byte independently as zero.
				body := fmt.Sprintf("PINSRB $%d,AX,X0\n%s%s X0,X1\nPEXTRB $%d,X1,AX\nMOVL AX,(DX)", at, stem, ratio.suffix, ratio.input)
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
				if mode == "signed-missing" {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("a missing sign byte acquired a numerical caller result", err)
					}
				} else if err != nil {
					t.Fatal("independent selected sign/constant-zero byte control rejected", err)
				}
			})
		}
	}
}
