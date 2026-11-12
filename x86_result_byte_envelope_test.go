package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ABI0ResultInitializationCompleteStateByteEnvelope(t *testing.T) {
	// 1944 FP bytes + 16 AUTO bytes + (16 GP + 16 canonical GP + 256 Z +
	// 8 native MMX + 8 K + 1 flags + 16 pointer + 16 caller-address identities + 32 origin
	// IDs + 2 scan-pending + 3 predicate + 1 DF + 1 string counter +
	// 1 shape discriminator + 2 adjacent LEA + 12 adjacent shift observation bytes) is the logical payload
	// bytes. Every vector bank now tracks all 64 byte-definedness bits; the
	// redundant representation of its low-X bits is not another logical value.
	// A linear CFG pays its source scan and
	// eight conservative copy/join units for each visited instruction. This
	// tests the logical work envelope, not Go's actual heap allocation size.
	const payloadBytes = 1944 + 16 + x86IndependentResultBasePayload
	const workLimit = 64 << 20
	const lastLinear = workLimit / (9 * payloadBytes)
	const lastSource = workLimit / (8 * payloadBytes)
	for _, count := range []int{lastLinear, lastLinear + 1, 3609, lastSource, lastSource + 1} {
		for _, target := range x86RawReturnTargets {
			t.Run(fmt.Sprintf("%d/%s", count, target.triple), func(t *testing.T) {
				body := "MOVL $1,AX\nMOVL AX,spill-4(SP)\n" +
					"MOVL AX,ret0+1936(FP)\nMOVL AX,ret0+1940(FP)\n" +
					strings.Repeat("NOP\n", count-5) + "RET"
				_, _, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x [1936]byte) uint64", body)
				source = strings.Replace(source, ",$0-", ",$16-", 1)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				t.Logf("actual complete-envelope source object: %+v", receipt)
				if sig.Frame.Results[0].Offset != 1936 || file.Funcs[0].ArgSize != 1944 || len(file.Funcs[0].Instrs) != count+1 {
					t.Fatal("actual typed source dimensions changed")
				}
				for _, query := range []struct {
					name string
					run  func(Func, FuncSig, string) error
				}{
					{"public", CheckX86ABI0ResultInitialization},
					{"private-scalar-views", checkX86ScalarFPResultInitialization},
				} {
					err := query.run(file.Funcs[0], sig, target.arch)
					if count == lastLinear {
						if err != nil {
							t.Errorf("%s rejected a bounded complete payload: %v", query.name, err)
						}
					} else {
						phase := "must-defined"
						if count > lastSource {
							phase = "source-CFG"
						}
						if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), phase+" byte budget exhausted") {
							t.Errorf("%s undercounted the complete numerical/pointer state at %s: %v", query.name, phase, err)
						}
					}
				}
			})
		}
	}
}
