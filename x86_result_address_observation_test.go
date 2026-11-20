package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86AddressObservationWholeSource(t *testing.T) {
	const declaration = "func view(p,q *byte,n uintptr) uint32\n"
	for _, target := range []struct {
		arch, triple, suffix string
		word                 int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", "Q", 8},
		{"386", "i386-unknown-linux-gnu", "L", 4},
	} {
		loads := fmt.Sprintf("MOV%s p+0(FP),SI\nMOV%s q+%d(FP),DI\nMOV%s n+%d(FP),BX\n",
			target.suffix, target.suffix, target.word, target.suffix, 2*target.word)
		delta := fmt.Sprintf("MOV%s DI,CX\nSUB%s SI,CX\n", target.suffix, target.suffix)
		for _, row := range []struct{ name, producer, observer string }{
			{"distance", delta, "CMP" + target.suffix + " CX,BX"},
			{"alignment", "MOVL SI,CX\nORL DI,CX\n", "TESTL $7,CX"},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				body := loads + row.producer + row.observer + `
JNE zero
MOVL $7,CX
JMP join
zero:
MOVL $0,CX
join:
MOVL CX,X0
PEXTRD $0,X0,AX
MOVL AX,ret+RESULT(FP)`
				source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s: initialized address observation unavailable to FLAGS: %v", api, err)
					}
					x86NumericNativeAddressObject(t, ir, target.triple)
					escape := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration,
						loads+row.producer+"MOVL CX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+RESULT(FP)")
					if ir, err := x86ScalarFPBitViewAPI(t, escape, declaration, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s: address observation became numerical register bytes: %v", api, err)
					}
				}
			})
		}
	}
}
