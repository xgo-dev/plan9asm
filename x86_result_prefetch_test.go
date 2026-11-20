package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86LegacyPrefetchCompleteTypedFlow(t *testing.T) {
	const declaration = "func view(p *byte, n uintptr) uint32\n"
	for _, target := range []struct {
		arch, triple, suffix string
		word                 int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", "Q", 8},
		{"386", "i386-unknown-linux-gnu", "L", 4},
	} {
		for _, op := range []string{"PREFETCHNTA", "PREFETCHT0", "PREFETCHT1", "PREFETCHT2"} {
			t.Run(target.arch+"/"+op, func(t *testing.T) {
				body := fmt.Sprintf("MOV%s p+0(FP),DI\nMOV%s n+%d(FP),CX\n", target.suffix, target.suffix, target.word)
				body += op + " -32(DI)(CX*1)\n"
				body += "TEST" + target.suffix + " $15,DI\nJNE done\nMOVL $0,CX\ndone:\n"
				body += "MOVBLZX (DI)(CX*1),AX\nMOVL AX,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+RESULT(FP)"
				source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatalf("%s: cache hint interrupted an initialized address and its follow-on access: %v", api, err)
					}
					x86NumericNativeAddressObject(t, ir, target.triple)
				}
			})
		}
	}
}
