package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestARM64NativeTargetPreflightComposesFamilyErrors(t *testing.T) {
	// Go independently rejects each malformed member. A different valid
	// native family must not hide it behind a missing/foreign target error.
	for _, pair := range [][2]string{
		{"SCVTFD R0,F0", "FCMPD F0,R0"},
		{"SCVTFD R0,F0", "MSR $1,FPCR"},
		{"FCMPD F0,F0", "MSR $1,FPSR"},
		{"FCMPD F0,F0", "WORD $0xffffffff"},
		{"FCMPD F0,F0", "FADDD F0,R0"},
		{"FADDD F0,F0", "MSR $1,FPCR"},
		{"FADDD F0,F0", "FMAXD F0,R0"},
		{"FMAXD F0,F0", "FADDD F0,R0"},
		{"FMAXD F0,F0", "MSR R0,RNDR"},
		{"MOVD RNDRRS,R0", "FMAXD F0,R0"},
	} {
		requireARM64GoAssemblerResult(t, "TEXT comparison(SB),4,$0-0\n"+pair[0]+"\nRET\n", true)
		if pair[1] != "WORD $0xffffffff" {
			requireARM64GoAssemblerResult(t, "TEXT comparison(SB),4,$0-0\n"+pair[1]+"\nRET\n", false)
		}
		for _, body := range []string{
			pair[0] + "\n" + pair[1], pair[1] + "\n" + pair[0],
			pair[0] + "\nRET\n" + pair[1],
		} {
			for _, target := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown", "aarch64-unknown-linux-gnu"} {
				for _, api := range []string{"text", "module", "Go", "public-module"} {
					t.Run(fmt.Sprintf("%s/%s/%s", api, target, body), func(t *testing.T) {
						present, err := arm64FPControlTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\n"+body+"\nRET\n", target)
						if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("cross-family malformed source hidden by target context: output=%t err=%v", present, err)
						}
					})
				}
			}
		}
	}
}
