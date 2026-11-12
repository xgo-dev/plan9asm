package plan9asm

import (
	"errors"
	"testing"
)

func TestARM64ScalarBinaryIllegalWordPrecedesNativeContext(t *testing.T) {
	for _, api := range []string{"text", "module", "owned-module", "Go"} {
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
			for _, invalid := range []string{"WORD $0xffffffff", "WORD $(0.0)"} {
				for _, body := range []string{
					invalid + "\nFADDS F0,F1", "FADDS F0,F1\n" + invalid,
					"RET\n" + invalid + "\nFADDS F0,F1", "FADDS F0,F1\nRET\n" + invalid,
				} {
					present, err := arm64BinaryTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\n"+body+"\nRET\n", triple)
					if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %q malformed WORD became output/context: %t %v\n%s", api, triple, present, err, body)
					}
				}
			}
			present, err := arm64BinaryTargetAPI(t, api,
				"TEXT comparison(SB),4,$0-0\nWORD $0xd503201f\nFADDS F0,F1\nRET\n", triple)
			if triple == "aarch64-unknown-linux-gnu" {
				if !present || err != nil {
					t.Fatalf("%s valid raw neighbor lost native translation: %v", api, err)
				}
			} else if present || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s valid raw neighbor changed native target requirement: %t %v", api, present, err)
			}
		}
	}
}
