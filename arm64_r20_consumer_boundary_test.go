package plan9asm

import (
	"fmt"
	"testing"
)

// The source-frame route and the typed read-before-write route have different
// obligations. In particular, a format-only signature is not a numerical entry
// contract, and an incomplete large TEXT cannot supply an incoming R20 value.
func TestARM64R20ConsumerSeparatesProducerAndTypedSoftwareValues(t *testing.T) {
	word := FuncSig{
		Name: "value", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		},
	}
	for _, tc := range []struct {
		name, text, body            string
		sig                         FuncSig
		producer, required, checked bool
	}{
		{"large", "$496-16", "MOVD arg+0(FP),R20", word, true, true, true},
		{"small", "$224-16", "MOVD arg+0(FP),R20", word, false, false, true},
		{"zero", "$0-16", "MOVD arg+0(FP),R20", word, false, false, true},
		{"omitted_args", "$496", "MOVD 32(R20),R0", word, false, true, true},
		{"dynamic_large", "$2097152-16", "MOVD arg+0(FP),R20", word, false, false, true},
		{"nonleaf_software", "$496-16", "CALL callee(SB)\nMOVD arg+0(FP),R20", word, false, false, true},
		{"format_only", "$0-0", "MOVD R30,R20", FuncSig{Name: "value", Ret: Void}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, fmt.Sprintf("TEXT value(SB),4,%s\n%s\nRET\n", tc.text, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			if got := arm64SourceFrameR20(fn); got != tc.producer {
				t.Errorf("producer=%v, want %v", got, tc.producer)
			}
			if got := arm64SourceFrameR20Required(fn); got != tc.required {
				t.Errorf("frame-proof route=%v, want %v", got, tc.required)
			}
			if got := arm64SourceFrameR20Checked(fn, tc.sig, nil); got != tc.checked {
				t.Errorf("typed availability=%v, want %v", got, tc.checked)
			}
		})
	}
}

func TestARM64R20ConsumerTypedDynamicFrameDoesNotInventUnknownScratch(t *testing.T) {
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc Value(uint64) uint64\n")
	for _, frame := range []int{0, 8, 224, 496, 2 << 20} {
		for _, body := range []string{
			"MOVD R12,R20\nMOVD R20,ret+8(FP)",
			"MOVD R20,ret+8(FP)",
		} {
			t.Run(fmt.Sprintf("%d/%s", frame, body), func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$%d-16\n%s\nRET\n", frame, body)
				requireARM64GoAssemblerResult(t, source, true)
				arm64LargeFrameCheckAPIs(t, source, pkg, nil, true, false)
			})
		}
	}
}
