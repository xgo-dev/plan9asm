package plan9asm

import (
	"strings"
	"testing"
)

const arm64PrefetchForms = `
TEXT prefetchforms(SB),$0-0
	PRFM (R0), PLDL1KEEP
	PRFM 8(R1), PLDL1STRM
	PRFM 16(R2), PLDL2KEEP
	PRFM 24(R3), PLDL2STRM
	PRFM 32(R4), PLDL3KEEP
	PRFM 40(R5), PLDL3STRM
	PRFM 48(R6), PLIL1KEEP
	PRFM 56(R7), PLIL1STRM
	PRFM 64(R8), PLIL2KEEP
	PRFM 72(R9), PLIL2STRM
	PRFM 80(R10), PLIL3KEEP
	PRFM 88(R11), PLIL3STRM
	PRFM 96(R12), PSTL1KEEP
	PRFM 104(R13), PSTL1STRM
	PRFM 112(R14), PSTL2KEEP
	PRFM 120(R15), PSTL2STRM
	PRFM 128(R16), PSTL3KEEP
	PRFM 136(R17), PSTL3STRM
	PRFM (RSP), $0
	// Go accepts ZR in this address position; encoding register 31 means SP.
	PRFM (ZR), $1
	// Go accepts every non-negative C_UOREG32K offset and the PRFM encoder
	// discards its low three bits rather than diagnosing offsets admitted by a
	// smaller compatible class.
	PRFM 1(R20), $31
	PRFM 8(R21), $30
	PRFM 4088(R22), PLDL1KEEP
	PRFM 8184(R23), PLDL1KEEP
	PRFM 16376(R24), PLDL1KEEP
	PRFM 32760(R19), PLDL1KEEP
	RET
`

func TestTranslateARM64PrefetchCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64PrefetchForms, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64PrefetchForms)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"prefetchforms": {Name: "prefetchforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, `asm sideeffect "prfm #`); got != 26 {
				t.Fatalf("ARM64 PRFM lowering emitted %d prefetch operations, want 26:\n%s", got, ll)
			}
			for _, want := range []string{
				`asm sideeffect "prfm #0, [$0, #0]"`,
				`asm sideeffect "prfm #13, [$0, #88]"`,
				`asm sideeffect "prfm #21, [$0, #136]"`,
				`asm sideeffect "prfm #31, [$0, #0]"`,
				`asm sideeffect "prfm #30, [$0, #8]"`,
				`asm sideeffect "prfm #0, [$0, #4088]"`,
				`asm sideeffect "prfm #0, [$0, #32760]"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 PRFM lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-prefetch.ll", "arm64-prefetch.o", ll)
		})
	}
}

func TestTranslateARM64PrefetchRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PRFM -8(R0), PLDL1KEEP",
		"PRFM 257(R0), PLDL1KEEP",
		"PRFM 505(R0), PLDL1KEEP",
		"PRFM 4097(R0), PLDL1KEEP",
		"PRFM 8191(R0), PLDL1KEEP",
		"PRFM 16381(R0), PLDL1KEEP",
		"PRFM 32761(R0), PLDL1KEEP",
		"PRFM 32768(R0), PLDL1KEEP",
		"PRFM (R0), PLDKEEP",
		"PRFM (R0), $32",
		"PRFM R0, PLDL1KEEP",
		"PRFM (R0)",
		"PRFM.P (R0), PLDL1KEEP",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's PRFM forms", instruction)
		}
	}
}
