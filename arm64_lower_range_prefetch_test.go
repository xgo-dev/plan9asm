package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RangePrefetchCompleteGo127Family(t *testing.T) {
	source := `TEXT range_prefetch_forms(SB),$0-0
	RPRFM (R0), R30, PLDKEEP
	RPRFM (R1), R2, PSTKEEP
	RPRFM (R2), R3, PLDSTRM
	RPRFM (RSP), R4, PSTSTRM
	RPRFM (R5), R6, $0
	RPRFM (R7), R8, $63
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"range_prefetch_forms": {Name: "range_prefetch_forms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "rprfm #0, $1, [$0]"`,
				`asm sideeffect "rprfm #5, $1, [$0]"`,
				`asm sideeffect "rprfm #63, $1, [$0]"`,
				`"r,r,~{memory}"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ARM64 range-prefetch lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-range-prefetch.ll", "arm64-range-prefetch.o", ll)
		})
	}
}

func TestTranslateARM64RangePrefetchRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"RPRFM 8(R1), R2, PLDKEEP",
		"RPRFM (R1)(R2), R3, PLDKEEP",
		"RPRFM (R1), RZR, PLDKEEP",
		"RPRFM (R1), R2, PLDL1KEEP",
		"RPRFM (R1), R2, $-1",
		"RPRFM (R1), R2, $64",
		"RPRFM.Z (R1), R2, PLDKEEP",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badrangeprefetch(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badrangeprefetch": {Name: "badrangeprefetch", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's RPRFM forms", instruction)
			}
		})
	}
}
