package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Native/source closure must supply every outgoing input byte and prove
// actual callee result writes. A declaration alone supplies neither fact.
func TestARM64NativeScratchSamePackageCallResults(t *testing.T) {
	for _, test := range []struct {
		name, leaf, before, after string
		context                   bool
	}{
		{"complete-result", "ADD $3,R1\nMOVD R1,ret+8(FP)", "MOVD R1,8(RSP)", "MOVD 16(RSP),R2", false},
		{"both-paths-result", "CBZ R1,other\nMOVD R1,ret+8(FP)\nB done\nother:\nMOVD $7,R2\nMOVD R2,ret+8(FP)\ndone:", "MOVD R1,8(RSP)", "MOVD 16(RSP),R2", false},
		{"missing-result", "ADD $3,R1", "MOVD R1,8(RSP)", "MOVD 16(RSP),R2", true},
		{"partial-result", "MOVW R1,ret+8(FP)", "MOVD R1,8(RSP)", "MOVD 16(RSP),R2", true},
		{"one-path-result", "CBZ R1,done\nMOVD R1,ret+8(FP)\ndone:", "MOVD R1,8(RSP)", "MOVD 16(RSP),R2", true},
		{"missing-input", "MOVD R1,ret+8(FP)", "", "MOVD 16(RSP),R2", true},
		{"partial-input", "MOVD R1,ret+8(FP)", "MOVW R1,8(RSP)", "MOVD 16(RSP),R2", true},
		{"unbound-postcall-register", "MOVD R1,ret+8(FP)", "MOVD R1,8(RSP)", "MOVD R1,R2", true},
		{"stale-postcall-local", "MOVD R1,ret+8(FP)", "MOVD R1,8(RSP)\nMOVD R1,24(RSP)", "MOVD 24(RSP),R2", true},
		{"native-entry-register", "MOVD R6,ret+8(FP)", "MOVD R1,8(RSP)", "MOVD 16(RSP),R2", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := "TEXT ·Value(SB),4,$32-16\nMOVD n+0(FP),R1\n" + test.before +
				"\nCALL ·Leaf(SB)\n" + test.after + "\nMOVD R2,ret+8(FP)\nRET\n"
			leaf := "TEXT ·Leaf(SB),4,$0-16\nMOVD n+0(FP),R1\n" + test.leaf + "\nRET\n"
			assembly := arm64ScratchSelectedSource[:strings.Index(arm64ScratchSelectedSource, "TEXT ·Value")] + value + leaf
			_, pkg, file, options, source := arm64ScratchActualBoundSourceWithPackage(t,
				"linux", "aarch64-unknown-linux-gnu", assembly, "example.invalid/scratchfixture", "func Leaf(n uint64) uint64\n")
			_, closed := source.closed[pkg.Path+".Value"]
			t.Logf("actual complete source/native call closure=%v; expected Context=%v", closed, test.context)
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ScratchSourceAPIWithAssembly(t, pkg, file, options, api, assembly)
					if test.context {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("unproved native input/result acquired scratch admission: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatalf("actual complete native/source tuple did not close: %v", err)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, options.TargetTriple, "closed.ll", "closed.o", ir)
				})
			}
		})
	}
}

func TestARM64NativeScratchSamePackageCallByteWidths(t *testing.T) {
	for _, test := range []struct{ typ, store, load string }{
		{"uint8", "MOVB", "MOVBU"},
		{"uint16", "MOVH", "MOVHU"},
		{"uint32", "MOVW", "MOVWU"},
		{"uint64", "MOVD", "MOVD"},
	} {
		t.Run(test.typ, func(t *testing.T) {
			body := fmt.Sprintf(`TEXT ·Value(SB),4,$24-16
MOVD n+0(FP),R1
MOVD R1,8(RSP)
CALL ·Leaf(SB)
%s 16(RSP),R2
MOVD R2,ret+8(FP)
RET
TEXT ·Leaf(SB),4,$0-16
MOVD n+0(FP),R1
%s R1,ret+8(FP)
RET
`, test.load, test.store)
			assembly := arm64ScratchSelectedSource[:strings.Index(arm64ScratchSelectedSource, "TEXT ·Value")] + body
			_, pkg, file, options, _ := arm64ScratchActualBoundSourceWithPackage(t,
				"linux", "aarch64-unknown-linux-gnu", assembly, "example.invalid/scratchfixture",
				"func Leaf(n uint64) "+test.typ+"\n")
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ScratchSourceAPIWithAssembly(t, pkg, file, options, api, assembly)
					if err != nil {
						t.Fatal(err)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, options.TargetTriple, "closed.ll", "closed.o", ir)
				})
			}
		})
	}
}
