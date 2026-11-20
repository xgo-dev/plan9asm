//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Reuse the existing element-granular protection oracle for stores. A zero
// mask must not read old destination bytes; inactive output elements must not
// be accessed. This executes portable IR, not original AVX512 instructions.
func TestX86SingleSourceNarrowingMaskedStoreActiveLaneFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("masked narrowing stores require LLVM22 llc/clang")
	}
	var source, declarations, prototypes, metadata strings.Builder
	count := 0
	for _, op := range x86SingleSourceNarrowingTestNames() {
		inputBits, outputBits := x86SingleSourceNarrowTestBits(op)
		for index, bank := range []string{"X", "Y", "Z"} {
			width := 16 << index
			lanes := width * 8 / inputBits
			name := fmt.Sprintf("NarrowStore%d", count)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\n"+
				"MOVQ mask+8(FP),CX\nKMOVQ CX,K1\nVPXORD Z0,Z0,Z0\n%s %s0,K1,(AX)\nRET\n", name, op, bank)
			fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint64_t);\n", name)
			fmt.Fprintf(&metadata, "{%s,%d,%d,%d},\n", name, lanes*outputBits/8, outputBits/8, lanes)
			count++
		}
	}
	if count != 54 {
		t.Fatal("masked store lost a family member or physical source width", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := x86E4DeadReadFaultOracle(prototypes.String(), metadata.String())
	// The shared oracle's last check supplies a read-only page. Every active
	// store must fault there, while its original read owners expect success.
	// Keep those existing owners and their driver bytes completely unchanged.
	readOnlyCheck := "if(fault(rows[r].run,p+page-rows[r].extent,UINT64_MAX)) return 1;"
	if strings.Count(driver, readOnlyCheck) != 1 {
		t.Fatal("shared protection oracle no longer exposes one read-only control")
	}
	driver = strings.Replace(driver, readOnlyCheck,
		"if(fault(rows[r].run,p+page-rows[r].extent,UINT64_MAX)!=1) return 1;", 1)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("initialized masked-store source rejected before fault observation", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "narrow-masked-store", triple, ir, driver)
		})
	}
}
