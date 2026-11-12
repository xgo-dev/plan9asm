package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64GoInternalVectorDuplicateInvalidForms(t *testing.T) {
	for _, instruction := range []string{
		"VMOV R0,V0.D1", "VMOV R0,V0", "VMOV RSP,V0.B16",
		"VMOV F0,V0.B16", "VMOV.P R0,V0.B16", "VMOV.W R0,V0.B16",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT ·Pass<ABIInternal>(SB),4,$0-16\n" + instruction + "\nRET\n"
			// No ABI selector is needed to prove the invalid operand grammar.
			requireARM64GoAssemblerResult(t, strings.ReplaceAll(source, "<ABIInternal>", ""), false)
			pkg := mustGoPackage(t, "test/vectorinvalid", "package vectorinvalid\nfunc Pass(uint64) uint64\n")
			tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOARCH: "arm64"})
			if tr != nil {
				tr.Module.Dispose()
			}
			if err == nil {
				t.Fatalf("invalid Go VMOV form was accepted: %s", instruction)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64GoInternalNarrowVectorDuplicate(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range []struct {
		arrangement string
		bits, lanes int
	}{
		{"B8", 8, 8}, {"B16", 8, 16}, {"H4", 16, 4}, {"H8", 16, 8},
		{"S2", 32, 2}, {"S4", 32, 4}, {"D2", 64, 2},
	} {
		t.Run(tc.arrangement, func(t *testing.T) {
			const value = uint64(0x123456789abcdef0)
			low := value
			if tc.bits < 64 {
				low = 0
				mask := uint64(1)<<uint(tc.bits) - 1
				for shift := 0; shift < 64; shift += tc.bits {
					low |= value & mask << uint(shift)
				}
			}
			high := low
			if tc.bits*tc.lanes == 64 {
				high = 0
			}
			source := "TEXT ·Pass<ABIInternal>(SB),4,$0-24\nCALL ·Compute<ABIInternal>(SB)\nMOVD R0,R9\n" +
				"VMOV R9,V0." + tc.arrangement + "\nVMOV V0.D[0],R0\nVMOV V0.D[1],R1\nRET\n" +
				"TEXT ·Compute<ABIInternal>(SB),4,$0-16\nMOVD $0x123456789abcdef0,R0\nRET\n"
			decl := fmt.Sprintf("func Pass(uint64) (uint64,uint64)\nfunc Compute(uint64) uint%d\n", tc.bits)
			runARM64GoInternalOracle(t, source, "package main\n"+decl+fmt.Sprintf(`func main() {
  for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    lo,hi:=Pass(a)
    if lo!=%d || hi!=%d { panic("Go vector broadcast low-bit/upper-half mismatch") }
  }
}
`, low, high), len(runner) != 0)
			pkg := mustGoPackage(t, "test/vectorbits", "package vectorbits\n"+decl)
			translate := func(target string) string {
				tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Module.Dispose()
				return tr.Module.String()
			}
			for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
				compileLLVMToObject(t, llc, target, "vector-bits.ll", "vector-bits.o", translate(target))
			}
			shim := fmt.Sprintf(`define i64 @invoke(i64 %%a) {
  %%r = call { i64, i64 } @Pass(i64 %%a)
  %%lo = extractvalue { i64, i64 } %%r, 0
  %%hi = extractvalue { i64, i64 } %%r, 1
  %%oklo = icmp eq i64 %%lo, %d
  %%okhi = icmp eq i64 %%hi, %d
  %%ok = and i1 %%oklo, %%okhi
  %%n = zext i1 %%ok to i64
  ret i64 %%n
}
`, low, high)
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "vector_bits", triple, translate(triple)+shim, `#include <stdint.h>
extern uint64_t invoke(uint64_t);
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) if (invoke(inputs[i])!=1) return 1;
  return 0;
}
`, runner)
		})
	}
}
