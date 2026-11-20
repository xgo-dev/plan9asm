package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A Go result declaration promises only its own bits. Native assembly can
// retain other bits in the physical register; zero-extending a typed LLVM
// result must not pretend that those extra native bits were transferred.
func TestCrossLinuxRuntimeMatrixARM64GoInternalNarrowResultHighBits(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	for _, bits := range []int{8, 16, 32} {
		for _, copy := range []bool{false, true} {
			t.Run(fmt.Sprintf("uint%d/copy_%t", bits, copy), func(t *testing.T) {
				body := ""
				if copy {
					body = "MOVD R0,R9\nMOVD R9,R0\n"
				}
				source := "TEXT ·Pass<ABIInternal>(SB),4,$0-16\nCALL ·Compute<ABIInternal>(SB)\n" + body + "RET\n" +
					"TEXT ·Compute<ABIInternal>(SB),4,$0-16\nMOVD $0x123456789abcdef0,R0\nRET\n"
				decl := fmt.Sprintf("func Pass(uint64) uint64\nfunc Compute(uint64) uint%d\n", bits)
				runARM64GoInternalOracle(t, source, "package main\n"+decl+`func main() {
  for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    if Pass(a)!=0x123456789abcdef0 { panic("actual Go narrow result retains unspecified high bits") }
  }
}
`, len(runner) != 0)
				pkg := mustGoPackage(t, "test/narrowresult", "package narrowresult\n"+decl)
				for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
					tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
						GOARCH: "arm64", TargetTriple: target,
						ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
					})
					if tr != nil {
						tr.Module.Dispose()
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s: unspecified uint%d result high bits must require context: %v", target, bits, err)
					}
				}
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64GoInternalNarrowResultConsumers(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const nativeBits = uint64(0x123456789abcdef0)
	for _, bits := range []int{8, 16, 32} {
		mask := uint64(1)<<uint(bits) - 1
		unsigned := nativeBits & mask
		signed := unsigned
		if signed&(uint64(1)<<uint(bits-1)) != 0 {
			signed |= ^mask
		}
		suffix := map[int]string{8: "B", 16: "H", 32: "W"}[bits]
		for _, tc := range []struct {
			name, body, result string
			want               uint64
		}{
			{"unsigned_extend", "UXT" + suffix + " R9,R0", "uint64", unsigned},
			{"signed_extend", "SXT" + suffix + " R9,R0", "uint64", signed},
			{"unsigned_move", "MOV" + suffix + "U R9,R0", "uint64", unsigned},
			{"signed_move", "MOV" + suffix + " R9,R0", "uint64", signed},
			{"bitfield_extract", fmt.Sprintf("UBFX $0,R9,$%d,R0", bits), "uint64", unsigned},
			{"bitfield_shifted_extract", fmt.Sprintf("UBFX $3,R9,$%d,R0", bits-3), "uint64", unsigned >> 3},
			{"bitfield_signed_extract", fmt.Sprintf("SBFX $0,R9,$%d,R0", bits), "uint64", signed},
			{"bitfield_insert", fmt.Sprintf("MOVD $-1,R0\nBFI $4,R9,$%d,R0", bits), "uint64", ^(mask << 4) | unsigned<<4},
			{"bitfield_low_insert", fmt.Sprintf("MOVD $-1,R0\nBFXIL $0,R9,$%d,R0", bits), "uint64", ^mask | unsigned},
			{"typed_narrow_return", "MOVD R9,R0", fmt.Sprintf("uint%d", bits), unsigned},
		} {
			t.Run(fmt.Sprintf("uint%d/%s", bits, tc.name), func(t *testing.T) {
				source := "TEXT ·Pass<ABIInternal>(SB),4,$0-16\nCALL ·Compute<ABIInternal>(SB)\nMOVD R0,R9\n" + tc.body + "\nRET\n" +
					"TEXT ·Compute<ABIInternal>(SB),4,$0-16\nMOVD $0x123456789abcdef0,R0\nRET\n"
				decl := fmt.Sprintf("func Pass(uint64) %s\nfunc Compute(uint64) uint%d\n", tc.result, bits)
				runARM64GoInternalOracle(t, source, "package main\n"+decl+fmt.Sprintf(`func main() {
  for _,a:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    if uint64(Pass(a))!=%d { panic("actual Go narrowed result consumer mismatch") }
  }
}
`, tc.want), len(runner) != 0)
				pkg := mustGoPackage(t, "test/narrowconsumer", "package narrowconsumer\n"+decl)
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
					compileLLVMToObject(t, llc, target, "narrow-consumer.ll", "narrow-consumer.o", translate(target))
				}
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "narrow_consumer", triple, translate(triple), fmt.Sprintf(`#include <stdint.h>
extern %s Pass(uint64_t);
int main(void) {
  uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) if ((uint64_t)Pass(inputs[i])!=UINT64_C(%d)) return 1;
  return 0;
}
`, map[string]string{"uint64": "uint64_t", "uint8": "uint8_t", "uint16": "uint16_t", "uint32": "uint32_t"}[tc.result], tc.want), runner)
			})
		}
	}
}

func TestARM64GoInternalNarrowMissingBitsContext(t *testing.T) {
	for _, bits := range []int{8, 16, 32} {
		for _, body := range []string{
			"ADD $1,R9,R0",
			fmt.Sprintf("UBFX $1,R9,$%d,R0", bits),
			fmt.Sprintf("BFI $4,R9,$%d,R0", bits), // old R0 high bits must be preserved
			"FMOVD R9,F0\nFMOVD F0,R0",
			"CBZ R9,done\ndone:\nMOVD $0,R0",
			"MOVD R9,(RSP)\nMOVD $0,R0", // a full-width memory write observes all bits
		} {
			t.Run(fmt.Sprintf("uint%d/%s", bits, body), func(t *testing.T) {
				source := "TEXT ·Pass<ABIInternal>(SB),4,$16-16\nCALL ·Compute<ABIInternal>(SB)\nMOVD R0,R9\n" + body + "\nRET\n"
				requireARM64GoABIInternalObject(t, source)
				pkg := mustGoPackage(t, "test/narrowmissing", fmt.Sprintf("package narrowmissing\nfunc Pass(uint64) uint64\nfunc Compute(uint64) uint%d\n", bits))
				for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
					tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
						GOARCH: "arm64", TargetTriple: target,
						ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
					})
					if tr != nil {
						tr.Module.Dispose()
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s: missing high bits must require context: %v", target, err)
					}
				}
			})
		}
	}
}
