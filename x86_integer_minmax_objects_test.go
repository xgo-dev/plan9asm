package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86IntegerMinMaxCompleteObjectTarget(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("integer min/max objects require LLVM22")
	}
	// All physical mode32 mask forms have low banks and the same original
	// bytes. Observe them with amd64's four-operand frontend, then independently
	// assemble the complete mode32 BYTE program, not a fictitious named row.
	physicalRows := x86IntegerMinMaxIndependentRows("amd64")
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(physicalRows, "\n")+"\nRET")
	if len(pcs) != len(physicalRows)+1 || code[len(code)-1] != 0xc3 {
		t.Fatal("incomplete independent original instruction byte boundaries")
	}
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	for _, raw := range []bool{false, true} {
		rows := x86IntegerMinMaxIndependentRows(arch)
		if raw {
			rows = physicalRows
		}
		for start := 0; start < len(rows); start += 48 {
			end := start + 48
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("raw-%t/batch-%04d", raw, start), func(t *testing.T) {
				var source, declarations strings.Builder
				for index := start; index < end; index++ {
					name := fmt.Sprint("MinMax", index)
					fmt.Fprintf(&declarations, "func %s(p *[64]byte) uint32\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),SI\n"+
						"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nMOVL $85,CX\nKMOVD CX,K1\n",
						name, word+4, move)
					if raw {
						for _, value := range code[pcs[index]:pcs[index+1]] {
							fmt.Fprintf(&source, "BYTE $%d\n", value)
						}
					} else {
						source.WriteString(rows[index] + "\n")
					}
					fmt.Fprintf(&source, "VPEXTRD $0,X2,CX\nMOVL CX,ret+%d(FP)\nRET\n", word)
				}
				x86LEAActualTargetGoObject(t, arch, triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete initialized named/raw family rejected", err)
						}
						optimized := x86DwordProductIROptimize(t, ir)
						for _, pipeline := range []struct{ ir, level string }{
							{ir, "-O0"}, {ir, "-O2"}, {optimized, "-O2"},
						} {
							x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
						}
					})
				}
			})
		}
	}
}

func TestX86IntegerMinMaxObjectsLinux386(t *testing.T) {
	x86IntegerMinMaxCompleteObjectTarget(t, "386", "i386-unknown-linux-gnu")
}

func TestX86IntegerMinMaxObjectsWindows386(t *testing.T) {
	x86IntegerMinMaxCompleteObjectTarget(t, "386", "i686-pc-windows-msvc")
}

func TestX86IntegerMinMaxObjectsLinuxAMD64(t *testing.T) {
	x86IntegerMinMaxCompleteObjectTarget(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86IntegerMinMaxObjectsDarwinAMD64(t *testing.T) {
	x86IntegerMinMaxCompleteObjectTarget(t, "amd64", "x86_64-apple-darwin")
}

func TestX86IntegerMinMaxObjectsWindowsAMD64(t *testing.T) {
	x86IntegerMinMaxCompleteObjectTarget(t, "amd64", "x86_64-pc-windows-msvc")
}
