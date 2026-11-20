package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneAMD64FixedLocalScalarSource(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	for _, width := range []string{"B", "W", "L", "Q"} {
		t.Run(width, func(t *testing.T) {
			var assembly strings.Builder
			assembly.WriteString("TEXT ·Value(SB),4,$64-16\nMOVQ a+0(FP),AX\nMOVQ AX,8(SP)\n")
			for _, operation := range []string{
				"MOV%s AX,8(SP)", "MOV%s 8(SP),AX", "MOV%s $1,8(SP)",
				"ADD%s $1,8(SP)", "XOR%s AX,8(SP)", "NOT%s 8(SP)",
				"ROL%s $1,8(SP)", "CMP%s 8(SP),AX",
			} {
				fmt.Fprintf(&assembly, operation+"\n", width)
			}
			assembly.WriteString("MOVQ 8(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n")
			pkg, input, config := amd64FixedLocalCLISourceFixture(t, assembly.String(),
				"package fixedlocal\nfunc Value(a uint64) uint64\n")
			output := filepath.Join(t.TempDir(), "scalar.ll")
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatalf("original Go scalar-only scratch source failed: %v", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || !strings.Contains(string(ir), "fixed_local_native") {
				t.Fatalf("scalar-only source lost original private-frame backing: %v", err)
			}
			info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o")
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("LLVM22 scalar-only source object missing: %v", err)
			}
		})
	}
}

// These are ordinary complete source programs, not injected frame tokens.
// The fixture first compiles the original Go assembly; compileOne must then
// discover its physical scratch requirement and produce a real LLVM22 object.
func TestCompileOneAMD64FixedLocalUnalignedTransportSource(t *testing.T) {
	// Share only disposable compiler artifacts, not source captures or Verify
	// results. Every case still observes and consumes its own complete program.
	t.Setenv("GOCACHE", t.TempDir())
	for _, row := range []struct{ opcode, register string }{
		{"MOVOU", "X0"}, {"MOVUPS", "X0"}, {"MOVUPD", "X0"},
		{"VMOVDQU", "Y0"}, {"VMOVUPS", "Z0"}, {"VMOVUPD", "Z0"},
		{"VMOVDQU8", "Z0"}, {"VMOVDQU16", "Z0"},
		{"VMOVDQU32", "Z0"}, {"VMOVDQU64", "Z0"},
	} {
		t.Run(row.opcode, func(t *testing.T) {
			// Existing fixture cells cover 16..31 and 48..63. Initialize the
			// remaining wide-source bytes without touching the saved SP at 96.
			operation := "MOVQ AX,32(SP)\nMOVQ AX,40(SP)\nMOVQ AX,64(SP)\nMOVQ AX,72(SP)\n" +
				row.opcode + " 16(SP)," + row.register
			pkg, input, config := amd64FixedLocalCLIFixture(t, operation)
			output := filepath.Join(t.TempDir(), "unaligned.ll")
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatalf("actual Go physical-scratch source lost its existing fixed-local route: %v", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || !strings.Contains(string(ir), "fixed_local_native") {
				t.Fatalf("complete source did not retain original private-frame backing: %v", err)
			}
			info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o")
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("LLVM22 complete-source object missing: %v", err)
			}
		})
	}
}
