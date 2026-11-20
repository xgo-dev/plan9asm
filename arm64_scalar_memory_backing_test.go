package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64ScalarMemoryBackingFixture() (source, declaration, goProgram, cProgram string) {
	var assembly, decl, goChecks, cDecl, cChecks strings.Builder
	for i, op := range arm64MemoryScratchAuditMoves {
		width := 1 << (i / 2)
		offset := width
		if width == 8 {
			offset = 0
		}
		for region := 0; region < 3; region++ {
			name := fmt.Sprintf("Backing%d", i*3+region)
			fmt.Fprintf(&decl, "func %s(input uint64, output *[2]uint64) uint64\n", name)
			frame := 0
			if region == 2 {
				frame = 32
			}
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$%d-24\n", name, frame)
			assembly.WriteString("MOVD input+0(FP),R0\nMOVD output+8(FP),R11\nMOVD $0x10203040aa80feff,R1\nMOVD $107,R27\nMOVD $255,R6\nMOVD $1,R7\nCMP R7,R6\n")
			whole, partial := "input+0(FP)", fmt.Sprintf("input+%d(FP)", offset)
			if region == 1 {
				whole, partial = "ret+16(FP)", fmt.Sprintf("ret+%d(FP)", 16+offset)
			} else if region == 2 {
				// Go AUTO offsets are relative to the logical top of the
				// declared frame. This is initialized local data, not SP0.
				whole, partial = "local-24(SP)", fmt.Sprintf("local%+d(SP)", -24+offset)
			}
			fmt.Fprintf(&assembly, "MOVD R0,%s\n%s R1,%s\nMOVD %s,R0\nMOVD R0,ret+16(FP)\n", whole, op, partial, whole)
			assembly.WriteString("MOVD R27,(R11)\nCSET HS,R2\nMOVD R2,8(R11)\nRET\n")
			mask := ^uint64(0)
			if width != 8 {
				mask = (uint64(1) << uint(width*8)) - 1
			}
			want := uint64(0xfedcba9876543210)&^(mask<<uint(offset*8)) |
				(uint64(0x10203040aa80feff)&mask)<<uint(offset*8)
			fmt.Fprintf(&goChecks, `
    {
        output := struct { left uint64; values [2]uint64; right uint64 }{left:0x1234,right:0x5678}
        got := %s(0xfedcba9876543210,&output.values)
        if got != %#x || output.values != ([2]uint64{107,1}) { panic("%s typed backing") }
        if output.left != 0x1234 || output.right != 0x5678 { panic("%s output canary") }
    }
`, name, want, name, name)
			fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t,uint64_t *);\n", name)
			fmt.Fprintf(&cChecks, `
    {
        struct { uint64_t left,values[2],right; } output={.left=0x1234,.right=0x5678};
        uint64_t got=%s(UINT64_C(0xfedcba9876543210),output.values);
        if (got!=UINT64_C(%#x) || output.values[0]!=107 || output.values[1]!=1) {
            fprintf(stderr,"%s typed backing: %%#llx\n",(unsigned long long)got);
            return 1;
        }
        if (output.left!=0x1234 || output.right!=0x5678) return 2;
    }
`, name, want, name)
		}
	}
	source, declaration = assembly.String(), decl.String()
	goProgram = "package main\n" + declaration + "func main() {\n" + goChecks.String() + "}\n"
	cProgram = "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + "int main(void) {\n" + cChecks.String() + "return 0;\n}\n"
	return
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMemoryTypedBacking(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	source, declaration, goProgram, cProgram := arm64ScalarMemoryBackingFixture()
	runARM64LocalRegisterGoOracle(t, source, goProgram, len(runner) != 0, "1.20")
	for api, ir := range arm64ScalarMemoryIRs(t, source, declaration, target) {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, fmt.Sprintf("scalar-memory-backing-%d", api), target, ir, cProgram, runner)
	}
	t.Log("21 initialized typed parameter/result/AUTO partial writes preserve untouched bits; output canaries and R27/NZCV")
}

func TestARM64ScalarMemoryTypedBackingLLVM22Objects(t *testing.T) {
	source, declaration, _, _ := arm64ScalarMemoryBackingFixture()
	requireARM64GoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc unavailable")
	}
	for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		for api, ir := range arm64ScalarMemoryIRs(t, source, declaration, target) {
			compileLLVMToObject(t, llc, target, fmt.Sprintf("scalar-memory-backing-%d.ll", api), fmt.Sprintf("scalar-memory-backing-%d.o", api), ir)
		}
	}
}
