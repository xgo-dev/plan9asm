package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86GoCallerFloatMulDivOriginalSourceReachesObjects(t *testing.T) {
	for _, opcode := range []string{"MULSS", "DIVSS", "VMULSS", "VDIVSS"} {
		t.Run(opcode, func(t *testing.T) {
			row := opcode + " X0,X1"
			if strings.HasPrefix(opcode, "V") {
				row += ",X2"
			}
			destination := "X1"
			if strings.HasPrefix(opcode, "V") {
				destination = "X2"
			}
			body := "VMOVSS (DI),X0\nVMOVSS (SI),X1\n" + row + "\nVMOVSS " + destination + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86FloatMulDivConstantMXCSR(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for _, opcode := range []string{"MULSS", "DIVSS", "VMULSS", "VDIVSS"} {
		name := strings.ToLower(opcode)
		left, right := uint32(0x3f800001), uint32(0x3f800001)
		if strings.Contains(opcode, "DIV") {
			left, right = 0x3f800000, 0x40400000
		}
		row, destination := opcode+" X1,X0", "X0"
		if strings.HasPrefix(opcode, "V") {
			row, destination = opcode+" X1,X0,X2", "X2"
		}
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-4\nMOVL $0x%x,AX\nMOVD AX,X0\nMOVL $0x%x,AX\nMOVD AX,X1\n%s\nMOVSS %s,ret+0(FP)\nRET\n", name, left, right, row, destination)
		sigs[name] = FuncSig{Name: name, Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Field: -1}}}}
		fmt.Fprintf(&declarations, "extern uint32_t %s(void);\n", name)
		fmt.Fprintf(&checks, "failed|=check(%s,0x%x,0x%x,%d,%q);\n", name, left, right, x86FloatAddSubBoolInt(strings.Contains(opcode, "DIV")), opcode)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const oracle = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t(*binary_constant)(void);
static int check(binary_constant fn,uint32_t left,uint32_t right,int divide,const char *name) {
 unsigned saved; __asm__ volatile("stmxcsr %0":"=m"(saved));
 int failed=0;
 for(unsigned mode=0;mode<4;mode++) {
  unsigned csr=0x1f80|(mode<<13),wantCSR,gotCSR;
  float a,b;memcpy(&a,&left,4);memcpy(&b,&right,4);
  __asm__ volatile("ldmxcsr %0"::"m"(csr));
  if(divide)__asm__ volatile("divss %1,%0":"+x"(a):"x"(b));
  else __asm__ volatile("mulss %1,%0":"+x"(a):"x"(b));
  uint32_t want;memcpy(&want,&a,4);
  __asm__ volatile("stmxcsr %0":"=m"(wantCSR));
  __asm__ volatile("ldmxcsr %0"::"m"(csr));
  uint32_t got=fn();__asm__ volatile("stmxcsr %0":"=m"(gotCSR));
  if(got!=want||gotCSR!=wantCSR) {
   fprintf(stderr,"%s RC%u got=%x/%x original-SSE=%x/%x\n",name,mode,got,gotCSR,want,wantCSR);
   failed=1;
  }
 }
 __asm__ volatile("ldmxcsr %0"::"m"(saved));return failed;
}
`
	main := oracle + declarations.String() + "int main(void){int failed=0;\n" + checks.String() + "return failed;}\n"
	t.Run("original-ir", func(t *testing.T) {
		compileAndRunRuntimeTestForTarget(t, llc, clang, "mul-div-constant-mxcsr", triple, ir, main, prefix)
	})
	t.Run("optimized-ir", func(t *testing.T) {
		opt := findLLVM22Tool("opt")
		if opt == "" {
			t.Fatal("LLVM22 opt missing")
		}
		dir := t.TempDir()
		input, output := filepath.Join(dir, "source.ll"), filepath.Join(dir, "optimized.ll")
		if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, opt, "-S", "-passes=default<O2>", input, "-o", output)
		message, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("LLVM22 O2: %v\n%s", err, message)
		}
		optimized, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, "mul-div-constant-mxcsr-o2", triple, string(optimized), main, prefix)
	})
}
