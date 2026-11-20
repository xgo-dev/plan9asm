package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func armSymbolScratchFixture() (string, map[string]FuncSig, string, string) {
	var source, cDeclarations, cChecks, goDeclarations, goChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		spec := armIntegerMemorySpecs[op]
		for _, offset := range []int{1, 3} {
			for _, suffix := range []string{"", ".EQ", ".NE", ".P", ".W", ".U", ".EQ.U.W", ".NE.U.P"} {
				for _, kind := range []string{"load_register", "load_scratch", "store_scratch"} {
					// Writeback with the same base/data register is not a portable
					// defined ARM runtime contract. Test those modifiers with R2,
					// not R11; Go/object grammar coverage remains separate.
					if kind != "load_register" && strings.ContainsAny(suffix, "PWU") {
						continue
					}
					name := fmt.Sprintf("scratch_%d", len(sigs))
					instruction := fmt.Sprintf("%s%s ·memory+%d(SB),R2", op, suffix, offset)
					if kind == "load_scratch" {
						instruction = fmt.Sprintf("%s%s ·memory+%d(SB),R11", op, suffix, offset)
					} else if kind == "store_scratch" {
						instruction = fmt.Sprintf("%s%s R11,·memory+%d(SB)", op, suffix, offset)
					}
					fmt.Fprintf(&source, `TEXT ·%s(SB),$0-4
MOVW $0x76543210,R11
CMP R2,R2
%s
MOVW R11,ret+0(FP)
RET
`, name, instruction)
					sigs[name] = FuncSig{Name: name, Ret: I32, Frame: FrameLayout{
						Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
					}}
					fmt.Fprintf(&cDeclarations, "extern uint32_t %s(void);\n", name)
					fmt.Fprintf(&goDeclarations, "func %s() uint32\n", name)
					wantC := fmt.Sprintf("(uint32_t)(uintptr_t)&memory[%d]", offset)
					wantGo := fmt.Sprintf("uint32(uintptr(unsafe.Pointer(&memory[%d])))", offset)
					if strings.Contains(suffix, ".NE") {
						wantC, wantGo = "UINT32_C(0x76543210)", "uint32(0x76543210)"
					} else if kind == "load_scratch" {
						var value uint32
						for i := 0; i < spec.bits/8; i++ {
							value |= uint32(byte((offset+i)*13+131)) << uint(8*i)
						}
						if spec.signed && spec.bits == 8 {
							value = uint32(int8(value))
						} else if spec.signed && spec.bits == 16 {
							value = uint32(int16(value))
						}
						wantC, wantGo = fmt.Sprintf("UINT32_C(%d)", value), fmt.Sprintf("uint32(%d)", value)
					}
					fmt.Fprintf(&cChecks, `reset_memory();
if (%s() != %s) { fprintf(stderr,"%s R11 mismatch\n"); return 1; }
for (unsigned i=0; i<sizeof memory; i++) {
  unsigned char want=(unsigned char)(i*13+131);
`, name, wantC, name)
					fmt.Fprintf(&goChecks, `resetMemory()
if %s() != %s { panic("%s Go R11 mismatch") }
for i := range memory {
  want := byte(i*13+131)
`, name, wantGo, name)
					if kind == "store_scratch" && !strings.Contains(suffix, ".NE") {
						fmt.Fprintf(&cChecks, "  if (i>=%d && i<%d) want=(unsigned char)((%s) >> (8*(i-%d)));\n", offset, offset+spec.bits/8, wantC, offset)
						fmt.Fprintf(&goChecks, "  if i>=%d && i<%d { want=byte((%s) >> (8*(i-%d))) }\n", offset, offset+spec.bits/8, wantGo, offset)
					}
					fmt.Fprintf(&cChecks, "  if(memory[i]!=want) { fprintf(stderr,\"%s memory canary mismatch\\n\"); return 2; }\n}\n", name)
					fmt.Fprintf(&goChecks, "  if memory[i]!=want { panic(\"%s Go memory canary mismatch\") }\n}\n", name)
				}
			}
		}
	}
	main := "#include <stdint.h>\n#include <stdio.h>\nunsigned char memory[80];\n" + cDeclarations.String() + `
static void reset_memory(void) {
  for(unsigned i=0; i<sizeof memory; i++) memory[i]=(unsigned char)(i*13+131);
}
int main(void) {
` + cChecks.String() + "return 0;\n}\n"
	goMain := "package main\nimport \"unsafe\"\nvar memory [80]byte\n" + goDeclarations.String() + `
func resetMemory() { for i := range memory { memory[i]=byte(i*13+131) } }
func main() {
` + goChecks.String() + "}\n"
	return source.String(), sigs, main, goMain
}

func translateARMSymbolScratchFixture(t *testing.T, triple string) (string, string, string, string) {
	t.Helper()
	source, sigs, main, goMain := armSymbolScratchFixture()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir, source, main, goMain
}

func TestARMSymbolScratchCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, _, _, _ := translateARMSymbolScratchFixture(t, triple)
		compileLLVMToObject(t, llc, triple, "arm-scratch.ll", "arm-scratch.o", ir)
	}
}

func TestCrossLinuxRuntimeMatrixARMSymbolScratch(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("actual ARM scratch execution is required by the Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM cross-runtime needs a Linux amd64 or arm64 driver")
	}
	for _, name := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", name, err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, source, main, goMain := translateARMSymbolScratchFixture(t, triple)
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module armscratchoracle\n\ngo 1.20\n", "main.go": goMain, "oracle_arm.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=2", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go ARM scratch oracle: %v\n%s", err, output)
	}
	t.Log("native Go ARM scratch oracle passed")
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "arm_scratch_memory", triple, ir, main,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
