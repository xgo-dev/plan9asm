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

func TestCrossLinuxRuntimeMatrixARMRawDataStatus(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for required original Go WORD and LLVM ARM flag execution")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM raw status oracle requires a Linux driver")
	}
	for _, name := range []string{"qemu-arm", "arm-linux-gnueabihf-gcc"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	variants := armRawStatusVariants()
	words := assembleARMRawStatusWords(t, variants)
	var source, goMain, declarations, cFunctions strings.Builder
	sigs := map[string]FuncSig{}
	goMain.WriteString("package main\nimport \"fmt\"\n")
	declarations.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for i, word := range words {
		source.WriteString(armRawStatusSource(i, word))
		name := fmt.Sprintf("rawstatus_%d", i)
		sigs[name] = armRawStatusSignature(name)
		fmt.Fprintf(&goMain, "func %s(status uint32,scratch *[256]byte) uint32\n", name)
		fmt.Fprintf(&declarations, "extern uint32_t %s(uint32_t,uint8_t*);\n", name)
		fmt.Fprintf(&cFunctions, "%s,\n", name)
	}
	goMain.WriteString("func main() {\n functions := []func(uint32,*[256]byte)uint32{\n")
	for i := range words {
		fmt.Fprintf(&goMain, "rawstatus_%d,\n", i)
	}
	goMain.WriteString(`}
 for i,probe := range functions {
  for flags:=uint32(0);flags<16;flags++ {
   for seed:=0;seed<4;seed++ {
    var scratch [256]byte
    for j:=range scratch { scratch[j]=byte(j*17+seed*71) }
    got:=probe(flags<<28,&scratch)
    if got!=flags { panic(fmt.Sprintf("Go raw WORD family=%d flags=%x seed=%d got=%x",i,flags,seed,got)) }
   }
  }
 }
 fmt.Printf("original Go raw WORD: %d families/condition variants, all 16 NZCV states, four buffers passed\n",len(functions))
}
`)
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":       "module armrawstatusoracle\n\ngo 1.20\n",
		"main.go":      goMain.String(),
		"oracle_arm.s": strings.ReplaceAll(source.String(), "TEXT rawstatus_", "TEXT ·rawstatus_"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=1", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0", "QEMU_CPU=max")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual original Go ARM raw-status oracle: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	cMain := declarations.String() + "static uint32_t (*const functions[])(uint32_t,uint8_t*)={\n" + cFunctions.String() + `};
int main(void) {
 for(unsigned i=0;i<sizeof(functions)/sizeof(functions[0]);i++) {
  for(uint32_t flags=0;flags<16;flags++) {
   for(unsigned seed=0;seed<4;seed++) {
    uint8_t scratch[256];
    for(unsigned j=0;j<256;j++)scratch[j]=(uint8_t)(j*17+seed*71);
    uint32_t got=functions[i](flags<<28,scratch);
    if(got!=flags) {
     fprintf(stderr,"LLVM raw-status family=%u flags=%x seed=%u got=%x\n",i,flags,seed,got);
     return 1;
    }
   }
  }
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "arm_raw_status", "armv7-unknown-linux-gnueabihf", ir, cMain,
		[]string{"qemu-arm", "-cpu", "max", "-L", "/usr/arm-linux-gnueabihf"})
	t.Logf("LLVM/C independent four-flag oracle: %d executed cases", len(words)*16*4)
}
