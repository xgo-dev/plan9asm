package plan9asm

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86LogicalAUTOInitializedBytesAndCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, goTest, reference strings.Builder
	declarations.WriteString("package autoscalar\n")
	goTest.WriteString(`package autoscalar
import("testing";"math")
func TestOriginal(t *testing.T) {
 for sample:=uint64(0);sample<257;sample++ {
  x:=sample*0x9e3779b97f4a7c15
`)
	reference.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n")
	for _, row := range []struct {
		name, move string
		width      int
	}{
		{"Byte", "MOVB", 1}, {"Word", "MOVW", 2}, {"Long", "MOVL", 4}, {"Quad", "MOVQ", 8},
	} {
		fmt.Fprintf(&declarations, "func %s(x uint64) uint64\n", row.name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$32-16\nXORQ AX,AX\n%s x+0(FP),AX\n%s AX,first-16(SP)\nXORQ AX,AX\n%s second-16(SP),AX\nMOVQ AX,ret0+8(FP)\nRET\n",
			row.name, row.move, row.move, row.move)
		mask := ^uint64(0)
		if row.width < 8 {
			mask = uint64(1)<<(8*row.width) - 1
		}
		fmt.Fprintf(&goTest, "if got:=%s(x);got!=x&0x%x {t.Fatalf(\"%s sample%%d got%%x want%%x\",sample,got,x&0x%x)}\n", row.name, mask, row.name, mask)
		fmt.Fprintf(&reference, "extern uint64_t %s(uint64_t);\n", row.name)
	}
	for _, row := range []struct {
		name, typ, move string
		args            int
	}{
		{"Single", "float32", "MOVSS", 12}, {"Double", "float64", "MOVSD", 16},
	} {
		fmt.Fprintf(&declarations, "func %s(x %s) %s\n", row.name, row.typ, row.typ)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$32-%d\n%s x+0(FP),X0\n%s X0,first-16(SP)\n%s second-16(SP),X1\n%s X1,ret0+8(FP)\nRET\n",
			row.name, row.args, row.move, row.move, row.move, row.move)
		if row.typ == "float32" {
			goTest.WriteString("if got:=math.Float32bits(Single(math.Float32frombits(uint32(x))));got!=uint32(x) {t.Fatalf(\"single sample%d got%x want%x\",sample,got,uint32(x))}\n")
			reference.WriteString("extern float Single(float);\n")
		} else {
			goTest.WriteString("if got:=math.Float64bits(Double(math.Float64frombits(x)));got!=x {t.Fatalf(\"double sample%d got%x want%x\",sample,got,x)}\n")
			reference.WriteString("extern double Double(double);\n")
		}
	}
	goTest.WriteString("}\n}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module autoscalar\n\ngo 1.20\n", "auto.go": declarations.String(),
		"auto_amd64.s": assembly.String(), "auto_test.go": goTest.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	binary := filepath.Join(dir, "original.test")
	command := exec.Command("go", "test", "-p=2", "-vet=off", "-c", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	output := execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginal") || !strings.Contains(string(output), "PASS\n") {
		t.Fatalf("original Go AUTO numerical oracle has no successful terminal: %s", output)
	}
	reference.WriteString(`int main(void) {
 for(uint64_t sample=0;sample<257;sample++) {
  uint64_t x=sample*UINT64_C(0x9e3779b97f4a7c15);
  struct {uint64_t left,values[6],right;} out;
  memset(&out,0xc3,sizeof(out));
  out.values[0]=Byte(x);out.values[1]=Word(x);out.values[2]=Long(x);out.values[3]=Quad(x);
  uint32_t small=(uint32_t)x,smallOut;float f;double d;uint64_t largeOut;
  memcpy(&f,&small,4);f=Single(f);memcpy(&smallOut,&f,4);out.values[4]=smallOut;
  memcpy(&d,&x,8);d=Double(d);memcpy(&largeOut,&d,8);out.values[5]=largeOut;
  const uint64_t want[]={x&255,x&65535,x&UINT64_C(0xffffffff),x,(uint32_t)x,x};
  if(out.left!=UINT64_C(0xc3c3c3c3c3c3c3c3)||out.right!=UINT64_C(0xc3c3c3c3c3c3c3c3)||memcmp(out.values,want,sizeof(want))) {
   fprintf(stderr,"AUTO sample%llu byte/alias/canary mismatch\n",(unsigned long long)sample);return 1;
  }
 }
 return 0;
}
`)
	pkg := mustGoPackage(t, "example.invalid/autoscalar", declarations.String())
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		name := strings.TrimPrefix(fn.Sym, "·")
		sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); err != nil {
			t.Fatal(err)
		}
		sigs[name] = sig
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "logical-auto", ir, reference.String(), level)
		})
	}
	t.Log("original Go 6 initialized AUTO kernels × 257 inputs; LLVM O0/O2 exact scalar bits and full output canaries; no native frame permission produced")
}
