package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This independent boolean reference uses architectural flags, not the
// translator's condition builder or the form map's condition strings.
const x86ConditionalSetIndependentC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static unsigned truth(unsigned condition,uint64_t flags) {
 unsigned c=flags&1,p=flags>>2&1,z=flags>>6&1,s=flags>>7&1,o=flags>>11&1;
 switch(condition) {
 case 0:return !c;case 1:return c;case 2:return z;case 3:return s==o;
 case 4:return !z&&s==o;case 5:return !c&&!z;case 6:return z||s!=o;
 case 7:return c||z;case 8:return s!=o;case 9:return s;case 10:return !z;
 case 11:return !o;case 12:return o;case 13:return !p;case 14:return !s;case 15:return p;
 } return 2;
}
`

func TestCrossLinuxRuntimeMatrixX86ConditionalSetAllFlagsAliasesAndCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, tests, c strings.Builder
	declarations.WriteString("package conditional\n")
	tests.WriteString(`package conditional
import("testing";"encoding/binary")
func TestOriginal(t *testing.T) {
 for sample:=0;sample<64;sample++ {
  flags:=uint64(2)
  for bit,index:=range []uint{0,2,4,6,7,11} {if sample&(1<<bit)!=0 {flags|=1<<index}}
`)
	c.WriteString(x86ConditionalSetIndependentC)
	c.WriteString("typedef void (*kernel)(uint8_t *,uint64_t);\n")
	var names []string
	for condition, op := range x86ConditionalSetTestNames {
		for destination, target := range []string{"AX", "AH", "BX", "BH", "(DI)", "1(DI)"} {
			name := fmt.Sprintf("conditional%d", len(names))
			names = append(names, name)
			fmt.Fprintf(&declarations, "func %s(out *[32]byte,flags uint64)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\nMOVQ out+0(FP),DI\nMOVQ $0x1122334455667788,AX\nMOVQ $0x8877665544332211,BX\nMOVQ flags+8(FP),CX\nPUSHQ CX\nPOPFQ\n%s %s\nMOVQ AX,8(DI)\nMOVQ BX,16(DI)\nPUSHFQ\nPOPQ CX\nMOVQ CX,24(DI)\nRET\n", name, op, target)
			fmt.Fprintf(&c, "extern void %s(uint8_t *,uint64_t);\n", name)
			fmt.Fprintf(&tests, `{
 var out,want [32]byte
 for i:=range out {out[i]=0xc3;want[i]=0xc3}
 binary.LittleEndian.PutUint64(want[8:],0x1122334455667788)
 binary.LittleEndian.PutUint64(want[16:],0x8877665544332211)
 c,p,z,s,o:=flags&1!=0,flags&4!=0,flags&64!=0,flags&128!=0,flags&2048!=0
 values:=[]bool{!c,c,z,s==o,!z&&s==o,!c&&!z,z||s!=o,c||z,s!=o,s,!z,!o,o,!p,!s,p}
 value:=byte(0);if values[%d] {value=1}
 offsets:=[]int{8,9,16,17,0,1};want[offsets[%d]]=value
 %s(&out,flags)
 observed:=binary.LittleEndian.Uint64(out[24:]);binary.LittleEndian.PutUint64(want[24:],observed)
 if out!=want || observed&0x8d5!=flags&0x8d5 {t.Fatalf("%s sample%%d got%%x want%%x flags%%x",sample,out,want,observed)}
}
`, condition, destination, name, name)
		}
	}
	tests.WriteString("}\n}\n")
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module conditional\n\ngo 1.20\n", "conditional.go": declarations.String(), "conditional_amd64.s": assembly.String(), "conditional_test.go": tests.String()} {
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
		t.Fatalf("actual original Go SETcc runtime missing terminal: %s", output)
	}
	c.WriteString("static kernel kernels[]={" + strings.Join(names, ",") + "};\n")
	c.WriteString(`int main(void) {
 const unsigned offsets[]={8,9,16,17,0,1};
 for(unsigned kernel=0;kernel<96;kernel++) for(unsigned sample=0;sample<64;sample++) {
  uint8_t out[32],want[32];memset(out,0xc3,32);memset(want,0xc3,32);
  uint64_t a=UINT64_C(0x1122334455667788),b=UINT64_C(0x8877665544332211),flags=2,observed;
  const unsigned bits[]={0,2,4,6,7,11};for(unsigned bit=0;bit<6;bit++) if(sample&(1<<bit))flags|=UINT64_C(1)<<bits[bit];
  memcpy(want+8,&a,8);memcpy(want+16,&b,8);want[offsets[kernel%6]]=truth(kernel/6,flags);
  kernels[kernel](out,flags);memcpy(&observed,out+24,8);memcpy(want+24,&observed,8);
  if(memcmp(out,want,32)||(observed&0x8d5)!=(flags&0x8d5)) {fprintf(stderr,"kernel%u sample%u flags%llx wanted%llx\n",kernel,sample,(unsigned long long)observed,(unsigned long long)flags);return 1;}
 }
 return 0;
}
`)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, name := range names {
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1},
		}}}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs, ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }})
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "conditional-set", ir, c.String(), level)
		})
	}
	t.Log("original Go 96 kernels × 64 independent flag seeds and LLVM O0/O2; exact full GP aliases, six flags, 32-byte canaries")
}
