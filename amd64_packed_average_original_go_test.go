package plan9asm

import (
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedAverageOriginalGo(t *testing.T) {
	x86AverageOriginalGo(t, false)
}

func x86AverageOriginalGo(t *testing.T, wide bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	if wide {
		execution.requireAVX(t)
		x86AverageRequireAVX2(t, execution)
	}
	var assembly, declarations, tests strings.Builder
	declarations.WriteString("package oracle\n")
	tests.WriteString(`package oracle

import (
 "testing"
 "unsafe"
 "runtime"
 "encoding/binary"
)

func aligned(storage *[192]byte) (*[64]byte,int) {
 offset:=64+int((-uintptr(unsafe.Pointer(&storage[64])))&63)
 return (*[64]byte)(unsafe.Pointer(&storage[offset])),offset
}

func TestOriginal(t *testing.T) {
 runtime.LockOSThread()
 defer runtime.UnlockOSThread()
 for sample:=0;sample<257;sample++ {
  for status:=0;status<2;status++ {
  var a,b,out [192]byte
  ap,_:=aligned(&a)
  bp,_:=aligned(&b)
  op,offset:=aligned(&out)
  for i:=range a {
   a[i]=0xa7
   b[i]=0xb9
   out[i]=0xc3
  }

  for i:=0;i<64;i++ {
   ap[i]=byte(sample*71+i*37)
   bp[i]=byte(sample*19-i*13)
   if sample<4 {
    ap[i]=[4]byte{255,0,128,255}[sample]
    bp[i]=[4]byte{255,1,128,0}[sample]
   }
  }
  beforeA,beforeB:=a,b
  flags:=uint64(2)
  if status!=0 {
   flags|=0x8d5
  }
  csr:=uint32(0x1f80|((sample%4)<<13)|(sample%64))
`)
	count := 0
	for _, row := range x86AverageNumericCases() {
		if row.width == 64 || row.masking != 0 || !wide && strings.HasPrefix(row.op, "V") {
			continue // Native EVEX is a distinct, unexecuted axis here.
		}
		move, bank, observedWidth := "MOVUPS", "X", 16
		if wide {
			move, bank, observedWidth = "VMOVUPS", "Y", 32
		}
		name := fmt.Sprintf("Average%d", count)
		count++
		fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags uint64,csr uint32)\n", name)
		fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$8-36
STMXCSR saved-4(SP)
LDMXCSR csr+32(FP)
MOVQ out+0(FP),AX
MOVQ a+8(FP),BX
MOVQ b+16(FP),CX
`, name)
		fmt.Fprintf(&assembly, "%s (CX),%s0\n%s (CX),%s2\n", move, bank, move, bank)
		if !row.memory || row.destination == 1 {
			fmt.Fprintf(&assembly, "%s (BX),%s1\n", move, bank)
		}
		if row.mmx {
			fmt.Fprintf(&assembly, "MOVQ (CX),M0\nMOVQ (BX),M1\n%s %s0,(AX)\n", move, bank)
		}
		assembly.WriteString("PUSHQ flags+24(FP)\nPOPFQ\n" + row.instruction() + "\n")
		if row.mmx {
			assembly.WriteString("MOVQ M0,(AX)\nEMMS\n")
		} else {
			fmt.Fprintf(&assembly, "%s %s%d,(AX)\n", move, bank, row.destination)
		}
		assembly.WriteString("PUSHFQ\nPOPQ R10\nMOVQ R10,32(AX)\nSTMXCSR 40(AX)\nLDMXCSR saved-4(SP)\nRET\n")
		fmt.Fprintf(&tests, `{
 for i:=range out {
  out[i]=0xc3
 }
 %s(op,ap,bp,flags,csr)
 if binary.LittleEndian.Uint64(op[32:40])&0x8d5!=flags&0x8d5 || binary.LittleEndian.Uint32(op[40:44])!=csr || a!=beforeA || b!=beforeB {
  t.Fatal("original flags/CSR/input canary")
 }
 for i:=0;i<%d;i++ {
  start:=i/%d*%d
  x,y:=uint32(ap[start]),uint32(bp[start])
  if %d==2 {
   x|=uint32(ap[start+1])<<8
   y|=uint32(bp[start+1])<<8
  }
  value:=(x+y+1)/2
  want:=byte(value>>uint(8*(i%%%d)))
  if i>=%d {
   want=0
   if %t {
    want=bp[i]
   }
  }
  if op[i]!=want {
   t.Fatalf("%s sample%%d byte%%d got%%x want%%x",sample,i,op[i],want)
  }
 }
 for i:=range out {
  if (i<offset||i>=offset+44||i>=offset+%d&&i<offset+32)&&out[i]!=0xc3 {
   t.Fatal("original output canary")
  }
 }
}
`, name, observedWidth, row.bits/8, row.bits/8, row.bits/8, row.bits/8, row.width,
			!strings.HasPrefix(row.op, "V"), name, observedWidth)
	}
	tests.WriteString("}\n}\n}\n")
	formattedTests, err := format.Source([]byte(tests.String()))
	if err != nil {
		t.Fatal("original Go numerical fixture is not complete syntax:", err)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	dir := t.TempDir()
	for name, contents := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n",
		"value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": string(formattedTests)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goos := runtime.GOOS
	binary := filepath.Join(dir, "original.test")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "test", "-c", "-p=2", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS="+goos)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go compile/asmdecl failed: %v\n%s", err, output)
	}
	output = execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginal") || !strings.Contains(string(output), "PASS\n") {
		t.Fatal("missing actual original Go numerical receipt", string(output))
	}
	t.Logf("%d original Go kernels × 257 patterns × 2 flag seeds; wide=%t (16-byte SSE or 32-byte VEX aliases)/CSR/canaries. No native EVEX or whole MMX/x87-state claim", count, wide)
}

// The wide original program includes Y-width VPAVG, not just AVX X moves.
// Missing AVX2 is a required-axis failure, never a skip or a software fallback.
func x86AverageRequireAVX2(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "average-isa.c")
	executable := filepath.Join(dir, "average-isa")
	const preflight = `#include <stdio.h>
int main(void) {
  __builtin_cpu_init();
  int avx2 = !!__builtin_cpu_supports("avx2");
  printf("required original VPAVG Y-width AVX2=%d\n", avx2);
  return avx2 ? 0 : 1;
}
`
	if err := os.WriteFile(source, []byte(preflight), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("actual original VPAVG capability: %s", strings.TrimSpace(string(execution.run(t, executable))))
}
