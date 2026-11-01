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

// The original stock-Go program contains legacy SSE only. Its full immediate,
// real m8/m16/m32/m64 accesses, flags and input/output canaries are independent
// of the translator. Rosetta is diagnostic; native Linux remains its own axis.
func TestCrossLinuxRuntimeMatrixX86ScalarLaneOriginalGo(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, checks strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, bits := range []int{8, 16, 32, 64} {
		for _, insert := range []bool{false, true} {
			for _, memory := range []bool{false, true} {
				for lane := 0; lane < 128/bits; lane++ {
					name := fmt.Sprint("Lane", count)
					count++
					fmt.Fprintf(&declarations, "func %s(out,in *[96]byte,seed uint64)\n", name)
					fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ in+8(FP),BX\nMOVQ seed+16(FP),CX\nMOVUPS (BX),X0\nMOVUPS (AX),X1\nMOVQ $-1,R11\nSTMXCSR 76(AX)\nCMPQ AX,AX\nSTC\n", name)
					op := "P"
					if insert {
						op += "INSR"
					} else {
						op += "EXTR"
					}
					op += map[int]string{8: "B", 16: "W", 32: "D", 64: "Q"}[bits]
					if insert {
						operand := "CX"
						if memory {
							operand = "3(BX)"
						}
						fmt.Fprintf(&assembly, "%s $%d,%s,X1\nMOVUPS X1,(AX)\n", op, lane, operand)
					} else {
						operand := "R11"
						if memory {
							operand = "3(AX)"
						}
						fmt.Fprintf(&assembly, "%s $%d,X0,%s\n", op, lane, operand)
						if !memory {
							assembly.WriteString("MOVQ R11,64(AX)\n")
						}
					}
					assembly.WriteString("SETCS 72(AX)\nSETNE 73(AX)\nSTMXCSR 80(AX)\nRET\n")
					fmt.Fprintf(&checks, "check(t,%s,%d,%d,%t,%t)\n", name, bits/8, lane, insert, memory)
				}
			}
		}
	}
	if count != 120 {
		t.Fatal("original legacy scalar-lane denominator", count)
	}
	const tests = `package oracle
import("testing";"encoding/binary";"runtime")
func check(t *testing.T,fn func(*[96]byte,*[96]byte,uint64),width,lane int,insert,memory bool){
 for sample:=0;sample<257;sample++{
  var input,output [96]byte
  for i:=range input{input[i]=byte(i*37+sample*71);output[i]=byte(i*19+sample*13)}
  before,want:=input,output
  seed:=[4]uint64{0,^uint64(0),0x9876fedcba543210,0x8000000000000001}[sample%4]
  if insert{
   for i:=0;i<width;i++{v:=byte(seed>>uint(i*8));if memory{v=input[3+i]};want[lane*width+i]=v}
  }else if memory{copy(want[3:3+width],input[lane*width:lane*width+width])
  }else{var value uint64;for i:=0;i<width;i++{value|=uint64(input[lane*width+i])<<uint(i*8)};binary.LittleEndian.PutUint64(want[64:72],value)}
  want[72],want[73]=1,0
  fn(&output,&input,seed)
  if binary.LittleEndian.Uint32(output[76:80])!=binary.LittleEndian.Uint32(output[80:84]){t.Fatal("original changed MXCSR")}
  copy(want[76:84],output[76:84])
  if input!=before||output!=want{t.Fatalf("original width=%d lane=%d ins=%t mem=%t sample=%d got=%x want=%x",width,lane,insert,memory,sample,output,want)}
 }
}
func TestOriginal(t *testing.T){runtime.LockOSThread();defer runtime.UnlockOSThread()
`
	formatted, err := format.Source([]byte(tests + checks.String() + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	dir := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": string(formatted)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "original.test")
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, "go", "test", "-c", "-p=2", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "CGO_ENABLED=0", "GOARCH=amd64", "GOOS="+runtime.GOOS)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("original Go source/object/asmdecl: %v\n%s", err, output)
	}
	output = execution.run(t, binary, "-test.run=^TestOriginal$", "-test.count=1", "-test.v")
	if !strings.Contains(string(output), "--- PASS: TestOriginal") || !strings.Contains(string(output), "PASS\n") {
		t.Fatal("missing original full-body result", string(output))
	}
	t.Logf("%d original Go legacy SSE kernels ×257 patterns, actual stock-Go ABI callers and physical scalar accesses; native Linux required separately", count)
}
