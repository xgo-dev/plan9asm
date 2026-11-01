package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedWrappingAddOriginalGoBits(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\n")
	tests.WriteString(`package oracle
import "testing"
func lane(p []byte,n int)uint64{var value uint64;for j:=0;j<n;j++{value|=uint64(p[j])<<uint(8*j)};return value}
func TestOriginalAdd(t *testing.T){
 var patterns [8][16]byte;state:=uint32(0x12345678)
 for p:=range patterns{for i:=range patterns[p]{state=state*1664525+1013904223;patterns[p][i]=byte(state>>24)}}
 for i:=range patterns[0]{patterns[0][i]=0xff;patterns[1][i]=1;patterns[2][i]=0x80;patterns[3][i]=0}
`)
	count := 0
	for index, opcode := range []string{"PADDB", "PADDW", "PADDL", "PADDQ"} {
		bytes := 1 << uint(index)
		for _, bank := range []string{"X", "M"} {
			if bank == "M" && opcode == "PADDQ" {
				continue // Actual Go PADDQ uses yxm, not Intel's MMX row.
			}
			forms := []string{"register"}
			if bank == "M" {
				forms = append(forms, "memory")
			}
			for _, form := range forms {
				name := fmt.Sprintf("packedaddgo%d", count)
				count++
				fmt.Fprintf(&declarations, "func %s(a,b,out *byte,csr uint32)\n", name)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-28\nSTMXCSR saved-4(SP)\nLDMXCSR csr+24(FP)\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),CX\n", name)
				move, width := "MOVOU", 16
				if bank == "M" {
					move, width = "MOVQ", 8
				}
				fmt.Fprintf(&assembly, "%s (BX),%s0\n", move, bank)
				first := "(AX)"
				if form == "register" {
					first = bank + "1"
					fmt.Fprintf(&assembly, "%s (AX),%s1\n", move, bank)
				}
				fmt.Fprintf(&assembly, "CMPQ AX,AX\nSTC\n%s %s,%s0\n%s %s0,(CX)\nSETCS 16(CX)\nSETNE 17(CX)\nSTMXCSR 18(CX)\n", opcode, first, bank, move, bank)
				if bank == "M" {
					assembly.WriteString("EMMS\n")
				}
				assembly.WriteString("LDMXCSR saved-4(SP)\nRET\n")
				fmt.Fprintf(&tests, `
 for _,a:=range patterns{for _,b:=range patterns{for mode:=0;mode<4;mode++{
  var out [24]byte;for i:=range out{out[i]=0xc3};csr:=uint32(0x1f80|mode<<13|mode)
  %[1]s(&a[0],&b[0],&out[1],csr)
  if out[0]!=0xc3||out[23]!=0xc3||out[17]!=1||out[18]!=0{t.Fatalf("%[1]s flags/canary %%x",out)}
  gotCSR:=uint32(out[19])|uint32(out[20])<<8|uint32(out[21])<<16|uint32(out[22])<<24
  if gotCSR!=csr{t.Fatalf("%[1]s CSR %%x != %%x",gotCSR,csr)}
  for i:=0;i<%[2]d;i+=%[3]d{
   want:=lane(a[i:],%[3]d)+lane(b[i:],%[3]d)
   for j:=0;j<%[3]d;j++{if out[i+j+1]!=byte(want>>uint(8*j)){t.Fatalf("%[1]s byte%%d got%%x want%%x",i+j,out,want)}}
  }
  for i:=%[2]d;i<16;i++{if out[i+1]!=0xc3{t.Fatal("touched upper MMX canary")}}
 }}}
`, name, width, bytes)
			}
		}
	}
	tests.WriteString("}\n")
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": tests.String()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original Go modulo integer-add oracle: %v\n%s", err, output)
	}
	t.Logf("%d actual Go SSE/MMX functions × 256 independent full-lane wrap/MXCSR/flags/canary cases; no x87 tag-state claim", count)
}
