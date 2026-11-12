package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedUnpackOriginalGoBitOracle(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\n")
	tests.WriteString(`package oracle
import "testing"
func TestOriginalGoInterleaveBits(t *testing.T) {
 patterns:=[][16]byte{
  {0x45,0x23,0x81,0x7f,0x78,0x56,0xc4,0xff,0xbc,0x9a,0x78,0x56,0x34,0x12,0xf0,0x7f},
  {0x54,0x76,0x98,0xba,0xdc,0xfe,0xf8,0xff,0x45,0x23,0xc1,0x7f,0,0,0,0x80},
  {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
  {0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0},
 }
`)
	count := 0
	for _, opcode := range x86CallerUnpackOpcodes() {
		if strings.HasPrefix(opcode, "V") {
			continue // Native VEX/EVEX execution needs separate ISA witnesses.
		}
		banks := []string{"X"}
		if x86UnpackTestHasMMX(opcode) {
			banks = append(banks, "M")
		}
		for _, bank := range banks {
			forms := []string{"register"}
			if bank == "M" {
				forms = append(forms, "memory")
			}
			for _, form := range forms {
				name := fmt.Sprintf("unpack%d", count)
				count++
				fmt.Fprintf(&declarations, "func %s(a,b,out *byte,csr uint32)\n", name)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-28\nSTMXCSR saved-4(SP)\nLDMXCSR csr+24(FP)\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),CX\n", name)
				move, bytes := "MOVOU", 16
				if bank == "M" {
					move, bytes = "MOVQ", 8
				}
				fmt.Fprintf(&assembly, "%s (BX),%s0\n", move, bank)
				first := bank + "1"
				if form == "register" {
					fmt.Fprintf(&assembly, "%s (AX),%s1\n", move, bank)
				} else {
					first = "(AX)"
				}
				fmt.Fprintf(&assembly, "CMPQ AX,AX\nSTC\n%s %s,%s0\n%s %s0,(CX)\nSETCS 16(CX)\nSETNE 17(CX)\nSTMXCSR 18(CX)\n", opcode, first, bank, move, bank)
				if bank == "M" {
					assembly.WriteString("EMMS\n")
				}
				assembly.WriteString("LDMXCSR saved-4(SP)\nRET\n")
				high := 0
				if strings.Contains(opcode, "UNPCKH") {
					high = bytes / 2
				}
				fmt.Fprintf(&tests, `
 for _,a:=range patterns { for _,b:=range patterns { for mode:=0;mode<4;mode++ {
  var out [24]byte
  for i:=range out {out[i]=0xc3}
  csr:=uint32(0x1f80|mode<<13|mode)
  %[1]s(&a[0],&b[0],&out[1],csr)
  if out[0]!=0xc3 || out[23]!=0xc3 || out[17]!=1 || out[18]!=0 {t.Fatalf("%[1]s canary/flags: %%x",out)}
  gotCSR:=uint32(out[19])|uint32(out[20])<<8|uint32(out[21])<<16|uint32(out[22])<<24
  if gotCSR!=csr {t.Fatalf("%[1]s changed MXCSR %%x want %%x",gotCSR,csr)}
  for i:=0;i<16;i++ {
   want:=byte(0xc3)
   if i<%[2]d {
    source:=%[3]d+(i/(2*%[4]d))*%[4]d+i%%%[4]d
    want=b[source]
    if i/%[4]d%%2!=0 {want=a[source]}
   }
   if out[i+1]!=want {t.Fatalf("%[1]s byte %%d got %%x want %%x",i,out[i+1],want)}
  }
 } } }
`, name, bytes, high, x86UnpackTestLaneBytes(opcode))
			}
		}
	}
	tests.WriteString("}\n")
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":   "module oracle\n\ngo 1.20\n",
		"value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": tests.String(),
	} {
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
		t.Fatalf("actual original Go interleave bit oracle: %v\n%s", err, output)
	}
	t.Logf("%d original SSE/MMX Go functions; 64 independent bitwise/MXCSR/flag/canary inputs each", count)
}
