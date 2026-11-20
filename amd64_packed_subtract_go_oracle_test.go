package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedSubtractOriginalGoBits(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\n")
	tests.WriteString(`package oracle

import "testing"

func lane(p []byte, n int) uint64 {
 var value uint64
 for j := 0; j < n; j++ {
  value |= uint64(p[j]) << uint(8*j)
 }
 return value
}

func difference(a, b uint64, n, mode int) uint64 {
 if mode == 0 {
  return b-a
 }
 if mode == 2 {
  if b < a {
   return 0
  }
  return b-a
 }
 sign := int64(1) << uint(n*8-1)
 left, right := int64(a), int64(b)
 if a&uint64(sign) != 0 {
  left -= sign*2
 }
 if b&uint64(sign) != 0 {
  right -= sign*2
 }
 result := right-left
 if result < -sign {
  result = -sign
 }
 if result > sign-1 {
  result = sign-1
 }
 return uint64(result)
}

func TestOriginalSubtract(t *testing.T) {
 var patterns [8][16]byte
 state := uint32(0x12345678)
 for p := range patterns {
  for i := range patterns[p] {
   state = state*1664525+1013904223
   patterns[p][i] = byte(state>>24)
  }
 }
 for i := range patterns[0] {
  patterns[0][i] = 0xff
  patterns[1][i] = 1
  patterns[2][i] = 0x80
  patterns[3][i] = 0
 }
`)
	opcodes := []string{"PSUBB", "PSUBW", "PSUBL", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW"}
	for index, opcode := range opcodes {
		bits, mode, _, _ := amd64PackedSubtractProperties(opcode)
		name := fmt.Sprintf("packedsubtractgo%d", index)
		fmt.Fprintf(&declarations, "func %s(a,b,out *byte,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-28\n"+
			"STMXCSR saved-4(SP)\nLDMXCSR csr+24(FP)\n"+
			"MOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),CX\n"+
			"MOVOU (AX),X1\nMOVOU (BX),X0\nCMPQ AX,AX\nSTC\n"+
			"%s X1,X0\nMOVOU X0,(CX)\nSETCS 16(CX)\nSETNE 17(CX)\n"+
			"STMXCSR 18(CX)\nLDMXCSR saved-4(SP)\nRET\n", name, opcode)
		fmt.Fprintf(&tests, `
 for _, a := range patterns {
  for _, b := range patterns {
   for csrMode := 0; csrMode < 4; csrMode++ {
    var out [24]byte
    for i := range out {
     out[i] = 0xc3
    }
    csr := uint32(0x1f80|csrMode<<13|csrMode)
    %[1]s(&a[0],&b[0],&out[1],csr)
    if out[0] != 0xc3 || out[23] != 0xc3 || out[17] != 1 || out[18] != 0 {
     t.Fatalf("%[1]s flags/canary %%x",out)
    }
    gotCSR := uint32(out[19]) | uint32(out[20])<<8 | uint32(out[21])<<16 | uint32(out[22])<<24
    if gotCSR != csr {
     t.Fatalf("%[1]s CSR %%x != %%x",gotCSR,csr)
    }
    for i := 0; i < 16; i += %[2]d {
     want := difference(lane(a[i:],%[2]d),lane(b[i:],%[2]d),%[2]d,%[3]d)
     for j := 0; j < %[2]d; j++ {
      if out[i+j+1] != byte(want >> uint(8*j)) {
       t.Fatalf("%[1]s byte%%d got%%x want%%x",i+j,out,want)
      }
     }
    }
   }
  }
 }
`, name, bits/8, mode)
	}
	tests.WriteString("}\n")
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(),
		"value_amd64.s": assembly.String(), "value_test.go": tests.String(),
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
		t.Fatalf("actual original Go packed subtract oracle: %v\n%s", err, output)
	}
	t.Logf("%d actual Go SSE functions × 256 independent full-lane wrapping/saturation/MXCSR/flags/canary cases", len(opcodes))
}
