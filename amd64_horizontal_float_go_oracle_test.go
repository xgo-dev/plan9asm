package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86HorizontalFloatOriginalGoBitOracle(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\n")
	tests.WriteString(`package oracle
import ("encoding/binary";"testing")
func TestOriginalHorizontalGolden(t *testing.T) {
`)
	for index, opcode := range []string{"HADDPS", "HADDPD", "HSUBPS", "HSUBPD"} {
		name, bits, move := fmt.Sprintf("horizontal%d", index), 32, "MOVUPS"
		if strings.HasSuffix(opcode, "PD") {
			bits, move = 64, "MOVUPD"
		}
		fmt.Fprintf(&declarations, "func %s(out *[20]byte,a,b *[16]byte,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-28\nSTMXCSR saved-4(SP)\nLDMXCSR csr+24(FP)\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\n%s (BX),X0\n%s (CX),X1\n%s X0,X1\nMOVUPS X1,(AX)\nSTMXCSR 16(AX)\nLDMXCSR saved-4(SP)\nRET\n", name, move, move, opcode)
		// Different qNaN/sNaN payloads in both halves establish horizontal
		// pair priority independently of the production binary helper.
		left, right, quiet := uint64(0x7f812345), uint64(0xffc45678), uint64(0x7fc12345)
		if bits == 64 {
			left, right, quiet = 0x7ff0123456789abc, 0xfff8fedcba987654, 0x7ff8123456789abc
		}
		fmt.Fprintf(&tests, `{
 var a,b [16]byte;var out [20]byte
 for lane:=0;lane<16/%[2]d;lane++ {
  value:=uint64(0x%[3]x);if lane%%2!=0 {value=0x%[4]x}
  if %[5]d==32 {binary.LittleEndian.PutUint32(a[lane*4:],uint32(value));binary.LittleEndian.PutUint32(b[lane*4:],uint32(value))} else {binary.LittleEndian.PutUint64(a[lane*8:],value);binary.LittleEndian.PutUint64(b[lane*8:],value)}
 }
 %[1]s(&out,&a,&b,0x1f80)
 for lane:=0;lane<16/%[2]d;lane++ {
  var got uint64;if %[5]d==32 {got=uint64(binary.LittleEndian.Uint32(out[lane*4:]))}else{got=binary.LittleEndian.Uint64(out[lane*8:])}
  if got!=0x%[6]x {t.Fatalf("%[1]s pair priority lane=%%d got=%%x",lane,got)}
 }
 if flags:=binary.LittleEndian.Uint32(out[16:]);flags!=0x1f81 {t.Fatalf("%[1]s sNaN flags=%%x",flags)}
}
`, name, bits/8, left, right, bits, quiet)
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
		t.Fatalf("actual original Go horizontal bit/flags oracle: %v\n%s", err, output)
	}
}
