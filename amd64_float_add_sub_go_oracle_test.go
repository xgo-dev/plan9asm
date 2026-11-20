package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86FloatAddSubOriginalGoBitOracle(t *testing.T) {
	_, _, _, _ = x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\n")
	tests.WriteString(`package oracle
import "testing"
func TestOriginalGoBinaryGolden(t *testing.T) {
`)
	for _, bits := range []int{32, 64} {
		for _, operation := range []string{"ADD", "SUB"} {
			name := fmt.Sprintf("%s%d", strings.ToLower(operation), bits)
			// gc's amd64 ABI0 result area starts at the next pointer alignment,
			// independently of the four-byte parameter/result element width.
			lane, move, frame, first, second, control, result, flags := "SS", "MOVSS", 24, 0, 4, 8, 16, 20
			if bits == 64 {
				lane, move, frame, second, control, result, flags = "SD", "MOVSD", 36, 8, 16, 24, 32
			}
			fmt.Fprintf(&declarations, "func %s(a,b uint%d,csr uint32) (value uint%d,flags uint32)\n", name, bits, bits)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-%d\nSTMXCSR saved-4(SP)\nLDMXCSR csr+%d(FP)\n%s a+%d(FP),X0\n%s b+%d(FP),X1\n%s%s X1,X0\n%s X0,value+%d(FP)\nSTMXCSR flags+%d(FP)\nLDMXCSR saved-4(SP)\nRET\n", name, frame, control, move, first, move, second, operation, lane, move, result, flags)
			// Literal special-value vectors are not computed by the production
			// helper or a host's language-level NaN canonicalization rules.
			vectors := [][3]uint64{{0x7fc12345, 0xffc45678, 0x7fc12345}, {0x7f812345, 0xffc45678, 0x7fc12345}, {0x3f800000, 0xff845678, 0xffc45678}}
			if bits == 64 {
				vectors = [][3]uint64{{0x7ff8123456789abc, 0xfff8fedcba987654, 0x7ff8123456789abc}, {0x7ff0123456789abc, 0xfff8fedcba987654, 0x7ff8123456789abc}, {0x3ff0000000000000, 0xfff0fedcba987654, 0xfff8fedcba987654}}
			}
			for index, vector := range vectors {
				flags := 0x1f80
				if index > 0 {
					flags |= 1
				}
				fmt.Fprintf(&tests, "if got,flags:=%s(0x%x,0x%x,0x1f80);got!=0x%x || flags!=0x%x {t.Fatalf(\"%s NaN got=%%x flags=%%x\",got,flags)}\n", name, vector[0], vector[1], vector[2], flags, name)
			}
			one, half, next := uint64(0x3f800000), uint64(0x33800000), uint64(0x3f800001)
			if bits == 64 {
				one, half, next = 0x3ff0000000000000, 0x3ca0000000000000, 0x3ff0000000000001
			}
			if operation == "SUB" {
				half |= uint64(1) << (bits - 1) // 1-(-half ULP) has the same tie
			}
			for mode := 0; mode < 4; mode++ {
				want := one
				if mode == 2 {
					want = next
				}
				fmt.Fprintf(&tests, "if got,flags:=%s(0x%x,0x%x,0x%x);got!=0x%x || flags!=0x%x {t.Fatalf(\"%s mode%d got=%%x flags=%%x\",got,flags)}\n", name, one, half, 0x1f80|mode<<13, want, 0x1fa0|mode<<13, name, mode)
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
		t.Fatalf("actual original Go SSE bit/round oracle: %v\n%s", err, output)
	}
}
