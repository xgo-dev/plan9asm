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

// Independent of the lowering table: Go's AMADD encoder row uses Rm, Ra, Rn,
// Rd, while architectural assembly uses Rd, Rn, Rm, Ra.
var arm64MultiplyAccumulateTestOps = []string{
	"MADD", "MSUB", "MADDW", "MSUBW", "SMADDL", "SMSUBL", "UMADDL", "UMSUBL",
}

var arm64MultiplyAccumulateInputs = [][3]uint64{
	{2, 3, 11}, {0, 1, 7}, {^uint64(0), 2, 3},
	{0xffffffff80000003, 0x8000000000000005, 0x1020304050607080},
	{0x80000000, 0xffffffff, ^uint64(0)}, {1 << 63, 1 << 63, 1 << 63},
}

func arm64MultiplyAccumulateSource(t *testing.T) string {
	t.Helper()
	var named, machine, results []string
	for _, op := range arm64MultiplyAccumulateTestOps {
		for shape := 0; shape < 8; shape++ {
			registers := []int{0, 1, 2, 4}
			if shape >= 1 && shape <= 3 {
				registers[3] = shape - 1 // Each destination/source alias.
			} else if shape >= 4 && shape <= 6 {
				registers[shape-4] = 31 // Each zero source, including the addend.
			} else if shape == 7 {
				registers[3] = 31
			}
			goReg := func(n int) string {
				if n == 31 {
					return "ZR"
				}
				return fmt.Sprintf("R%d", n)
			}
			machineReg := func(n, width int) string {
				prefix := "x"
				if width == 32 {
					prefix = "w"
				}
				if n == 31 {
					return prefix + "zr"
				}
				return fmt.Sprintf("%s%d", prefix, n)
			}
			width, resultWidth := 64, 64
			if strings.HasSuffix(op, "W") || strings.HasSuffix(op, "L") {
				width = 32
			}
			if strings.HasSuffix(op, "W") {
				resultWidth = 32
			}
			machine = append(machine, fmt.Sprintf("%s %s, %s, %s, %s", strings.ToLower(strings.TrimSuffix(op, "W")),
				machineReg(registers[3], resultWidth), machineReg(registers[1], width),
				machineReg(registers[0], width), machineReg(registers[2], resultWidth)))
			named = append(named, fmt.Sprintf("%s %s,%s,%s,%s", op, goReg(registers[0]),
				goReg(registers[2]), goReg(registers[1]), goReg(registers[3])))
			result := registers[3]
			if result == 31 {
				result = 0 // Writing ZR must not change the input.
			}
			results = append(results, goReg(result))
		}
	}
	// One assembler process for the whole independent-axis matrix.
	words := assembleARM64LLVMWords(t, machine, "")
	var source strings.Builder
	source.WriteString("TEXT multiplyAccumulate(SB),$0-32\nMOVD out+24(FP),R3\n")
	for i, instruction := range named {
		for kind, form := range []string{instruction, fmt.Sprintf("WORD $%#08x", words[i])} {
			source.WriteString("MOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD add+16(FP),R2\n")
			fmt.Fprintf(&source, "%s\nMOVD %s,%d(R3)\n", form, results[i], (i*2+kind)*8)
		}
	}
	source.WriteString("RET\n")
	return source.String()
}

func arm64MultiplyAccumulateExpected(input [3]uint64) []uint64 {
	var result []uint64
	for _, op := range arm64MultiplyAccumulateTestOps {
		for shape := 0; shape < 8; shape++ {
			operands := input
			if shape >= 4 && shape <= 6 {
				operands[shape-4] = 0
			}
			a, b, add := operands[0], operands[1], operands[2]
			if strings.HasPrefix(op, "S") {
				a, b = uint64(int64(int32(a))), uint64(int64(int32(b)))
			} else if strings.HasPrefix(op, "U") {
				a, b = uint64(uint32(a)), uint64(uint32(b))
			}
			want := add + a*b
			if strings.Contains(op, "SUB") {
				want = add - a*b
			}
			if strings.HasSuffix(op, "W") {
				want = uint64(uint32(want))
			}
			if shape == 7 {
				want = input[0]
			}
			result = append(result, want, want)
		}
	}
	return result
}

func arm64MultiplyAccumulateIR(t *testing.T, triple string) (string, string) {
	t.Helper()
	source := arm64MultiplyAccumulateSource(t)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"multiplyAccumulate": {
			Name: "multiplyAccumulate", Args: []LLVMType{I64, I64, I64, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var main strings.Builder
	main.WriteString(`#include <stdint.h>
#include <stdio.h>
extern void multiplyAccumulate(uint64_t, uint64_t, uint64_t, uint64_t*);
int main(void) {
`)
	for i, input := range arm64MultiplyAccumulateInputs {
		want := arm64MultiplyAccumulateExpected(input)
		fmt.Fprintf(&main, "{ uint64_t got[%d] = {0};\nmultiplyAccumulate(%dULL,%dULL,%dULL,got);\n", len(want), input[0], input[1], input[2])
		main.WriteString("const uint64_t want[] = {\n")
		for _, value := range want {
			fmt.Fprintf(&main, "%dULL,\n", value)
		}
		fmt.Fprintf(&main, `};
  for (unsigned j = 0; j < %d; j++) {
    if (got[j] != want[j]) {
      fprintf(stderr, "multiply input=%d case=%%u actual=%%llx expected=%%llx\n",
              j, (unsigned long long)got[j], (unsigned long long)want[j]);
      return 1;
    }
  }
}
`, len(want), i)
	}
	main.WriteString("return 0;\n}\n")
	return ir, main.String()
}

func TestARM64MultiplyAccumulateLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64MultiplyAccumulateIR(t, triple)
			compileLLVMToObject(t, llc, triple, "multiply.ll", "multiply.o", ir)
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "multiply", triple, ir, main, nil)
			}
		})
	}
}

func TestARM64MultiplyAccumulateNativeGo(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !cross {
		t.Skip("native Go oracle runs on arm64 or required Linux/QEMU")
	}
	source := strings.Replace(arm64MultiplyAccumulateSource(t), "TEXT multiplyAccumulate", "TEXT ·multiplyAccumulate", 1)
	var main strings.Builder
	main.WriteString(`package main
func multiplyAccumulate(a, b, add uint64, out *uint64)
func main() {
`)
	for i, input := range arm64MultiplyAccumulateInputs {
		want := arm64MultiplyAccumulateExpected(input)
		fmt.Fprintf(&main, "{ var got [%d]uint64\nmultiplyAccumulate(%d,%d,%d,&got[0])\nwant := [...]uint64{", len(want), input[0], input[1], input[2])
		for _, value := range want {
			fmt.Fprintf(&main, "%d,", value)
		}
		fmt.Fprintf(&main, `}
  for j := range want {
    if got[j] != want[j] {
      println(%d, j, got[j], want[j])
      panic("multiply mismatch")
    }
  }
}
`, i)
	}
	main.WriteString("}\n")
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":  "module multiplyoracle\n\ngo 1.20\n",
		"main.go": main.String(), "multiply_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"run", "."}
	if cross {
		if _, err := exec.LookPath("qemu-aarch64"); err != nil {
			t.Fatal(err)
		}
		args = []string{"run", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Go multiply oracle: %v\n%s", err, out)
	}
}

func TestARM64MultiplyAccumulateRejectsNonGoForms(t *testing.T) {
	if len(arm64MultiplyAccumulateOps) != len(arm64MultiplyAccumulateTestOps) {
		t.Fatal("multiply-accumulate grammar differs from the complete Go AMADD family")
	}
	for _, op := range arm64MultiplyAccumulateTestOps {
		if _, ok := arm64MultiplyAccumulateOps[Op(op)]; !ok {
			t.Fatalf("missing Go AMADD family member %s", op)
		}
		forms := []string{
			op + " R0,R1,R2", op + " R0,R1,R2,R3,R4", op + ".P R0,R1,R2,R3",
			op + " $1,R1,R2,R3", op + " R0,(R1),R2,R3", op + " R0,R1,F2,R3",
		}
		for position := 0; position < 4; position++ {
			operands := []string{"R0", "R1", "R2", "R3"}
			operands[position] = "RSP"
			forms = append(forms, op+" "+strings.Join(operands, ","))
		}
		for _, instruction := range forms {
			t.Run(instruction, func(t *testing.T) {
				source := "TEXT bad(SB),$0-0\n" + instruction + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					return
				}
				_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
				if err == nil {
					t.Fatalf("accepted form rejected by Go: %s", instruction)
				}
			})
		}
	}
}
