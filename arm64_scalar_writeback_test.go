package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var arm64ScalarWritebackOps = []struct {
	op     string
	bits   int
	signed bool
}{
	{"MOVD", 64, false},
	{"MOVW", 32, true},
	{"MOVWU", 32, false},
	{"MOVH", 16, true},
	{"MOVHU", 16, false},
	{"MOVB", 8, true},
	{"MOVBU", 8, false},
}

func TestARM64ScalarWritebackCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	// The Cartesian product changes SP by a nonzero net amount. Preserve the
	// real entry SP in a register that none of these forms writes, then restore
	// it before the caller RET. This is an object-form oracle, not execution of
	// deliberately unaligned SP accesses or unknown-pointer R1 accesses.
	source.WriteString("TEXT scalarWritebackForms(SB),$0-0\nMOVD RSP,R20\n")
	for _, form := range arm64ScalarWritebackOps {
		for _, suffix := range []string{".P", ".W"} {
			for _, off := range []int{-256, -1, 0, 1, 255} {
				fmt.Fprintf(&source, "%s%s %d(R1), R2\n", form.op, suffix, off)
				fmt.Fprintf(&source, "%s%s %d(RSP), ZR\n", form.op, suffix, off)
				fmt.Fprintf(&source, "%s%s R2, %d(R1)\n", form.op, suffix, off)
				fmt.Fprintf(&source, "%s%s ZR, %d(RSP)\n", form.op, suffix, off)
				fmt.Fprintf(&source, "%s%s $0, %d(R1)\n", form.op, suffix, off)
				fmt.Fprintf(&source, "%s%s $0, %d(RSP)\n", form.op, suffix, off)
			}
		}
	}
	source.WriteString("MOVD R20,RSP\nRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{
			"scalarWritebackForms": {Name: "scalarWritebackForms", Ret: Void},
		}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "scalar-writeback.ll", "scalar-writeback.o", ir)
	}
}

func TestARM64ScalarWritebackRejectsGoInvalidForms(t *testing.T) {
	for _, instruction := range []string{
		"MOVD.P R1, R2", "MOVD.W $1, R2",
		"MOVD.P frame+0(FP), R2", "MOVD.W R2, frame+0(FP)",
		"MOVD.P data(SB), R2", "MOVD.W R2, data(SB)",
		"MOVD.P (R1)(R2), R3", "MOVD.W R3, (R1)(R2)",
		"MOVD.P 256(R1), R2", "MOVD.W R2, -257(R1)",
		"MOVD.P 8(R1), R1", "MOVWU.W R1, 4(R1)",
		"MOVBW.P R2, 1(R1)", "MOVHW.W R2, 1(R1)",
		"MOVD.P $1, 8(R1)", "MOVD.W $-1, 8(R1)",
		"MOVW.P $1, 4(R1)", "MOVW.W $-1, 4(R1)",
		"MOVWU.P $1, 4(R1)", "MOVWU.W $-1, 4(R1)",
		"MOVH.P $1, 2(R1)", "MOVH.W $-1, 2(R1)",
		"MOVHU.P $1, 2(R1)", "MOVHU.W $-1, 2(R1)",
		"MOVB.P $1, 1(R1)", "MOVB.W $-1, 1(R1)",
		"MOVBU.P $1, 1(R1)", "MOVBU.W $-1, 1(R1)",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT badScalarWriteback(SB),$0-16\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"badScalarWriteback": {Name: "badScalarWriteback", Ret: Void},
			}})
			if err == nil {
				t.Fatal("translator accepted Go-rejected scalar memory writeback")
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64ScalarWriteback(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, declarations, checks, goDeclarations, goChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, form := range arm64ScalarWritebackOps {
		for _, suffix := range []string{"", ".P", ".W"} {
			for _, off := range []int{-4, 0, 4} {
				for _, access := range []struct {
					store bool
					zero  bool
				}{
					{}, {store: true}, {store: true, zero: true},
				} {
					store := access.store
					name := fmt.Sprintf("scalar_wb_%d", len(sigs))
					instruction := fmt.Sprintf("%s%s %d(R1), R4", form.op, suffix, off)
					if store {
						instruction = fmt.Sprintf("%s%s R2, %d(R1)", form.op, suffix, off)
					}
					if access.zero {
						instruction = fmt.Sprintf("%s%s $0, %d(R1)", form.op, suffix, off)
					}
					fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD base+0(FP), R1\nMOVD R1, R0\nMOVD value+8(FP), R2\nMOVD out+16(FP), R3\n%s\n", name, instruction)
					if !store {
						source.WriteString("MOVD R4, (R3)\n")
					}
					source.WriteString("SUB R0, R1, R5\nMOVD R5, ret+24(FP)\nRET\n")
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, I64, Ptr}, Ret: I64, Frame: FrameLayout{
						Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1}},
						Results: []FrameSlot{{Offset: 24, Type: I64, Index: 0, Field: -1}},
					}}
					fmt.Fprintf(&declarations, "extern int64_t %s(unsigned char *, uint64_t, uint64_t *);\n", name)
					fmt.Fprintf(&goDeclarations, "func %s(base *byte, value uint64, out *uint64) int64\n", name)
					addressOff := off
					baseDelta := off
					if suffix == ".P" {
						addressOff = 0
					}
					if suffix == "" {
						baseDelta = 0
					}
					fmt.Fprintf(&goChecks, "{\nvar buffer, expected [128]byte\nfor i := range buffer { buffer[i] = byte(i*13 + 131) }\nexpected = buffer\nvar observed, want uint64\nvalue := uint64(0xfedcba9876543210)\n")
					if access.zero {
						goChecks.WriteString("value = 0\n")
					}
					if store {
						fmt.Fprintf(&goChecks, "for i := 0; i < %d; i++ { expected[%d+i] = byte(value >> (8*i)) }\n", form.bits/8, 64+addressOff)
					} else {
						fmt.Fprintf(&goChecks, "for i := 0; i < %d; i++ { want |= uint64(buffer[%d+i]) << (8*i) }\n", form.bits/8, 64+addressOff)
						if form.signed {
							fmt.Fprintf(&goChecks, "want = uint64(int64(int%d(want)))\n", form.bits)
						}
					}
					fmt.Fprintf(&goChecks, "delta := %s(&buffer[64], value, &observed)\nif delta != %d || observed != want || buffer != expected { println(\"%s\", delta, observed, want); panic(\"Go scalar writeback oracle\") }\n}\n", name, baseDelta, instruction)
					fmt.Fprintf(&checks, "  { /* %s */\n    unsigned char bytes[128], expected[128];\n    for (unsigned i = 0; i < sizeof bytes; i++) bytes[i] = (unsigned char)(i * 13 + 131);\n    memcpy(expected, bytes, sizeof bytes);\n    uint64_t observed = 0, want = 0, value = UINT64_C(0xfedcba9876543210);\n", instruction)
					if access.zero {
						checks.WriteString("    value = 0;\n")
					}
					if store {
						fmt.Fprintf(&checks, "    memcpy(expected + %d, &value, %d);\n", 64+addressOff, form.bits/8)
					} else {
						fmt.Fprintf(&checks, "    memcpy(&want, bytes + %d, %d);\n", 64+addressOff, form.bits/8)
						if form.signed {
							fmt.Fprintf(&checks, "    want = (uint64_t)(int64_t)(int%d_t)want;\n", form.bits)
						}
					}
					fmt.Fprintf(&checks, "    int64_t delta = %s(bytes + 64, value, &observed);\n    if (delta != %d || observed != want || memcmp(bytes, expected, sizeof bytes)) { fprintf(stderr, \"%s delta=%%lld want=%d observed=%%llx expected=%%llx\\n\", (long long)delta, (unsigned long long)observed, (unsigned long long)want); return 1; }\n  }\n", name, baseDelta, instruction, baseDelta)
				}
			}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	goSource := "package main\n" + goDeclarations.String() + "func main() {\n" + goChecks.String() + "}\n"
	arm64ScalarWritebackGoOracle(t, source.String(), goSource, len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "scalar_writeback", triple, ir, main, runner)
}

func arm64ScalarWritebackGoOracle(t *testing.T, source, main string, cross bool) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":         "module scalarwritebackoracle\n\ngo 1.20\n",
		"main.go":        main,
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT scalar_wb_", "TEXT ·scalar_wb_"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"run", "-p=2", "."}
	env := append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0")
	if cross {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
		env = append(env, "GOOS=linux")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir, cmd.Env = dir, env
	if out, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("native Go scalar writeback oracle: %v\n%s", err, out)
	}
}
