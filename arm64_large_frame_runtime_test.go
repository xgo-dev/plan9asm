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

	"github.com/xgo-dev/llvm"
)

func TestARM64LargeFrameStructureFamilyAPIsAndObjects(t *testing.T) {
	source, pkg, cases := arm64PrivateStructureFixture(t)
	source = strings.ReplaceAll(source, "$120-16", "$496-16")
	source = strings.ReplaceAll(source, "ADD $16,RSP,R9", "ADD $16,R20,R9")
	source = strings.ReplaceAll(source, "ADD $16,RSP,R10", "ADD $16,R20,R10")
	requireARM64GoAssemblerResult(t, source, true)
	arm64LargeFrameCheckAPIs(t, source, pkg, nil, false, true)
	t.Logf("%d complete structure arrangements/counts/lanes/writeback consumers of the same Go R20 producer", len(cases))
}

func TestCrossLinuxRuntimeMatrixARM64LargeFrameStructureFamily(t *testing.T) {
	source, pkg, cases := arm64PrivateStructureFixture(t)
	source = strings.ReplaceAll(source, "$120-16", "$496-16")
	source = strings.ReplaceAll(source, "ADD $16,RSP,R9", "ADD $16,R20,R9")
	source = strings.ReplaceAll(source, "ADD $16,RSP,R10", "ADD $16,R20,R10")
	arm64RunPrivateStructureFixture(t, source, pkg, cases)
}

func TestCrossLinuxRuntimeMatrixARM64LargeFrameMemoryFamily(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source, pkg, cases := arm64LargeFrameMemoryFixture(t)
	var declarations, checks, cDeclarations, cChecks strings.Builder
	for _, tc := range cases {
		fmt.Fprintf(&declarations, "func %s(*byte,*byte)\n", tc.name)
		fmt.Fprintf(&cDeclarations, "extern void %s(const unsigned char *,unsigned char *);\n", tc.name)
		floating := 0
		if tc.floating {
			floating = 1
		}
		fmt.Fprintf(&checks, "check(%s,%d,%d,%d,%d)\n", tc.name, tc.width, tc.count, tc.signBits, floating)
		fmt.Fprintf(&cChecks, "if (check(%s,%d,%d,%d,%d)) return 1;\n", tc.name, tc.width, tc.count, tc.signBits, floating)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module largeframe\n\ngo 1.20\n",
		"main.go": arm64RawPrivateFrameOracleGo + declarations.String() +
			"func main() {\n" + checks.String() + "}\n",
		"oracle_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{"run", "-p=2", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go R20 numerical family: %v\n%s", err, output)
	}
	llvmCtx := llvm.NewContext()
	result, err := translateGoModuleInContext(llvmCtx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if err != nil {
		llvmCtx.Dispose()
		t.Fatal(err)
	}
	ir := result.Module.String()
	result.Module.Dispose()
	llvmCtx.Dispose()
	cSource := arm64RawPrivateFrameOracleC + cDeclarations.String() +
		"int main(void) {\n" + cChecks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "large_frame_memory", triple, ir, cSource, runner)
	t.Logf("actual Go + LLVM22/C independent reference: %d scalar/pair variants x 256 patterns x 5 unaligned offsets, complete input/output canaries", len(cases))
}

func TestCrossLinuxRuntimeMatrixARM64LargeFrameScalarEntry(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	source := arm64LargeFrameScalarSource(496)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module largeframe\n\ngo 1.20\n",
		"main.go": `package main

func LargeR20() uint64

func main() {
	for i := 0; i < 64; i++ {
		if got := LargeR20(); got != 0x123456789abcdef {
			panic(got)
		}
	}
}

`,
		"oracle_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"run", "-p=2", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go scalar R20 entry oracle: %v\n%s", err, output)
	}
	ir := arm64LargeFrameScalarIRs(t, source, triple)[0]
	ir = strings.ReplaceAll(ir, "@largeframe.LargeR20", "@LargeR20")
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "large_frame_scalar", triple, ir, `#include <stdint.h>
extern uint64_t LargeR20(void);
int main(void) {
	for (int i = 0; i < 64; i++) {
		if (LargeR20() != UINT64_C(0x123456789abcdef)) return 1;
	}
	return 0;
}
`, runner)
}

func TestCrossLinuxRuntimeMatrixARM64CheckedR20SoftwareValues(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, declarations, goChecks, cDeclarations, cChecks strings.Builder
	for index, frame := range []int{496, 224, 8, 0, -8} {
		flags, size := 4, frame
		if frame == -8 {
			flags, size = 516, 0
		}
		for variant, body := range []string{
			"MOVD $7,R20",
			"MOVD arg+0(FP),R20",
			"MOVD arg+0(FP),R8\nADD $7,R8,R20",
		} {
			name := fmt.Sprintf("value_%d_%d", index, variant)
			fmt.Fprintf(&source, "TEXT ·%s(SB),%d,$%d-16\n%s\nMOVD R20,ret+8(FP)\nRET\n", name, flags, size, body)
			fmt.Fprintf(&declarations, "func %s(uint64) uint64\n", name)
			fmt.Fprintf(&cDeclarations, "extern uint64_t %s(uint64_t);\n", name)
			want := []string{"7", "value", "value+7"}[variant]
			fmt.Fprintf(&goChecks, "if got := %s(value); got != %s { panic(got) }\n", name, want)
			fmt.Fprintf(&cChecks, "if (%s(value) != %s) return 1;\n", name, want)
		}
	}
	pkg := mustGoPackage(t, "largeframe", "package main\n"+declarations.String())
	dir := t.TempDir()
	goDriver := "package main\n" + declarations.String() + `
func main() {
	for i := uint64(0); i < 256; i++ {
		value := i*0x1020304050607081 ^ 0xcafebabef00dcafe
` + goChecks.String() + "\n}\n}\n"
	for name, body := range map[string]string{
		"go.mod":  "module largeframe\n\ngo 1.20\n",
		"main.go": goDriver, "oracle_arm64.s": source.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"run", "-p=2", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		cmd.Env = append(cmd.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go known R20 values: %v\n%s", err, output)
	}
	llvmCtx := llvm.NewContext()
	result, err := translateGoModuleInContext(llvmCtx, pkg, []byte(source.String()), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	})
	if err != nil {
		llvmCtx.Dispose()
		t.Fatal(err)
	}
	ir := result.Module.String()
	result.Module.Dispose()
	llvmCtx.Dispose()
	cDriver := "#include <stdint.h>\n" + cDeclarations.String() + `
int main(void) {
	for (uint64_t i = 0; i < 256; i++) {
		uint64_t value = i*UINT64_C(0x1020304050607081) ^ UINT64_C(0xcafebabef00dcafe);
` + cChecks.String() + "\n}\nreturn 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "known_r20_values", triple, ir, cDriver, runner)
	t.Log("actual Go + LLVM22/C: 5 frame modes x 3 literal/FP-load/FP-arithmetic values x 256 full-width patterns")
}
