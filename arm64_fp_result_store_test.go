package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type arm64ResultStoreCase struct {
	resultBits int
	store      string
}

var arm64ResultStoreCases = []arm64ResultStoreCase{
	{8, "MOVH"}, {8, "MOVHU"}, {8, "MOVW"}, {8, "MOVWU"}, {8, "MOVD"},
	{16, "MOVW"}, {16, "MOVWU"}, {16, "MOVD"},
	{32, "MOVD"},
}

func (row arm64ResultStoreCase) name() string {
	return fmt.Sprintf("ret%d%s", row.resultBits, row.store)
}

func arm64ResultStoreSource() (declarations, assembly string) {
	var goSource, asm strings.Builder
	goSource.WriteString("package resultstore\n")
	for _, row := range arm64ResultStoreCases {
		fmt.Fprintf(&goSource, "func %s(value uint64) uint%d\n", row.name(), row.resultBits)
		fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$0-%d\nMOVD value+0(FP),R0\n%s R0,ret+8(FP)\nRET\n",
			row.name(), 8+row.resultBits/8, row.store)
	}
	return goSource.String(), asm.String()
}

func arm64ResultStoreIR(t *testing.T, triple string) string {
	t.Helper()
	declarations, source := arm64ResultStoreSource()
	pkg := mustGoPackage(t, "resultstore", declarations)
	result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Module.Dispose()
	return result.Module.String()
}

func TestARM64ABI0AlignedResultStoreObjects(t *testing.T) {
	_, source := arm64ResultStoreSource()
	requireARM64GoAssemblerResult(t, source, true)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "result-store.ll", "result-store.o", arm64ResultStoreIR(t, triple))
		})
	}
}

func TestARM64ABI0AlignedResultStoreRejectsUnprovedPadding(t *testing.T) {
	pkg := mustGoPackage(t, "resultstore", "package resultstore\nfunc store(value uint64) uint32\n")
	for _, test := range []struct {
		name, extent, before, after string
	}{
		{"wrong TEXT extent", "16", "", ""},
		{"frame address", "12", "MOVD $ret+8(FP),R2\n", ""},
		{"stack alias", "12", "MOVD RSP,R2\n", ""},
		{"goroutine stack root", "12", "MOVD g,R2\n", ""},
		{"implicit stack base", "12", "LDAR (ZR),R2\n", ""},
		{"opaque code", "12", "WORD $0xf9400be2\n", ""},
		{"full-width read", "12", "", "MOVD ret+8(FP),R2\n"},
		{"padding-only read", "12", "", "MOVBU ret+12(FP),R2\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT ·store(SB),4,$0-" + test.extent + "\nMOVD value+0(FP),R0\n" +
				test.before + "MOVD R0,ret+8(FP)\n" + test.after + "RET\n"
			result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
			})
			if err == nil {
				result.Module.Dispose()
				t.Fatal("unproved padding access translated")
			}
			if !strings.Contains(err.Error(), "FP frame range") {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64ABI0AlignedResultStores(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	declarations, assembly := arm64ResultStoreSource()
	var goMain, cMain, bridge strings.Builder
	goMain.WriteString("package main\n\n")
	cMain.WriteString("#include <stdint.h>\n")
	for _, row := range arm64ResultStoreCases {
		fmt.Fprintf(&cMain, "extern uint64_t observe_%s(uint64_t);\n", row.name())
		// Make the comparison through the translator's typed LLVM ABI.
		// Darwin C uses a zeroext contract on narrow integer returns.
		fmt.Fprintf(&bridge, `
define i64 @observe_%s(i64 %%value) {
  %%result = call i%d @%s(i64 %%value)
  %%wide = zext i%d %%result to i64
  ret i64 %%wide
}
`, row.name(), row.resultBits, row.name(), row.resultBits)
	}
	goMain.WriteString("func main() {\nfor _, value := range []uint64{")
	cMain.WriteString("int main(void) {\nconst uint64_t inputs[] = {")
	for _, value := range arm64PaddingRuntimeInputs() {
		fmt.Fprintf(&goMain, "%d,", value)
		fmt.Fprintf(&cMain, "UINT64_C(%d),", value)
	}
	goMain.WriteString("} {\n")
	cMain.WriteString("};\nfor (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {\n")
	cMain.WriteString("  uint64_t value = inputs[i];\n")
	for index, row := range arm64ResultStoreCases {
		fmt.Fprintf(&goMain, "if %s(value) != uint%d(value) { panic(%q) }\n", row.name(), row.resultBits, row.name())
		fmt.Fprintf(&cMain, "  if (observe_%s(value) != (uint%d_t)value) return %d;\n", row.name(), row.resultBits, index+1)
	}
	goMain.WriteString("}\n}\n")
	cMain.WriteString("}\nreturn 0;\n}\n")

	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":         "module resultstore\n\ngo 1.20\n",
		"main.go":        goMain.String(),
		"decl.go":        strings.Replace(declarations, "package resultstore", "package main", 1),
		"result_arm64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	args := []string{"run", "-p=1"}
	if len(runner) != 0 {
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "-exec="+quoted)
	}
	command := exec.CommandContext(ctx, "go", append(args, ".")...)
	command.Dir = dir
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH=arm64", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		command.Env = append(command.Env, "GOOS=linux")
	}
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("original Go ARM64 aligned result stores: %v\n%s", err, out)
	}
	ir := arm64ResultStoreIR(t, triple) + bridge.String()
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_result_store", triple, ir, cMain.String(), runner, optimization)
		})
	}
	if !t.Failed() {
		t.Logf("original Go and LLVM agreed on %d input and store-width combinations", len(arm64PaddingRuntimeInputs())*len(arm64ResultStoreCases))
	}
}
