package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type x86SourceStackRuntimeCase struct {
	name  string
	width int
	body  string
	flags bool
}

func x86SourceStackRuntimeCases(arch string) []x86SourceStackRuntimeCase {
	word, suffix, rawMove := 8, "Q", "WORD $0x8948\nBYTE $0xe5"
	rawRestore := "WORD $0x8948\nBYTE $0xec"
	rawAlign := "LONG $0xf8e48348"
	if arch == "386" {
		word, suffix, rawMove = 4, "L", "WORD $0xe589"
		rawRestore, rawAlign = "WORD $0xec89", "WORD $0xe483\nBYTE $0xfc"
	}
	var cases []x86SourceStackRuntimeCase
	for _, width := range []int{8, 16, 32, 64} {
		if arch == "386" && width == 64 {
			continue
		}
		move := map[int]string{8: "MOVB", 16: "MOVW", 32: "MOVL", 64: "MOVQ"}[width]
		cases = append(cases, x86SourceStackRuntimeCase{
			name: fmt.Sprintf("Physical%d", width), width: width,
			body: fmt.Sprintf("%s %d(SP),AX\nADD%s $7,AX\n%s AX,%d(SP)\nBYTE $0xc3", move, word, suffix, move, 2*word),
		})
	}
	finish := fmt.Sprintf("ADD%s $7,AX\nMOV%s AX,ret+%d(FP)\nBYTE $0xc3", suffix, suffix, word)
	start := "MOV" + suffix + " x+0(FP),AX\n"
	cases = append(cases,
		x86SourceStackRuntimeCase{name: "BalancedRaw", width: word * 8,
			body: start + "BYTE $0x55\n" + rawMove + "\n" + rawAlign + "\n" + rawRestore + "\nBYTE $0x5d\n" + finish},
		x86SourceStackRuntimeCase{name: "BalancedNamed", width: word * 8,
			body: start + "PUSH" + suffix + " BP\nMOV" + suffix + " SP,BP\nPUSH" + suffix + " AX\nMOV" + suffix + " $0,AX\nPOP" + suffix + " AX\nMOV" + suffix + " BP,SP\nPOP" + suffix + " BP\n" + finish},
		x86SourceStackRuntimeCase{name: "WordData", width: word * 8,
			body: start + "PUSHW AX\nMOVW $0,AX\nPOPW AX\n" + finish},
		x86SourceStackRuntimeCase{name: "WordImmediate", width: word * 8,
			body: start + "PUSHW $65530\nPOPW AX\n" + finish},
		x86SourceStackRuntimeCase{name: "Branch", width: word * 8,
			body: start + "CMP" + suffix + " AX,$1\nJE done\nADD" + suffix + " $0,BX\ndone:\n" + finish},
		x86SourceStackRuntimeCase{name: "FlagsStack", width: word * 8, flags: true,
			body: start + "CMP" + suffix + " AX,$1\nPUSHF" + suffix + "\n" +
				fmt.Sprintf("SUB%s $%d,SP\nADD%s $%d,SP\n", suffix, word, suffix, word) +
				"POPF" + suffix + "\nADC" + suffix + " $0,AX\n" + finish},
	)
	for _, flagSuffix := range []string{"W", suffix} {
		cases = append(cases, x86SourceStackRuntimeCase{
			name: "Flags" + flagSuffix, width: word * 8, flags: true,
			body: start + "CMP" + suffix + " AX,$1\nPUSHF" + flagSuffix + "\nADD" + suffix + " $0,BX\nPOPF" + flagSuffix + "\nADC" + suffix + " $0,AX\n" + finish,
		})
	}
	return cases
}

func x86SourceStackRuntimeSource(arch string) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for _, test := range x86SourceStackRuntimeCases(arch) {
		word, move := int64(8), "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		ty := map[int]LLVMType{8: I8, 16: I16, 32: I32, 64: I64}[test.width]
		text, sig, _ := x86SourceStackTypedFixture(arch, fmt.Sprintf("uint%d", test.width), ty, word, move, test.body)
		source.WriteString(strings.ReplaceAll(text, "·Value", "·"+test.name))
		sig.Name = test.name
		sigs[test.name] = sig
	}
	word := int64(8)
	if arch == "386" {
		word = 4
	}
	text, sig, _ := x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB",
		"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3")
	source.WriteString(strings.ReplaceAll(text, "·Value", "·PhysicalBool"))
	sig.Name = "PhysicalBool"
	sigs[sig.Name] = sig
	// Preserve the original identity kernel above byte-for-byte. This sibling
	// observes a physical result byte before its final logical bool conversion:
	// prematurely truncating the intermediate 2 to i1 would return false.
	text, sig, _ = x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB",
		"MOVB $2,@RESULT(SP)\nMOVB @RESULT(SP),AX\nSHRB $1,AX\nANDB $1,AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3")
	source.WriteString(strings.ReplaceAll(text, "·Value", "·PhysicalBoolIntermediate"))
	sig.Name = "PhysicalBoolIntermediate"
	sigs[sig.Name] = sig
	text, sig, _ = x86SourceStackTypedFixture(arch, "bool", I1, word, "MOVB",
		"MOVB $2,ret+@WORD(FP)\nMOVB ret+@WORD(FP),AX\nSHRB $1,AX\nANDB $1,AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3")
	source.WriteString(strings.ReplaceAll(text, "·Value", "·PhysicalBoolNamedFP"))
	sig.Name = "PhysicalBoolNamedFP"
	sigs[sig.Name] = sig
	return source.String(), sigs
}

func x86SourceStackGoOracle(arch string) string {
	var goSource strings.Builder
	goSource.WriteString("package sourceframe\nimport \"testing\"\n")
	for _, test := range x86SourceStackRuntimeCases(arch) {
		fmt.Fprintf(&goSource, "func %s(x uint%d) uint%d\n", test.name, test.width, test.width)
	}
	goSource.WriteString("func PhysicalBool(x bool) bool\n")
	goSource.WriteString("func PhysicalBoolIntermediate(x bool) bool\n")
	goSource.WriteString("func PhysicalBoolNamedFP(x bool) bool\n")
	goSource.WriteString("func TestNumerical(t *testing.T) {\n")
	for _, test := range x86SourceStackRuntimeCases(arch) {
		fmt.Fprintf(&goSource, `
	for iteration := 0; iteration < 64; iteration++ {
		for _, input := range []uint%d{0, 1, 17, 253, ^uint%d(0)-3} {
			want := input + 7
`, test.width, test.width)
		if test.flags {
			goSource.WriteString("\t\t\tif input == 0 { want++ }\n")
		}
		if test.name == "WordImmediate" {
			fmt.Fprintf(&goSource, "\t\t\twant = ((input & ^uint%d(65535)) | 65530) + 7\n", test.width)
		}
		fmt.Fprintf(&goSource, `
			canary := [4]uint64{11, 23, 37, 41}
			if got := %s(input); got != want || canary != [4]uint64{11, 23, 37, 41} {
				t.Fatalf("%s(%%#x)=%%#x, want %%#x; canary=%%v", input, got, want, canary)
			}
		}
	}
`, test.name, test.name)
	}
	goSource.WriteString("\tif PhysicalBool(false) || !PhysicalBool(true) { t.Fatal(\"bool byte slot\") }\n")
	goSource.WriteString("\tcanary := [4]uint64{11,23,37,41}\n\tif !PhysicalBoolIntermediate(false) || !PhysicalBoolIntermediate(true) || !PhysicalBoolNamedFP(false) || !PhysicalBoolNamedFP(true) || canary != [4]uint64{11,23,37,41} { t.Fatal(\"physical/named intermediate bool byte/canary\") }\n}\n")
	return goSource.String()
}

func x86SourceStackActualGoNumerical(t *testing.T, arch string, runner []string) {
	t.Helper()
	dir := t.TempDir()
	source, _ := x86SourceStackRuntimeSource(arch)
	for name, text := range map[string]string{
		"go.mod":               "module example.invalid/sourceframeoracle\n\ngo 1.20\n",
		"value_" + arch + ".s": source,
		"value_test.go":        x86SourceStackGoOracle(arch),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"test", "-p=2", "-vet=off", "-count=1"}
	if len(runner) != 0 {
		args = append(args, "-exec", strings.Join(runner, " "))
	}
	args = append(args, ".")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := append(os.Environ(), "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir, command.Env, command.WaitDelay = dir, env, 2*time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual Go %s original source numerical oracle: %v\n%s", arch, err, output)
	}
}

func x86SourceStackCOracle(arch string) string {
	var source strings.Builder
	source.WriteString("#include <stdint.h>\n")
	source.WriteString("#include <stdbool.h>\nextern bool PhysicalBool(bool);\nextern bool PhysicalBoolIntermediate(bool);\n")
	source.WriteString("extern bool PhysicalBoolNamedFP(bool);\n")
	for _, test := range x86SourceStackRuntimeCases(arch) {
		fmt.Fprintf(&source, "extern uint%d_t %s(uint%d_t);\n", test.width, test.name, test.width)
	}
	source.WriteString("int main(void) {\n")
	for _, test := range x86SourceStackRuntimeCases(arch) {
		fmt.Fprintf(&source, `
	for (unsigned iteration = 0; iteration < 64; iteration++) {
		const uint%d_t inputs[] = {0, 1, 17, 253, (uint%d_t)-4};
		for (unsigned index = 0; index < sizeof(inputs)/sizeof(inputs[0]); index++) {
			const uint%d_t input = inputs[index];
			uint%d_t want = input + 7;
`, test.width, test.width, test.width, test.width)
		if test.flags {
			source.WriteString("\t\t\tif (input == 0) want++;\n")
		}
		if test.name == "WordImmediate" {
			fmt.Fprintf(&source, "\t\t\twant = (input & ~(uint%d_t)65535) | 65530;\n\t\t\twant += 7;\n", test.width)
		}
		fmt.Fprintf(&source, `
			volatile uint64_t canary = UINT64_C(0x123456789abcdef0);
			if (%s(input) != want || canary != UINT64_C(0x123456789abcdef0)) return 1;
		}
	}
`, test.name)
	}
	source.WriteString("\tif (PhysicalBool(false) || !PhysicalBool(true)) return 2;\n")
	source.WriteString("\tvolatile uint64_t boolCanary = UINT64_C(0x123456789abcdef0);\n\tif (!PhysicalBoolIntermediate(false) || !PhysicalBoolIntermediate(true) || !PhysicalBoolNamedFP(false) || !PhysicalBoolNamedFP(true) || boolCanary != UINT64_C(0x123456789abcdef0)) return 3;\n\treturn 0;\n}\n")
	return source.String()
}

func TestX86RawReturnBoundSourceStackRuntimeForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		source, sigs := x86SourceStackRuntimeSource(target.arch)
		requireX86GoAssemblerResult(t, target.arch, source, true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs,
			ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, target.triple, "source-stack-forms.ll", "source-stack-forms.o", ir)
	}
}

func TestCrossLinuxRuntimeMatrixX86RawSourceStackNumerical(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("x86 source-stack numerical oracle runs in the required Linux/amd64 cross-runtime gate")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	t.Run("amd64", func(t *testing.T) {
		x86SourceStackActualGoNumerical(t, "amd64", nil)
		source, sigs := x86SourceStackRuntimeSource("amd64")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
			ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
		})
		if err != nil {
			t.Fatal(err)
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, "source_stack64", triple, ir, x86SourceStackCOracle("amd64"), runner)
	})
	// This required native owner must execute the original physical 386 bool
	// bytes too, even when the broader ARM/QEMU matrix is not selected. Explicit
	// cross execution retains its old dynamic guest transport independently.
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" || runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			t.Fatal("PLAN9ASM_CROSS_EXEC source-stack matrix requires Linux/amd64")
		}
		t.Run("386", func(t *testing.T) {
			runner = nil
			compiler := []string{"i686-linux-gnu-gcc", "-static", "-no-pie"}
			if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" {
				runner = []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"}
				compiler = []string{"i686-linux-gnu-gcc", "-no-pie"}
			}
			x86SourceStackActualGoNumerical(t, "386", runner)
			source, sigs := x86SourceStackRuntimeSource("386")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: sigs,
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
			})
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler,
				"source_stack32", "i386-unknown-linux-gnu", ir, x86SourceStackCOracle("386"), runner)
		})
	}
}
