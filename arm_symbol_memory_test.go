package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func armSymbolMemoryFixture() (string, map[string]FuncSig, string, string) {
	var source, declarations, checks, goDeclarations, goChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		spec := armIntegerMemorySpecs[op]
		for _, offset := range []int{0, 1, 3, 11} {
			for _, condition := range []string{"", ".EQ", ".NE"} {
				load := fmt.Sprintf("symbol_load_%d", len(sigs))
				store := fmt.Sprintf("symbol_store_%d", len(sigs))
				fmt.Fprintf(&source, "TEXT %s(SB),$0-4\nMOVW $0x76543210,R0\nCMP R2,R2\n%s%s ·memory+%d(SB),R0\nMOVW R0,ret+0(FP)\nRET\n", load, op, condition, offset)
				fmt.Fprintf(&source, "TEXT %s(SB),$0-4\nMOVW value+0(FP),R0\nCMP R2,R2\n%s%s R0,·memory+%d(SB)\nRET\n", store, op, condition, offset)
				sigs[load] = FuncSig{Name: load, Ret: I32, Frame: FrameLayout{
					Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				}}
				sigs[store] = FuncSig{Name: store, Args: []LLVMType{I32}, Ret: Void, Frame: FrameLayout{
					Params: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				}}
				fmt.Fprintf(&declarations, "extern uint32_t %s(void);\nextern void %s(uint32_t);\n", load, store)
				fmt.Fprintf(&goDeclarations, "func %s() uint32\nfunc %s(value uint32)\n", load, store)
				var want uint32
				for i := 0; i < spec.bits/8; i++ {
					want |= uint32(byte((offset+i)*13+131)) << uint(8*i)
				}
				if spec.signed && spec.bits == 8 {
					want = uint32(int8(want))
				}
				if spec.signed && spec.bits == 16 {
					want = uint32(int16(want))
				}
				if condition == ".NE" {
					want = 0x76543210
				}
				fmt.Fprintf(&checks, "  reset_memory();\n  if (%s() != UINT32_C(%d)) { fprintf(stderr,\"%s load failed\\n\"); return 1; }\n  %s(UINT32_C(0xfedcba98));\n  for (unsigned i=0;i<sizeof memory;i++) { unsigned char want=(unsigned char)(i*13+131);\n", load, want, op+condition, store)
				fmt.Fprintf(&goChecks, "resetMemory()\nif %s() != uint32(%d) { panic(\"%s Go load oracle\") }\n%s(0xfedcba98)\nfor i := range memory { want := byte(i*13+131)\n", load, want, op+condition, store)
				if condition != ".NE" {
					fmt.Fprintf(&checks, "    if(i>=%d && i<%d) want=(unsigned char)(UINT32_C(0xfedcba98) >> (8*(i-%d)));\n", offset, offset+spec.bits/8, offset)
					fmt.Fprintf(&goChecks, "if i>=%d && i<%d { want=byte(uint32(0xfedcba98) >> (8*(i-%d))) }\n", offset, offset+spec.bits/8, offset)
				}
				fmt.Fprintf(&checks, "    if(memory[i]!=want) { fprintf(stderr,\"%s store canary failed\\n\"); return 2; }\n  }\n", op+condition)
				fmt.Fprintf(&goChecks, "if memory[i]!=want { panic(\"%s Go store canary oracle\") }\n}\n", op+condition)
			}
		}
	}
	main := "#include <stdint.h>\n#include <stdio.h>\nunsigned char memory[80];\n" + declarations.String() +
		"static void reset_memory(void) { for(unsigned i=0;i<sizeof memory;i++) memory[i]=(unsigned char)(i*13+131); }\nint main(void) {\n" + checks.String() + "return 0;\n}\n"
	goMain := "package main\nvar memory [80]byte\n" + goDeclarations.String() +
		"func resetMemory() { for i := range memory { memory[i]=byte(i*13+131) } }\nfunc main() {\n" + goChecks.String() + "}\n"
	return source.String(), sigs, main, goMain
}

func translateARMSymbolFixture(t *testing.T, triple string) (string, string, string, string) {
	t.Helper()
	source, sigs, main, goMain := armSymbolMemoryFixture()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir, source, main, goMain
}

func TestARMSymbolIntegerMemorySemantics(t *testing.T) {
	ir, _, _, _ := translateARMSymbolFixture(t, "armv7-unknown-linux-gnueabihf")
	for _, text := range []string{"load i32, ptr @memory, align 1", "load i8, ptr", "load i16, ptr", "sext i8", "zext i8", "sext i16", "zext i16"} {
		if !strings.Contains(ir, text) {
			t.Fatalf("symbol memory semantics missing %q", text)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, _, _, _ := translateARMSymbolFixture(t, triple)
		compileLLVMToObject(t, llc, triple, "arm-symbols.ll", "arm-symbols.o", ir)
	}
}

func TestARMSymbolIntegerMemoryGrammarMatchesGoEncoder(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm/asm5.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{A(MOV\w+), C_(ADDR|REG), C_NONE, C_(ADDR|REG), (64|65|93|94),`).FindAllStringSubmatch(string(data), -1)
	seen := make(map[string]int)
	for _, row := range rows {
		if row[2] == row[3] {
			continue
		}
		if _, ok := armIntegerMemorySpecs[row[1]]; !ok {
			t.Errorf("Go C_ADDR family member %s missing", row[1])
		}
		seen[row[1]]++
	}
	if len(seen) != 7 || len(seen) != len(armIntegerMemorySpecs) {
		t.Fatalf("symbol grammar has %d mnemonics, spec has %d", len(seen), len(armIntegerMemorySpecs))
	}
	for op, count := range seen {
		if count != 2 {
			t.Errorf("%s has %d C_ADDR rows, want load and store", op, count)
		}
	}
}

func TestARMSymbolIntegerMemoryCompleteForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT symbolforms(SB),$0-0\nCMP R2,R2\n")
	count := 0
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, offset := range []int{-4097, -1, 0, 1, 4097} {
			for _, suffix := range []string{"", ".U", ".P", ".W", ".U.P", ".U.W", ".P.W", ".U.P.W", ".EQ", ".NE.P", ".EQ.U.W"} {
				fmt.Fprintf(&source, "%s%s ·memory%+d(SB),R0\n%s%s R0,·memory%+d(SB)\n", op, suffix, offset, op, suffix, offset)
				count += 2
			}
		}
	}
	// An address constant is not a memory load. Go only provides MOVW for
	// this C_LCON row; narrow variants are covered by the rejection test.
	source.WriteString("MOVW $·memory+3(SB),R0\nRET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple,
			Sigs: map[string]FuncSig{"symbolforms": {Name: "symbolforms", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "arm-symbol-forms.ll", "arm-symbol-forms.o", ir)
	}
	t.Logf("checked %d C_ADDR forms plus MOVW address constant", count)
}

func TestARMSymbolIntegerMemoryRejectsNonGoForms(t *testing.T) {
	var instructions []string
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		instructions = append(instructions,
			op+" ·memory(SB),·other(SB)",
			op+" $0,·memory(SB)",
			op+" R0,$·memory(SB)",
			op+".S ·memory(SB),R0",
		)
		if op != "MOVW" {
			instructions = append(instructions, op+" $·memory(SB),R0")
		}
	}
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT invalidsymbol(SB),$0-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"invalidsymbol": {Name: "invalidsymbol", Ret: Void}},
			}); err == nil {
				t.Fatalf("translator accepted %q outside Go's symbol-memory grammar", instruction)
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARMSymbolMemory(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("actual ARM symbol execution is required by the Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatal("ARM cross-runtime needs a Linux amd64 or arm64 driver")
	}
	for _, name := range []string{"arm-linux-gnueabihf-gcc", "qemu-arm"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", name, err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, source, main, goMain := translateARMSymbolFixture(t, triple)
	dir := t.TempDir()
	source = strings.ReplaceAll(source, "TEXT symbol_", "TEXT ·symbol_")
	for name, contents := range map[string]string{
		"go.mod": "module armsymboloracle\n\ngo 1.20\n", "main.go": goMain, "oracle_arm.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "run", "-p=2", "-exec=qemu-arm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm", "GOARM=7", "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go ARM symbol oracle: %v\n%s", err, output)
	}
	t.Log("native Go ARM symbol oracle passed")
	// The object probe uses llc's static relocation model. Match it with a
	// non-PIE executable rather than relying on the cross GCC distro default.
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "arm_symbol_memory", triple, ir, main,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
