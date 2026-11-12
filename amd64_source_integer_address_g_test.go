package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	goparser "go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const x86ActualGoGRegistration = `if linkArch == &x86.Linkamd64 {
	register["g"] = x86.REGG
}`

func x86ActualGoGRegistrationRule(source []byte) error {
	set := token.NewFileSet()
	file, err := goparser.ParseFile(set, "arch.go", source, 0)
	if err != nil {
		return err
	}
	count, references := 0, 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "archX86" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			index, ok := node.(*ast.IndexExpr)
			if !ok {
				return true
			}
			name, named := index.X.(*ast.Ident)
			literal, text := index.Index.(*ast.BasicLit)
			if named && name.Name == "register" && text && literal.Value == `"g"` {
				references++
			}
			return true
		})
		for _, statement := range function.Body.List {
			conditional, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			var body bytes.Buffer
			if err := format.Node(&body, set, conditional); err != nil {
				return err
			}
			if strings.Contains(body.String(), `register["g"]`) {
				count++
				if strings.Join(strings.Fields(body.String()), " ") != strings.Join(strings.Fields(x86ActualGoGRegistration), " ") {
					return fmt.Errorf("unreviewed actual Go g registration: %s", body.String())
				}
			}
		}
	}
	if count != 1 || references != 1 {
		return fmt.Errorf("actual Go g registration count %d / references %d", count, references)
	}
	return nil
}

func TestX86UnnamedAddressImmediateGSourceModeCPP(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, replacement := range []string{"g", "R14"} {
			t.Run(arch+"/"+replacement, func(t *testing.T) {
				source := "#define REG " + replacement + "\nTEXT addr(SB),4,$0-0\nADDL $1(REG),DX\nRET\n"
				accepted := arch == "amd64" || replacement == "R14"
				x86ScalarLiteralExpectedGoListing(t, arch, source, accepted)
				expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{FileName: "g-source.s"})
				if err != nil {
					t.Fatal(err)
				}
				file, err := Parse(ArchAMD64, expanded)
				if err != nil {
					t.Fatal(err)
				}
				original := file.Funcs[0].Instrs[1]
				if original.Args[0].Sym != "$1("+replacement+")" {
					t.Fatal("CPP or parser lost the actual source register token")
				}
				_, changed, err := normalizeX86SourceIntegerAddress(original, arch)
				if accepted != (changed && err == nil) {
					t.Fatalf("CPP token acquired another source architecture: %v", err)
				}
			})
		}
	}
	if _, err := Parse(ArchAMD64, "TEXT addr(SB),4,$0-0\nADDL $1(REG),DX\nRET\n"); err == nil {
		// Unexpanded register identifiers are not a qualified alias. A parser
		// may retain unknown symbols, but complete normalization must reject.
		file, _ := Parse(ArchAMD64, "TEXT addr(SB),4,$0-0\nADDL $1(REG),DX\nRET\n")
		if _, err := normalizeX86SourceIntegerAddresses(file, Options{}); err == nil {
			t.Fatal("an unresolved CPP register token acquired g qualification")
		}
	}
}

func TestX86UnnamedAddressImmediateGSourceModeActualRule(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := x86ActualGoGRegistrationRule(source); err != nil {
		t.Fatal(err)
	}
	t.Logf("ACTUAL_G_REGISTER_ROLE sourceSHA=%x Go=%s", sha256.Sum256(source), runtime.Version())
	for _, change := range [][2]string{
		{"&x86.Linkamd64", "&x86.Link386"},
		{`register["g"]`, `register["G"]`},
		{"x86.REGG", "x86.REG_AX"},
		{"==", "!="},
	} {
		copy := strings.Replace(x86ActualGoGRegistration, change[0], change[1], 1)
		fixture := "package arch\nfunc archX86() {\n" + copy + "\n}\n"
		if x86ActualGoGRegistrationRule([]byte(fixture)) == nil {
			t.Fatal("changed actual architecture qualifier accepted")
		}
	}
}

func TestX86UnnamedAddressImmediateGSourceModeActualGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, annotation := range []string{"g", "R14"} {
			for _, address := range []string{
				"1(" + annotation + ")",
				"1(" + annotation + "*1)",
				"1(AX)(" + annotation + "*2)",
				"1(" + annotation + ")(CX)",
				"1 ( " + annotation + " )",
				"1(AX) ( " + annotation + " * 2 )",
			} {
				t.Run(arch+"/"+address, func(t *testing.T) {
					source := "TEXT addr(SB),4,$0-0\nADDL $" + address + ",DX\nRET\n"
					accepted := arch == "amd64" || annotation == "R14"
					x86ScalarLiteralExpectedGoListing(t, arch, source, accepted)
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediateGSourceModeCompleteConstantRows(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{
			"MOV", "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR", "CMP", "TEST",
			"SAL", "SHL", "SHR", "SAR", "ROL", "ROR", "RCL", "RCR", "IMUL", "IMUL3",
			"BT", "BTC", "BTR", "BTS", "PUSH",
		} {
			for _, suffix := range []string{"B", "W", "L", "Q"} {
				if suffix == "Q" && arch == "386" || stem == "MOV" && suffix != "B" && suffix != "W" ||
					suffix == "B" && (strings.HasPrefix(stem, "IMUL") || strings.HasPrefix(stem, "BT") || stem == "PUSH") ||
					stem == "PUSH" && (suffix == "L" && arch != "386" || suffix == "Q" && arch != "amd64") {
					continue
				}
				t.Run(arch+"/"+stem+suffix, func(t *testing.T) {
					for _, annotation := range []string{"g", "R14"} {
						operands := "$1(" + annotation + "),DX"
						if stem == "CMP" {
							operands = "DX,$1(" + annotation + ")"
						} else if stem == "IMUL3" {
							operands = "$1(" + annotation + "),BX,DX"
						} else if stem == "PUSH" {
							operands = "$1(" + annotation + ")"
						}
						ending := "RET\n"
						if stem == "PUSH" {
							ending = "POP" + suffix + " DX\nRET\n"
						}
						source := "TEXT addr(SB),4,$0-0\n" + stem + suffix + " " + operands + "\n" + ending
						accepted := annotation == "R14" || arch == "amd64"
						if accepted {
							original := x86PackedShiftActualGoBytes(t, arch, source)
							plain := x86PackedShiftActualGoBytes(t, arch, strings.ReplaceAll(source, "("+annotation+")", ""))
							if !bytes.Equal(original, plain) {
								t.Fatal("ignored annotation changed original instruction bytes")
							}
						} else {
							x86ScalarLiteralExpectedGoListing(t, arch, source, false)
						}
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						_, changed, err := normalizeX86SourceIntegerAddress(file.Funcs[0].Instrs[1], arch)
						if accepted != (changed && err == nil) {
							t.Fatalf("source g qualifier differs from actual Go: %s: %v", annotation, err)
						}
					}
				})
			}
		}
	}
}

func TestX86UnnamedAddressImmediateGSourceModeImmutableAndIsolated(t *testing.T) {
	source := "TEXT addr(SB),4,$0-0\nADDL $1(g),DX\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	original := file.Funcs[0].Instrs[1]
	if original.Args[0].Sym != "$1(g)" {
		t.Fatal("parser destroyed the original register spelling")
	}
	derived, err := normalizeX86SourceIntegerAddresses(file, Options{})
	if err != nil || !reflect.DeepEqual(file.Funcs[0].Instrs[1], original) || derived.Funcs[0].Instrs[1].Args[0].Kind != OpImm {
		t.Fatalf("mode adapter changed the original input: %v", err)
	}
	again, err := normalizeX86SourceIntegerAddresses(derived, Options{})
	if err != nil || !reflect.DeepEqual(derived, again) {
		t.Fatal("source g normalization is not idempotent")
	}
	for _, role := range []string{"LOCK", "raw", "frame", "addressBits", "encoded"} {
		t.Run(role, func(t *testing.T) {
			copy := *file
			copy.Funcs = append([]Func(nil), file.Funcs...)
			copy.Funcs[0].Instrs = append([]Instr(nil), file.Funcs[0].Instrs...)
			switch role {
			case "LOCK":
				copy.Funcs[0].Instrs = append(copy.Funcs[0].Instrs, Instr{Op: "LOCK"})
			case "raw":
				copy.Funcs[0].X86RawText = []byte{0xc3}
			case "frame":
				copy.Funcs[0].x86FixedLocal = &x86FixedLocalProof{}
			case "addressBits":
				copy.Funcs[0].Instrs[1].x86AddressBits = 32
			case "encoded":
				copy.Funcs[0].Instrs[1].x86Encoded = true
			}
			if _, err := normalizeX86SourceIntegerAddresses(&copy, Options{}); err == nil {
				t.Fatal("g alias inherited an unrelated source/native certificate")
			}
		})
	}
	for _, symbol := range []string{"$g(SB)", "$g<>(SB)", "$slot(FP)(g)", "$slot(SP)(g)", "$g+1(SB)"} {
		for _, arch := range []string{"386", "amd64"} {
			if _, matched, err := x86UnnamedSourceAddressInMode(Operand{Kind: OpSym, Sym: symbol}, arch); matched || err != nil {
				t.Fatalf("named role became an unnamed g constant: %q / %v", symbol, err)
			}
		}
	}
}

func TestX86UnnamedAddressImmediateGSourceModeFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			annotation := "g"
			if target.arch == "386" {
				annotation = "R14"
			}
			source := "TEXT ·addr(SB),4,$0-4\nMOVL $2,DX\n" +
				"MOVW $1(" + annotation + "),DX\nADDL $1(AX)(" + annotation + "*2),DX\n" +
				"CMPL DX,$1(" + annotation + ")(CX)\nMOVL DX,ret+0(FP)\nRET\n"
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			pkg := x86AddSubLiteralPackage(t, target.arch, "func addr() uint32\n")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					context := llvm.NewContext()
					defer context.Dispose()
					var ir string
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						var module llvm.Module
						module, err = TranslateModuleInContext(context, file, options)
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
					case "GoModule":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
							ir = result.Module.String()
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(ir, "%reg_R14") || strings.Contains(ir, "%reg_CX") {
						t.Fatal("ignored annotations became physical register inputs")
					}
					compileLLVMToObject(t, llc, target.triple, "g-source.ll", "g-source.o", ir)
				})
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86UnnamedAddressGSourceConstant(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	const source = "TEXT gconstant(SB),4,$0-16\nMOVQ x+0(FP),DX\nADDL $1(g),DX\nMOVQ DX,ret+8(FP)\nRET\n"
	code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT addr(SB),4,$0-0\nADDL $1(g),DX\nRET\n")
	plain := x86PackedShiftActualGoBytes(t, "amd64", "TEXT addr(SB),4,$0-0\nADDL $1,DX\nRET\n")
	if !bytes.Equal(code, plain) || len(code) != 4 || code[3] != 0xc3 {
		t.Fatalf("unbound actual constant opcode: %x / %x", code, plain)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	signature := FuncSig{Name: "gconstant", Args: []LLVMType{I64}, Ret: I64, Frame: FrameLayout{
		Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
		Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
	}}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: map[string]FuncSig{"gconstant": signature}})
	if err != nil {
		t.Fatal(err)
	}
	main := fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>
extern uint64_t gconstant(uint64_t);

static uint64_t original(uint64_t input) {
    uint64_t value = input;
    __asm__ volatile(".byte 0x%02x,0x%02x,0x%02x" : "+d"(value) : : "cc");
    return value;
}

int main(void) {
    for (unsigned seed = 0; seed < 256; seed++) {
        volatile struct { uint64_t before, input, after; } guarded = {
            UINT64_C(0x8977665544332211), UINT64_C(0x2398111297893221) * seed,
            UINT64_C(0x998812345679abcd)
        };
        uint64_t input = guarded.input;
        uint64_t expected = (uint32_t)(input + 1);
        if (original(input) != expected || gconstant(input) != expected ||
            guarded.input != input || guarded.before != UINT64_C(0x8977665544332211) ||
            guarded.after != UINT64_C(0x998812345679abcd)) {
            fprintf(stderr, "g constant numerical/canary failure %%u\n", seed);
            return 31;
        }
    }
    puts("G_SOURCE_ORIGINAL_LLVM_MATH_CANARIES_256_OK");
    return 0;
}
`, code[0], code[1], code[2])
	for _, optimization := range []string{"-O0", "-O2"} {
		execution.compileAndRunLLVM(t, "g-source-constant", ir, main, optimization)
	}
}

func TestX86UnnamedAddressImmediateGSourceModeThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, statement := range []string{
			"MOVW $1(g),DX",
			"ADDL $1(g),DX",
			"ADDL $1(AX)(g*2),DX",
			"CMPL DX,$1(g)(CX)",
		} {
			t.Run(target.triple+"/"+statement, func(t *testing.T) {
				source := "TEXT ·addr(SB),4,$0-0\nMOVL $2,DX\n" + statement + "\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				pkg := x86AddSubLiteralPackage(t, target.arch, "func addr()\n")
				resolve := func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) }
				sigs, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(api, func(t *testing.T) {
						context := llvm.NewContext()
						defer context.Dispose()
						var translationErr error
						switch api {
						case "text":
							_, translationErr = Translate(file, options)
						case "module":
							var module llvm.Module
							module, translationErr = TranslateModuleInContext(context, file, options)
							if !module.IsNil() {
								module.Dispose()
							}
						case "GoModule":
							var result *GoModuleTranslation
							result, translationErr = translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
							if result != nil && !result.Module.IsNil() {
								result.Module.Dispose()
							}
						}
						if target.arch == "386" && translationErr == nil {
							t.Error(fmt.Sprintf("%s accepted unregistered source g after ignored R14 normalization", api))
						}
						if target.arch == "amd64" && translationErr != nil {
							t.Fatalf("actual registered g constant annotation: %v", translationErr)
						}
					})
				}
			})
		}
	}
}
