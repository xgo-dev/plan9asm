package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

const x86ScalarRelocationStoragePrefix = "DATA ·cell+0(SB)/1,$0xa7\n" +
	"GLOBL ·cell(SB),16,$32\nGLOBL ·result(SB),16,$336\n"

// This captures the original unmodified ASM builder and reference payloads,
// not the runtime driver's wiring, tool selection or implementation methods.
func x86ScalarRelocationOriginalFixture(t *testing.T) (assembly, originalGo, reference string, driver []byte) {
	t.Helper()
	driver, err := os.ReadFile("amd64_scalar_relocation_runtime_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(driver)
	start := strings.Index(text, "\tvar source strings.Builder\n")
	end := strings.Index(text, "\trun := func(")
	if start < 0 || end <= start || fmt.Sprintf("%x", sha256.Sum256(driver[start:end])) !=
		"9494401542aad43bd2b99e91c60c2deba1d8e26e6cbd3537fceb0122df49a0c7" {
		t.Fatal("original complete 42-case ASM construction changed")
	}
	var source strings.Builder
	source.WriteString("TEXT ·Value(SB),4,$0-0\n")
	index := 0
	for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
		for _, seed := range []uint32{0, 0xffffffff, 0x81234567} {
			for _, carry := range []string{"CLC", "STC"} {
				fmt.Fprintf(&source, "MOVL $%d,AX\n%s\n%sL $·cell+8(SB),AX\nMOVL AX,·result+%d(SB)\nMOVL $0,BX\nSETCS BX\nMOVL BX,·result+%d(SB)\n",
					seed, carry, stem, index*8, index*8+4)
				index++
			}
		}
	}
	source.WriteString("RET\n")
	assembly = source.String()
	if index != 42 || fmt.Sprintf("%x", sha256.Sum256([]byte(assembly))) !=
		"f616eb040c6a5e958c9f6273b764aab7434675ab0b2b892d7004fb94a01bebda" {
		t.Fatal("original complete ASM payload changed")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "original.go", driver, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			if len(value.Names) == 1 && len(value.Values) == 1 {
				literal, ok := value.Values[0].(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					values[value.Names[0].Name], err = strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	originalGo, reference = values["x86ScalarRelocationOriginalGo"], values["x86ScalarRelocationReferenceC"]
	if fmt.Sprintf("%x", sha256.Sum256([]byte(originalGo))) != "0ac7f99dc09dd95dd05e3de1d4688a3f758b9f75c9af502d3f4aaf9622482bea" ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(reference))) != "33173d2c83173a738d76aecedced3372f5c42fcdcdafea102ec5c604d35cf0ca" {
		t.Fatal("original stock-Go/C comparisons or storage definitions changed")
	}
	return
}

// LLVM owns the actual objects; C only names them. Neither a C declaration nor
// a linked address supplies a standalone source/storage capability.
func x86ScalarRelocationOwnedLLVMFixture(t *testing.T, assembly, reference string) (string, string) {
	t.Helper()
	if fmt.Sprintf("%x", sha256.Sum256([]byte(assembly))) != "f616eb040c6a5e958c9f6273b764aab7434675ab0b2b892d7004fb94a01bebda" ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(reference))) != "33173d2c83173a738d76aecedced3372f5c42fcdcdafea102ec5c604d35cf0ca" {
		t.Fatal("owned counterpart requires the complete original ASM/C")
	}
	for _, pair := range [][2]string{
		{"uint8_t cell[32] = {0xa7};", "extern uint8_t cell[32];"},
		{"uint32_t result[84];", "extern uint32_t result[84];"},
	} {
		if strings.Count(reference, pair[0]) != 1 {
			t.Fatal("one exact original C storage definition required", pair[0])
		}
		reference = strings.Replace(reference, pair[0], pair[1], 1)
	}
	return x86ScalarRelocationStoragePrefix + assembly, reference
}

func TestX86ScalarAbsoluteRelocationOriginalProgramRetainsUnboundStorage(t *testing.T) {
	assembly, originalGo, _, _ := x86ScalarRelocationOriginalFixture(t)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "386",
		"package main\nfunc Value()\n", assembly, originalGo)
	if _, err := x87IA32StaticExecutable(original); err != nil {
		t.Fatal("complete original stock-Go IA32 executable prior", err)
	}
	for _, api := range []string{"text", "module", "go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86AddressMemoryAPI(t, api, assembly, "386", "i386-unknown-linux-gnu")
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original unbound C/Go storage became public source authority", err)
			}
		})
	}
}

func TestX86ScalarAbsoluteRelocationOwnedOriginalProgramObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	original, _, reference, _ := x86ScalarRelocationOriginalFixture(t)
	assembly, companion := x86ScalarRelocationOwnedLLVMFixture(t, original, reference)
	if !strings.HasSuffix(assembly, original) || strings.Count(companion, "extern uint8_t cell[32];") != 1 ||
		strings.Count(companion, "extern uint32_t result[84];") != 1 {
		t.Fatal("counterpart changed original instructions or lost actual module-owned storage")
	}
	for _, target := range x86AddressMemoryTargets("386") {
		t.Run(target, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", target, assembly)
			for _, api := range []string{"text", "module", "go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86AddressMemoryAPI(t, api, assembly, "386", target)
					if err != nil || ir == "" {
						t.Fatal("same complete original program with actual owned storage", err)
					}
					if !strings.Contains(ir, "ptrtoint ptr") || strings.Contains(ir, "load i32, ptr @cell") ||
						strings.Contains(ir, "load volatile i32, ptr @cell") {
						t.Fatal("R_ADDR value became a pointee read")
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target, ir, level)
					}
				})
			}
		})
	}
}

func x86ScalarRelocationRuntimeStorageWiring(source []byte) error {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "runtime.go", source, 0)
	if err != nil {
		return err
	}
	var function *ast.FuncDecl
	for _, declaration := range file.Decls {
		if candidate, ok := declaration.(*ast.FuncDecl); ok && candidate.Name.Name == "TestCrossLinuxRuntimeMatrixX86ScalarAbsoluteRelocation" {
			function = candidate
		}
	}
	if function == nil || function.Body == nil {
		return fmt.Errorf("missing complete original runtime owner")
	}
	var body bytes.Buffer
	if err := format.Node(&body, set, function.Body); err != nil {
		return err
	}
	text := body.String()
	// Formatting the AST removes comments. Every required call consumes the
	// exact bound source/C, not an unused variable or printed command marker.
	ordered := []string{
		`x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "386",`,
		`"package main\nfunc Value()\n", source.String(), x86ScalarRelocationOriginalGo)`,
		`run(original)`,
		`llvmSource, llvmReference := x86ScalarRelocationOwnedLLVMFixture(t, source.String(), x86ScalarRelocationReferenceC)`,
		`for _, api := range []string{"text", "module", "go"}`,
		`x86AddressMemoryAPI(t, api, llvmSource, "386", "i386-unknown-linux-gnu")`,
		`for _, level := range []string{"-O0", "-O2"}`,
		`map[string]string{input: ir, driver: llvmReference}`,
		`exec.Command(llc, level, "-mtriple=i386-unknown-linux-gnu", "-filetype=obj", input, "-o", object)`,
		`exec.Command(compiler, "-O2", "-no-pie", object, driver, "-o", executable)`,
		`run(executable)`,
	}
	offset := 0
	for _, required := range ordered {
		at := strings.Index(text[offset:], required)
		if at < 0 || strings.Count(text, required) != 1 {
			return fmt.Errorf("missing exact owned storage/execution contract: %s", required)
		}
		offset += at + len(required)
	}
	return nil
}

func TestX86ScalarAbsoluteRelocationRuntimeUsesActualOwnedStorage(t *testing.T) {
	_, _, _, original := x86ScalarRelocationOriginalFixture(t)
	binding := "\tllvmSource, llvmReference := x86ScalarRelocationOwnedLLVMFixture(t, source.String(), x86ScalarRelocationReferenceC)\n"
	wiredAPI := `x86AddressMemoryAPI(t, api, llvmSource, "386", "i386-unknown-linux-gnu")`
	unwiredAPI := `x86AddressMemoryAPI(t, api, source.String(), "386", "i386-unknown-linux-gnu")`
	wiredC := `map[string]string{input: ir, driver: llvmReference}`
	unwiredC := `map[string]string{input: ir, driver: x86ScalarRelocationReferenceC}`
	unwired := string(original)
	for _, pair := range [][2]string{{binding, ""}, {wiredAPI, unwiredAPI}, {wiredC, unwiredC}} {
		if strings.Count(unwired, pair[0]) != 1 {
			t.Fatal("actual owner lost one exact source/storage binding", pair[0])
		}
		unwired = strings.Replace(unwired, pair[0], pair[1], 1)
	}
	if x86ScalarRelocationRuntimeStorageWiring([]byte(unwired)) == nil {
		t.Fatal("independent unwired owner acquired an owned-storage contract")
	}
	complete := strings.Replace(unwired, "\trun(original)\n", "\trun(original)\n"+binding, 1)
	complete = strings.Replace(complete, `x86AddressMemoryAPI(t, api, source.String(), "386", "i386-unknown-linux-gnu")`,
		`x86AddressMemoryAPI(t, api, llvmSource, "386", "i386-unknown-linux-gnu")`, 1)
	complete = strings.Replace(complete, `map[string]string{input: ir, driver: x86ScalarRelocationReferenceC}`,
		`map[string]string{input: ir, driver: llvmReference}`, 1)
	if complete != string(original) {
		t.Fatal("independent binding round trip changed the actual complete runtime owner")
	}
	if err := x86ScalarRelocationRuntimeStorageWiring([]byte(complete)); err != nil {
		t.Fatal("independent complete wiring control", err)
	}
	for _, mutation := range [][2]string{
		{`(t, source.String(), x86ScalarRelocationReferenceC)`, `(t, "wrong", x86ScalarRelocationReferenceC)`},
		{`(t, source.String(), x86ScalarRelocationReferenceC)`, `(t, source.String(), "wrong")`},
		{`(t, api, llvmSource,`, `(t, api, source.String(),`},
		{`driver: llvmReference`, `driver: x86ScalarRelocationReferenceC`},
		{`x86OrderingHintBuildOriginal(`, `otherBuilder(`},
		{`run(original)`, `_ = original`},
		{`[]string{"text", "module", "go"}`, `[]string{"text", "module"}`},
		{`[]string{"-O0", "-O2"}`, `[]string{"-O0"}`},
		{`run(executable)`, `_ = executable`},
	} {
		changed := strings.Replace(complete, mutation[0], mutation[1], 1)
		if changed == complete || x86ScalarRelocationRuntimeStorageWiring([]byte(changed)) == nil {
			t.Fatal("incomplete source/storage/execution substitution passed", mutation)
		}
	}
	if err := x86ScalarRelocationRuntimeStorageWiring(original); err != nil {
		t.Fatal("actual original owner has not bound its LLVM storage counterpart", err)
	}
}
