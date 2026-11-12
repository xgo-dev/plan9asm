package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The source-role check uses actual SDK selection, not a runtime Skip or a
// filename convention inferred by this test. Native execution remains required
// on Linux; portable object/transport observations receive no native credit.
func TestX86StackFlagsIDOriginalGoBuildRoles(t *testing.T) {
	for _, target := range []struct {
		goos, arch string
		native     bool
		cross      bool
	}{
		{"darwin", "arm64", false, false},
		{"windows", "amd64", false, false},
		{"linux", "amd64", true, true},
		{"linux", "386", true, false},
	} {
		t.Run(target.goos+"/"+target.arch, func(t *testing.T) {
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "list", "-json", ".")
			command.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.arch,
				"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=")
			output, diagnostics, err := runtimeOracleMachineOutput(ctx, command)
			if err != nil {
				t.Fatalf("actual SDK source selection: %v\n%s", err, diagnostics)
			}
			if len(diagnostics) != 0 {
				t.Logf("actual Go selection diagnostics: %s", diagnostics)
			}
			var selected struct {
				Dir         string
				TestGoFiles []string
			}
			if err := json.Unmarshal(output, &selected); err != nil {
				t.Fatal(err)
			}
			functions := make(map[string]bool)
			for _, name := range selected.TestGoFiles {
				file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(selected.Dir, name), nil, 0)
				if err != nil {
					t.Fatal(err)
				}
				for _, declaration := range file.Decls {
					if function, ok := declaration.(*ast.FuncDecl); ok {
						functions[function.Name.Name] = true
					}
				}
			}
			for _, root := range []struct {
				name string
				want bool
			}{
				{"TestX86StackFlagsIDNativeGo", target.native},
				{"TestCrossLinuxRuntimeMatrixX86StackFlagsIDNativeGo", target.cross},
				{"TestX86StackFlagsIDOriginalGoPortableTransport", true},
			} {
				if functions[root.name] != root.want {
					t.Errorf("actual SDK source role %s: selected=%v want=%v", root.name, functions[root.name], root.want)
				}
			}
		})
	}
}

func x86StackIDOriginalExecutable(t *testing.T, goos, arch string) string {
	t.Helper()
	const driver = `package main

import "fmt"

func main() {
    var out [4]uint32
    idroundtrip(&out)
    if out != [4]uint32{0x200000, 0x200000, 0x200000, 1} {
        panic(fmt.Sprintf("original Go flags roundtrip: %x", out))
    }
    fmt.Println("original Go stack ID observations 4")
}
`
	return x86StackIDOriginalBuild(t, goos, arch, driver)
}

func x86StackIDOriginalBuild(t *testing.T, goos, arch, driver string) string {
	t.Helper()
	source := strings.Replace(x86StackIDSource(arch), "idroundtrip(SB)", "·idroundtrip(SB)", 1)
	if arch == "386" {
		source = strings.Replace(source, "$0-8", "$0-4", 1)
	}
	const declarations = "package main\nfunc idroundtrip(out *[4]uint32)\n"
	return x86OrderingHintBuildOriginal(t, t.TempDir(), goos, arch, declarations, source, driver)
}

// Rosetta's original POPFW currently clears the upper ID bit. This is a
// complete output-transport diagnostic, not success of the four-word ISA
// assertion. The unchanged strict reference executes in the required native
// root; an actually native host cannot bypass it through this diagnostic.
func TestX86StackFlagsIDOriginalGoPortableTransport(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const driver = `package main

import "fmt"

func main() {
    var out [4]uint32
    idroundtrip(&out)
    fmt.Printf("original Go stack ID transport %08x %08x %08x %08x\n", out[0], out[1], out[2], out[3])
}
`
	original := x86StackIDOriginalBuild(t, runtime.GOOS, "amd64", driver)
	output := execution.run(t, original)
	fields := strings.Fields(string(output))
	if len(fields) != 9 || strings.Join(fields[:5], " ") != "original Go stack ID transport" {
		t.Fatalf("incomplete original Go transport observations: %q", output)
	}
	var observed [4]uint32
	for index, field := range fields[5:] {
		value, err := strconv.ParseUint(field, 16, 32)
		if err != nil || len(field) != 8 {
			t.Fatalf("invalid complete uint32 observation %q: %v", field, err)
		}
		observed[index] = uint32(value)
	}
	canonical := fmt.Sprintf("original Go stack ID transport %08x %08x %08x %08x\n",
		observed[0], observed[1], observed[2], observed[3])
	if string(output) != canonical {
		t.Fatalf("extra or noncanonical transport output: %q", output)
	}
	want := [4]uint32{0x200000, 0x200000, 0x200000, 1}
	if observed != want {
		if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
			t.Fatalf("native-applicable original Go strict ID assertion: got=%x want=%x", observed, want)
		}
		t.Logf("ISA DEVIATION: Rosetta original opcode observations=%x strict native expectation=%x; not native ISA P", observed, want)
	}
	t.Logf("four original Go observations via %q; transport observation, not native Linux evidence", execution.prefix)
}

func TestX86StackFlagsIDOriginal386StaticELFCompileOnly(t *testing.T) {
	original := x86StackIDOriginalExecutable(t, "linux", "386")
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("original Go IA32 static ELF bytes=%d SHA256=%x; compile only, required native execution is separate",
		sealed.size, sealed.hash)
}

func TestX86StackFlagsIDRequiredNativeSourceContract(t *testing.T) {
	const name = "TestCrossLinuxRuntimeMatrixX86StackFlagsIDNativeGo"
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_stack_flags_id_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == name {
			body = function.Body
		}
	}
	if body == nil {
		t.Fatal("required Linux selector root is absent")
	}
	calls := make(map[string]int)
	ast.Inspect(body, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "TestX86StackFlagsIDNativeGo" {
			calls[identifier.Name]++
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if identifier, ok := call.Fun.(*ast.Ident); ok {
				calls[identifier.Name]++
			}
			if method, ok := call.Fun.(*ast.SelectorExpr); ok &&
				(method.Sel.Name == "Skip" || method.Sel.Name == "Skipf" || method.Sel.Name == "SkipNow") {
				t.Error("required native execution cannot skip")
			}
		}
		return true
	})
	for function, count := range map[string]int{
		"x87IA32RequireNativeHost":     2,
		"TestX86StackFlagsIDNativeGo":  1,
		"x86StackIDOriginalExecutable": 1,
		"x87IA32StaticExecutable":      1,
		"x87IA32RunDirect":             1,
	} {
		if calls[function] != count {
			t.Errorf("required native producer/consumer %s count=%d want=%d", function, calls[function], count)
		}
	}
	// This is the exact original embedded strict reference from the pre-companion
	// source, not a reconstructed test that silently accepts Rosetta's zeroes.
	strict, err := parser.ParseFile(token.NewFileSet(), "amd64_stack_flags_id_native_linux_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	matched := 0
	ast.Inspect(strict, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(value, "package flagsidnative\n") {
			matched++
			if hash := fmt.Sprintf("%x", sha256.Sum256([]byte(value))); hash !=
				"635f87191dac5a025ba6676a9abdaa7b0b04b3525c76fe71749474fe353af572" {
				t.Error("original native Go source/assertions changed", hash)
			}
		}
		return true
	})
	if matched != 1 {
		t.Fatalf("original native strict reference count=%d want=1", matched)
	}
}
