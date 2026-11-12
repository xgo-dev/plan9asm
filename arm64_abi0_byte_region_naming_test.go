package plan9asm

import (
	"bytes"
	"debug/pe"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The actual fixture's naming statements are compiled with explicit GOOS
// controls. This is a naming unit and a Windows PE build, not Windows execution.
func TestARM64ABI0ByteRegionNativeExecutableNaming(t *testing.T) {
	original, err := os.ReadFile("arm64_abi0_byte_region_role_test.go")
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "actual-role.go", original, 0)
	if err != nil {
		t.Fatal(err)
	}
	var naming bytes.Buffer
	var retained ast.Expr
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestARM64ABI0ByteRegionActualLinuxSourceRole" {
			continue
		}
		collect := false
		for _, statement := range function.Body.List {
			if assignment, ok := statement.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 {
				if identifier, ok := assignment.Lhs[0].(*ast.Ident); ok {
					if identifier.Name == "executable" {
						collect = true
					}
					if identifier.Name == "command" {
						collect = false
					}
				}
			}
			if collect {
				if err := format.Node(&naming, set, statement); err != nil {
					t.Fatal(err)
				}
				naming.WriteByte('\n')
			}
			if expression, ok := statement.(*ast.ExprStmt); ok {
				if call, ok := expression.X.(*ast.CallExpr); ok {
					if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "arm64ABI0RegionRetain" {
						if retained != nil || len(call.Args) < 4 {
							t.Fatal("ambiguous actual artifact retention")
						}
						retained = call.Args[len(call.Args)-1]
					}
				}
			}
		}
	}
	if naming.Len() == 0 || retained == nil {
		t.Fatal("actual source-role naming/retention statements are absent")
	}
	var kept bytes.Buffer
	if err := format.Node(&kept, set, retained); err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`package main

import (
	"fmt"
	"path/filepath"
)

func names(goos string) (string,string) {
	dir := "owned-fixture"
	runtime := struct { GOOS string }{goos}
	_ = runtime
	%s
	return filepath.Base(executable), %s
}

func main() {
	for _, goos := range []string{"windows","darwin","linux","freebsd","openbsd"} {
		executable,retained := names(goos)
		fmt.Printf("%%s=%%s/%%s\n",goos,executable,retained)
	}
}
`, naming.String(), kept.String())
	formatted, err := format.Source([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "names.go"), formatted, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actual-role-source.txt"), original, 0600); err != nil {
		t.Fatal(err)
	}
	lookup, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "os", "exec", "lp_windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "windows-lookup-source.txt"), lookup, 0600); err != nil {
		t.Fatal(err)
	}
	name := "names"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	executable := filepath.Join(dir, name)
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	build := func(goos, goarch, output string) {
		t.Helper()
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		command := exec.CommandContext(ctx, goTool, "build", "-p=2", "-o", output, "names.go")
		command.Dir = dir
		command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0",
			"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
		if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
			t.Fatalf("actual naming unit build %s/%s: %v\n%s", goos, goarch, err, output)
		}
	}
	build(runtime.GOOS, runtime.GOARCH, executable)
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, executable)
	command.Dir = dir
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual naming unit execution: %v\n%s", err, output)
	}
	build("windows", "amd64", filepath.Join(dir, "windows-naming.exe"))
	image, err := pe.Open(filepath.Join(dir, "windows-naming.exe"))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if image.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || image.NumberOfSections == 0 {
		t.Fatal("actual Windows build did not produce an AMD64 PE")
	}
	arm64ABI0RegionRetain(t, dir, "source-naming-unit-and-Windows-build-only", "names.go",
		"actual-role-source.txt", "windows-lookup-source.txt", name, "windows-naming.exe")
	var expected strings.Builder
	for _, goos := range []string{"windows", "darwin", "linux", "freebsd", "openbsd"} {
		name := "scope"
		if goos == "windows" {
			name += ".exe"
		}
		fmt.Fprintf(&expected, "%s=%s/%s\n", goos, name, name)
	}
	if string(output) != expected.String() {
		t.Fatalf("actual native executable/retained filename routing differs (unit, not native Windows):\n%s\nwant:\n%s",
			output, expected.String())
	}
	t.Logf("actual SDK=%s native-source naming controls plus Windows/amd64 PE BUILD ONLY:\n%s",
		runtime.Version(), output)
}
