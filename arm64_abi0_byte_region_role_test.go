package plan9asm

import (
	"bytes"
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

// This compiles the actual Linux root body with explicit synthetic profile,
// lookup and run observers. It proves source-role routing, not Linux execution,
// tool availability, an original ARM64 result or any native ABI permission.
func TestARM64ABI0ByteRegionActualLinuxSourceRole(t *testing.T) {
	name := "arm64_abi0_byte_region_linux_test.go"
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, name, original, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "TestCrossLinuxRuntimeMatrixARM64ABI0ByteRegionOriginal" {
			if body.Len() != 0 {
				t.Fatal("duplicate required cross root")
			}
			if err := format.Node(&body, set, function.Body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if body.Len() == 0 {
		t.Fatal("actual required Linux root is absent")
	}
	cases := []struct {
		name, arch, cross, want string
		qemu                    bool
		lookups                 int
	}{
		{"ordinary-amd64-empty", "amd64", "", "skip", false, 0},
		{"ordinary-amd64-zero", "amd64", "0", "skip", false, 0},
		{"ordinary-amd64-unknown", "amd64", "yes", "skip", false, 0},
		{"required-amd64", "amd64", "1", "guest", true, 1},
		{"required-amd64-missing-qemu", "amd64", "1", "fatal", false, 1},
		{"native-arm64", "arm64", "", "native", false, 0},
		{"native-arm64-cross-env", "arm64", "1", "native", false, 0},
		{"ordinary-386", "386", "", "skip", false, 0},
		{"unsupported-required-386", "386", "1", "skip", false, 0},
		{"unsupported-required-arm", "arm", "1", "skip", false, 0},
	}
	var source strings.Builder
	source.WriteString(`package main

import "fmt"

var runtime struct { GOARCH string }
var cross string
var available bool
var lookups int

var os = struct { Getenv func(string) string } {
	Getenv: func(name string) string {
		if name != "PLAN9ASM_CROSS_EXEC" { panic("unregistered environment") }
		return cross
	},
}
var exec = struct { LookPath func(string) (string,error) } {
	LookPath: func(name string) (string,error) {
		if name != "qemu-aarch64" { panic("unregistered tool") }
		lookups++
		if !available { return "",fmt.Errorf("synthetic unavailable QEMU") }
		return "unit-qemu",nil
	},
}

type observer struct { outcome string }
func (t *observer) Fatal(args ...interface{}) { panic("fatal") }
func (t *observer) Skip(args ...interface{}) { panic("skip") }
func (t *observer) Log(args ...interface{}) {}
func arm64ABI0ByteRegionOriginalRun(t *observer,goos string,runner []string) {
	if goos != "linux" { panic("wrong original runtime target") }
	if len(runner)==0 { t.outcome="native";return }
	if len(runner)!=1 || runner[0]!="unit-qemu" { panic("wrong guest execution prefix") }
	t.outcome="guest"
}

func root(t *observer) `)
	source.Write(body.Bytes())
	source.WriteString("\n\nfunc main() {\n")
	for _, test := range cases {
		fmt.Fprintf(&source, `
	{
	runtime.GOARCH=%q
	cross=%q
	available=%t
	lookups=0
	t:=&observer{outcome:"unobserved"}
	func() {
		defer func() { if value:=recover();value!=nil { t.outcome=fmt.Sprint(value) } }()
		root(t)
	}()
	fmt.Printf("%s=%%s/%%d\n",t.outcome,lookups)
	}
`, test.arch, test.cross, test.qemu, test.name)
	}
	source.WriteString("}\n")
	formatted, err := format.Source([]byte(source.String()))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"scope.go": formatted, "actual-linux-source.txt": original} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	executable := filepath.Join(dir, "scope")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	command := exec.CommandContext(ctx, goTool, "build", "-p=2", "-o", executable, "scope.go")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH,
		"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil {
		t.Fatalf("actual stock Go compilation of source-role unit: %v\n%s", err, output)
	}
	ctx, cancel = runtimeOracleStageContext(t)
	defer cancel()
	command = exec.CommandContext(ctx, executable)
	command.Dir = dir
	output, err = runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("actual source-role unit execution: %v\n%s", err, output)
	}
	arm64ABI0RegionRetain(t, dir, "synthetic-source-role", "actual-linux-source.txt", "scope.go", filepath.Base(executable))
	var expected strings.Builder
	for _, test := range cases {
		fmt.Fprintf(&expected, "%s=%s/%d\n", test.name, test.want, test.lookups)
	}
	if string(output) != expected.String() {
		t.Fatalf("actual Linux source-role routing differs; synthetic controls, not native execution:\n%s\nwant:\n%s",
			output, expected.String())
	}
	t.Logf("actual SDK=%s source-role unit outcomes (no ARM64 native runtime):\n%s", runtime.Version(), output)
}
