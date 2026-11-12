package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A test-only observation of this invocation, not a frame or caller capability.
type x86LEAGoObjectReceipt struct {
	Target, GoVersion      string
	Source, Driver, Object [sha256.Size]byte
}

// These existing LEAW/L/Q source forms also belong to the historical SDK.
// The generic current-table helper remains unchanged for other families.
func requireLEANativeGoObject(t *testing.T, arch, source string, wantSuccess bool) {
	t.Helper()
	if wantSuccess {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		x86LEAActualTargetGoObject(t, arch, triple, source)
	} else {
		x86LEAActualSDKDriver(t)
		goAssemblerOracleOutput(t, arch, source, "", false)
	}
}

func x86LEAActualSDKDriver(t *testing.T) (string, [sha256.Size]byte) {
	t.Helper()
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	driver, err = filepath.EvalSymlinks(driver)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(runtime.GOROOT())
	if err != nil || driver != x86LEASDKDriverPath(root, runtime.GOOS) {
		t.Fatalf("LEA oracle must invoke this SDK's driver: %s: %v", driver, err)
	}
	driverBytes, err := os.ReadFile(driver)
	if err != nil {
		t.Fatal(err)
	}
	return driver, sha256.Sum256(driverBytes)
}

func x86LEASDKDriverPath(root, hostGOOS string) string {
	filename := "go"
	if hostGOOS == "windows" {
		filename = "go.exe"
	}
	return filepath.Join(root, "bin", filename)
}

func TestX86LEAActualSDKDriverPathUsesHostToolSuffix(t *testing.T) {
	root := filepath.Join("selected-sdk", "root")
	for _, test := range []struct {
		goos, filename string
	}{
		{"windows", "go.exe"},
		{"darwin", "go"},
		{"linux", "go"},
	} {
		t.Run(test.goos, func(t *testing.T) {
			got := x86LEASDKDriverPath(root, test.goos)
			want := filepath.Join(root, "bin", test.filename)
			if got != want {
				t.Fatalf("actual SDK driver for host %s = %q, want %q", test.goos, got, want)
			}
		})
	}
}

func x86LEAReadObjectReceipt(t *testing.T, arch, goos, source, input, driver string, driverHash [sha256.Size]byte, object string) *x86LEAGoObjectReceipt {
	t.Helper()
	info, err := os.Lstat(object)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("actual LEA oracle lacks a regular nonempty object: %v", err)
	}
	data, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	header := strings.Fields(string(bytes.SplitN(data, []byte("\n"), 2)[0]))
	if len(header) < 5 || header[0] != "go" || header[1] != "object" ||
		header[2] != goos || header[3] != arch || header[4] != runtime.Version() {
		t.Fatalf("LEA object does not bind the actual target/SDK: %q", header)
	}
	inputBytes, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(inputBytes, []byte(source)) {
		t.Fatalf("actual LEA source changed during the tool invocation: %v", err)
	}
	driverBytes, err := os.ReadFile(driver)
	if err != nil || sha256.Sum256(driverBytes) != driverHash {
		t.Fatalf("actual LEA driver changed during the tool invocation: %v", err)
	}
	receipt := &x86LEAGoObjectReceipt{
		Target: goos + "/" + arch, GoVersion: header[4],
		Source: sha256.Sum256(inputBytes), Driver: driverHash,
		Object: sha256.Sum256(data),
	}
	t.Logf("actual LEA source/object receipt: SDK=%s target=%s source=%x driver=%x object=%x",
		receipt.GoVersion, receipt.Target, receipt.Source, receipt.Driver, receipt.Object)
	return receipt
}

func TestX86LEAActualGoOracleCannotSilentlyReturnBeforeTool(t *testing.T) {
	for name, filename := range map[string]string{
		"x86LEAActualTargetGoObject": "amd64_go_caller_lea_test.go",
		"requireLEANativeGoObject":   "amd64_lea_go_oracle_receipt_test.go",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok {
				if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "requireX86GoAssemblerResult" {
					t.Errorf("%s uses a current-table helper instead of its actual applicable LEA tool oracle", filename)
				}
			}
			return true
		})
		found := false
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != name {
				continue
			}
			found = true
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if statement, ok := node.(*ast.ReturnStmt); ok {
					missing := len(statement.Results) == 0
					if len(statement.Results) == 1 {
						value, ok := statement.Results[0].(*ast.Ident)
						missing = ok && value.Name == "nil"
					}
					if missing {
						t.Errorf("%s has a silent return instead of its actual tool receipt", name)
					}
				}
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if identifier, ok := call.Fun.(*ast.Ident); ok &&
					(identifier.Name == "goToolchainAtLeast" || identifier.Name == "currentGoMinorAtLeast") {
					t.Errorf("%s silently gates its actual tool invocation by build version", name)
				}
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok &&
					(selector.Sel.Name == "Skip" || selector.Sel.Name == "Skipf" || selector.Sel.Name == "SkipNow") {
					t.Errorf("%s cannot skip an applicable LEA source oracle", name)
				}
				return true
			})
		}
		if !found {
			t.Fatalf("actual LEA oracle %s is missing", name)
		}
	}
}

func TestX86LEAActualGoOracleRequiresToolAndObjectReceipt(t *testing.T) {
	targets := map[string]string{
		"x86_64-apple-darwin":      "darwin/amd64",
		"x86_64-unknown-linux-gnu": "linux/amd64",
		"x86_64-pc-windows-msvc":   "windows/amd64",
		"i386-unknown-linux-gnu":   "linux/386",
		"i686-pc-windows-msvc":     "windows/386",
	}
	for _, target := range x86RawReturnTargets {
		for _, suffix := range []string{"W", "L", "Q"} {
			if x86LEAWidth(Op("LEA"+suffix), target.arch) == 0 {
				continue // No LEAQ physical encoding in 386 mode.
			}
			t.Run(target.triple+"/"+suffix, func(t *testing.T) {
				source := "TEXT lea(SB),4,$0-0\nLEA" + suffix + " 19(AX)(BX*4),AX\nRET\n"
				receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				if receipt == nil {
					t.Fatal("actual LEA oracle omitted its selected SDK tool/object invocation")
				}
				zero := [sha256.Size]byte{}
				if receipt.GoVersion != runtime.Version() || receipt.Source != sha256.Sum256([]byte(source)) ||
					receipt.Driver == zero || receipt.Object == zero || receipt.Target != targets[target.triple] {
					t.Fatalf("actual LEA receipt is incomplete or misbound: %+v", receipt)
				}
			})
		}
	}
}
