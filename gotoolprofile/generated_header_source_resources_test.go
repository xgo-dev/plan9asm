package gotoolprofile

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func nativeHeaderGrowingStringSources(steps int) map[string]string {
	var first, second strings.Builder
	first.WriteString("package header\nconst A0 = \"x\"\n")
	second.WriteString("package header\n")
	for step := 1; step <= steps; step++ {
		file := &first
		if step%2 != 0 {
			file = &second
		}
		fmt.Fprintf(file, "const A%d = (A%d) + A%d\n", step, step-1, step-1)
	}
	fmt.Fprintf(&second, "const Alias = (A%d)\nvar Observed = len(Alias)\n", steps)
	return map[string]string{"first.go": first.String(), "second.go": second.String()}
}

func TestGeneratedHeaderSourceStringExpansionBoundBeforeTypecheck(t *testing.T) {
	const childKey = "PLAN9ASM_NATIVE_HEADER_RESOURCE_CHILD"
	if os.Getenv(childKey) == "1" {
		// This is a soft Go memory limit, not an OS allocation-security claim.
		// The fixed 24-step witness has a 16 MiB largest original string, so the
		// pre-fix child remains a deliberately bounded diagnostic, not an OOM test.
		debug.SetMemoryLimit(128 << 20)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		definitions, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", nativeHeaderGrowingStringSources(24))
		runtime.ReadMemStats(&after)
		t.Logf("NATIVE_HEADER_RESOURCE steps=24 allocated=%d retained=%d definitions=%d error=%v", after.TotalAlloc-before.TotalAlloc,
			after.HeapAlloc, len(definitions), err)
		if definitions != nil || !NativeHeaderSourceDomainUnsupported(err) {
			t.Fatalf("bounded source model expanded a compact string DAG before its resource-domain refusal: definitions=%d error=%v", len(definitions), err)
		}
		if after.TotalAlloc-before.TotalAlloc > 8<<20 {
			t.Fatalf("string resource guard ran after expensive type/constant materialization: allocated=%d", after.TotalAlloc-before.TotalAlloc)
		}
		return
	}

	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	env := append(os.Environ(), childKey+"=1", "GOMEMLIMIT=128MiB")
	stdout, stderr, err := RunBounded(ctx, t.TempDir(), env, binary,
		"-test.run=^TestGeneratedHeaderSourceStringExpansionBoundBeforeTypecheck$", "-test.v", "-test.timeout=25s")
	if err != nil || len(stderr) != 0 || !strings.Contains(string(stdout), "NATIVE_HEADER_RESOURCE steps=24") {
		t.Fatalf("actual bounded model child failed its pre-typecheck resource contract: %v\n%s\n%s", err, stdout, stderr)
	}
	t.Logf("original resource child receipt:\n%s", stdout)
}

func TestGeneratedHeaderSourceOrdinaryStringConstantsRemainExact(t *testing.T) {
	sources := nativeHeaderGrowingStringSources(6)
	definitions, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", sources)
	if err != nil || definitions["const_Alias"] != fmt.Sprintf("%q", strings.Repeat("x", 64)) || definitions["const_A0"] != "\"x\"" {
		t.Fatalf("ordinary alias/parenthesis/cross-file string semantics changed: %v %v", definitions, err)
	}
	sources["conversion.go"] = "package header\ntype Text string\nconst Converted = Text(\"a\" + \"b\")\nconst RuneText = string(65)\nconst Repeated = Converted\n"
	definitions, err = ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", sources)
	if err != nil || definitions["const_Converted"] != "\"ab\"" || definitions["const_RuneText"] != "\"A\"" || definitions["const_Repeated"] != "\"ab\"" {
		t.Fatalf("bounded named/rune conversion string semantics changed: %v %v", definitions, err)
	}
}

func TestGeneratedHeaderSourceStringResourcesMatchFiveNativeObjects(t *testing.T) {
	source := "package header\n" +
		"const (\n  First = \"a\"\n  Repeated\n  Pair = First + Repeated\n)\n" +
		"type Text string\nconst Named = Text(Pair)\nconst Rune = string(65)\n" +
		"const Escaped = \"\\x00\\xff\" + \"\\u2028\"\nconst Length = len(Named)\n"
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRules(t, target, source)
			replayed, err := ReplayNativeGeneratedHeader("example.invalid/header", target, "go1.20", map[string]string{"header.go": source})
			if err != nil || !reflect.DeepEqual(actual, replayed) {
				t.Fatalf("resource precheck changed actual native string/header semantics: actual=%v replay=%v error=%v", actual, replayed, err)
			}
		})
	}
}

func TestGeneratedHeaderSourceStringResourceCheckedBoundaries(t *testing.T) {
	budget := &nativeHeaderStringBudget{limit: 32, bindings: make(map[string]ast.Expr),
		memo: make(map[string]uint64), active: make(map[string]bool)}
	literal := &ast.BasicLit{Kind: token.STRING, Value: "\"abcd\""}
	width, err := budget.expression(literal, 0)
	if err != nil || width != 24 {
		t.Fatalf("independent literal escaping bound: %d %v", width, err)
	}
	if sum, err := budget.add(width, 8); err != nil || sum != 32 {
		t.Fatalf("exact resource boundary was rejected: %d %v", sum, err)
	}
	for _, pair := range [][2]uint64{{width, 9}, {33, 0}, {0, ^uint64(0)}} {
		if _, err := budget.add(pair[0], pair[1]); !NativeHeaderSourceDomainUnsupported(err) {
			t.Fatalf("overflow/excess became a bounded query: %v %v", pair, err)
		}
	}
	budget.bindings["Recursive"] = &ast.Ident{Name: "Recursive"}
	if _, err := budget.expression(&ast.Ident{Name: "Recursive"}, 0); err == nil || NativeHeaderSourceDomainUnsupported(err) {
		t.Fatal("invalid constant recursion was swallowed as an unsupported successful query")
	}
	budget.work = 100000
	if _, err := budget.expression(literal, 0); !NativeHeaderSourceDomainUnsupported(err) {
		t.Fatal("exhausted precheck work acquired query authority")
	}
}

func TestGeneratedHeaderSourceSelectorResourcesCoverOriginalReceivers(t *testing.T) {
	for _, test := range []struct {
		name, expression string
		exceeds          bool
	}{
		{"field", `struct { Text string }{Text: "abcdef"}.Text`, true},
		{"parenthesized", `(struct { Text string }{Text: "abcdef"}).Text`, true},
		{"nested", `struct { Inner struct { Text string } }{Inner: struct { Text string }{Text: "abcdef"}}.Inner.Text`, true},
		{"sizeof", `unsafe.Sizeof(struct { Text string }{Text: "abcdef"}.Text)`, true},
		{"alignof", `unsafe.Alignof(struct { Text string }{Text: "abcdef"}.Text)`, true},
		{"offsetof", `unsafe.Offsetof(struct { Text string }{Text: "abcdef"}.Text)`, true},
		{"ordinary field", `struct { Value uint64 }{}.Value`, false},
		{"builtin property", `unsafe.Sizeof(struct { Value uint64 }{}.Value)`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			expression, err := parser.ParseExpr(test.expression)
			if err != nil {
				t.Fatal(err)
			}
			// Exercise only the existing resource observer, never materialize a
			// Go constant or execute the receiver. The original witness is tiny.
			budget := &nativeHeaderStringBudget{limit: 32, bindings: make(map[string]ast.Expr),
				memo: make(map[string]uint64), active: make(map[string]bool)}
			width, err := budget.expression(expression, 0)
			if test.exceeds {
				if !NativeHeaderSourceDomainUnsupported(err) {
					t.Fatalf("selector receiver bypassed its original string resource bound: width=%d error=%v", width, err)
				}
			} else if err != nil || width > budget.limit {
				t.Fatalf("small original receiver lost its bounded query domain: width=%d error=%v", width, err)
			}
		})
	}
}

func TestGeneratedHeaderSourcePreflightNeverCertifiesTypecheck(t *testing.T) {
	for _, source := range []string{
		"package header\nconst Huge = 1 << 1000000000\n",
		"package header\ntype A = B\ntype B = A\n",
		"package header\nconst Wrong = Missing\n",
	} {
		definitions, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/amd64", "go1.20", map[string]string{"header.go": source})
		if definitions != nil || err == nil || NativeHeaderSourceDomainUnsupported(err) {
			t.Fatalf("actual type/shift/alias failure became a conservative query success: %v %v", definitions, err)
		}
	}
}

func TestGeneratedHeaderSourceInvalidConstantsMatchActualCompiler(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	env := replaceEnv(os.Environ(), map[string]string{
		"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "",
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOEXPERIMENT": "",
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module example.invalid/header\ngo 1.20\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := RunBounded(ctx, directory, env, goBinary,
		"env", "-json", "GOVERSION", "GOTOOLDIR", "GOHOSTOS")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual invalid-source SDK: %v\n%s\n%s", err, stdout, stderr)
	}
	var sdk struct{ GOVERSION, GOTOOLDIR, GOHOSTOS string }
	if err := json.Unmarshal(stdout, &sdk); err != nil || sdk.GOTOOLDIR == "" || sdk.GOVERSION == "" {
		t.Fatalf("invalid-source compiler has no actual SDK identity: %+v %v", sdk, err)
	}
	extension := ""
	if sdk.GOHOSTOS == "windows" {
		extension = ".exe"
	}
	compiler := filepath.Join(sdk.GOTOOLDIR, "compile"+extension)
	inputs := []string{goBinary, compiler}
	digests := make(map[string][32]byte)
	for _, input := range inputs {
		data, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		digests[input] = sha256.Sum256(data)
	}
	for _, axis := range []string{"huge shift", "recursive alias", "missing constant"} {
		t.Run(axis, func(t *testing.T) {
			source := "package header\nconst Wrong = Missing\n"
			diagnostic := "undefined: Missing"
			switch axis {
			case "huge shift":
				source = "package header\nconst Huge = 1 << 1000000000\n"
				diagnostic = "invalid shift count 1000000000"
			case "recursive alias":
				source = "package header\ntype A = B\ntype B = A\n"
				diagnostic = "invalid recursive type A"
			}
			goFile := filepath.Join(directory, "header.go")
			if err := os.WriteFile(goFile, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := RunBounded(ctx, directory, env, goBinary,
				"list", "-p=2", "-mod=readonly", "-export", "-compiled", "-json", ".")
			var exit *exec.ExitError
			output := string(stdout) + string(stderr)
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(stderr), "header.go:") ||
				!strings.Contains(string(stderr), diagnostic) || strings.Contains(output, "panic:") {
				t.Fatalf("actual original invalid declaration did not fail with a bound diagnostic: %v\n%s", err, output)
			}
			var selected struct {
				ImportPath, Export string
				CompiledGoFiles    []string
			}
			if err := json.Unmarshal(stdout, &selected); err != nil || selected.Export != "" ||
				selected.ImportPath != "example.invalid/header" || !reflect.DeepEqual(selected.CompiledGoFiles, []string{"header.go"}) {
				t.Fatalf("invalid original acquired compiler export evidence: export=%q error=%v", selected.Export, err)
			}
			for _, input := range append(inputs, goFile) {
				data, err := os.ReadFile(input)
				wanted := digests[input]
				if input == goFile {
					wanted = sha256.Sum256([]byte(source))
				}
				if err != nil || sha256.Sum256(data) != wanted {
					t.Fatalf("invalid-source compiler input changed: %s %v", input, err)
				}
			}
			t.Logf("NATIVE_HEADER_INVALID_SOURCE sdk=%s source_sha=%x compile_sha=%x selection_sha=%x exit=%d stderr=%q",
				sdk.GOVERSION, sha256.Sum256([]byte(source)), digests[compiler], sha256.Sum256(stdout), exit.ExitCode(), stderr)
		})
	}
}
