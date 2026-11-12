package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreprocessAssemblyActiveIncludes(t *testing.T) {
	const source = `#define OUTER 41
#ifdef ENABLE
#include "outer.h"
#else
#include invalid missing operand
#define LEAK 900
#endif
#ifdef LEAK
BAD
#endif
VALUE
#undef VALUE
#define VALUE 73
VALUE
`
	files := map[string]string{
		"outer.h": "#ifdef ENABLE\n#include \"inner.h\"\n#endif\n#define VALUE OUTER+INNER\n",
		"inner.h": "#define INNER 1\n",
	}
	var calls []string
	got, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
		FileName: "main.s", Defines: []string{"ENABLE"},
		ReadInclude: func(parent, name string) (string, []byte, error) {
			calls = append(calls, parent+":"+name)
			body, ok := files[name]
			if !ok {
				return "", nil, fmt.Errorf("missing %s", name)
			}
			return name, []byte(body), nil
		},
	})
	if err != nil || strings.TrimSpace(got) != "41+1\n73" {
		t.Fatalf("preprocess = %q, %v; want real source-order headers", got, err)
	}
	if strings.Join(calls, ",") != "main.s:outer.h,outer.h:inner.h" {
		t.Fatalf("resolver calls = %v", calls)
	}
}

func TestPreprocessAssemblyIncludeFailures(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"no-resolver", "#include \"missing.h\"\n", "resolver"},
		{"missing", "#include \"missing.h\"\n", "missing header"},
		{"malformed", "#include notQuoted\n", "invalid #include"},
		{"trailing", "#include \"h\" garbage\n", "invalid #include"},
		{"cycle", "#include \"main.s\"\n", "cycle"},
		{"redefined", "#define A 1\n#define A 2\n", "redefinition"},
		{"undefined-undef", "#undef A\n", "undefined macro"},
		{"invalid-ifdef", "#ifdef A garbage\n#endif\n", "invalid #ifdef"},
		{"unknown-control", "#if A\n#endif\n", "unsupported Go assembly directive"},
		{"expanded-include", "#define HEADER #include \"h\"\nHEADER\n", "missing header"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := AssemblyPreprocessOptions{FileName: "main.s"}
			if tc.name != "no-resolver" {
				opt.ReadInclude = func(parent, name string) (string, []byte, error) {
					if name == "main.s" {
						return name, []byte(tc.source), nil
					}
					return "", nil, fmt.Errorf("missing header %s", name)
				}
			}
			if _, err := PreprocessAssemblySource(tc.source, opt); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want %q", err, tc.want)
			}
		})
	}
	if _, err := preprocess("#include \"legacy.h\"\nRET\n"); err != nil {
		t.Fatalf("legacy Parse compatibility: %v", err)
	}
	if got, err := PreprocessAssemblySource("#ifdef ABSENT\n#include notQuoted\n#endif\nRET\n", AssemblyPreprocessOptions{}); err != nil || strings.TrimSpace(got) != "RET" {
		t.Fatalf("inactive include = %q, %v", got, err)
	}
}

func TestPreprocessAssemblyGoObjectOracle(t *testing.T) {
	// These are assembler objects, not runtime/ISA coverage. The actual Go
	// assembler independently consumes the original header graph, then checks
	// the same data bytes as the emitted source on all supported architectures.
	for _, target := range []struct{ arch, goos, key, value, define string }{
		{"amd64", "linux", "GOAMD64", "v1", "GOAMD64_v1"},
		{"amd64", "linux", "GOAMD64", "v3", "GOAMD64_v3"},
		{"386", "linux", "GO386", "sse2", "GO386_sse2"},
		{"386", "linux", "GO386", "softfloat", "GO386_softfloat"},
		{"arm", "linux", "GOARM", "5", "GOARM_5"},
		{"arm", "linux", "GOARM", "6,softfloat", "GOARM_6"},
		{"arm", "linux", "GOARM", "7", "GOARM_7"},
		{"arm64", "linux", "GOARM64", "v9.1,lse", "GOARM64_LSE"},
		{"wasm", "js", "", "", "GOARCH_wasm"},
	} {
		t.Run(target.arch+"-"+target.value, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
				t.Fatal(err)
			}
			headers := map[string]string{
				"sub/outer.h": "#include \"inner.h\"\n#define VALUE OUTER+INNER\n",
				"inner.h":     "#define INNER 2\n",
			}
			for name, body := range headers {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			source := "#define OUTER 40\n#ifdef " + target.define + "\n#include \"sub/outer.h\"\n#else\n#include \"absent.h\"\n#define LEAK 1\n#endif\n" +
				"#ifdef LEAK\nBAD\n#endif\nDATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n"
			defines := GoAssemblerDefinesWithEnv(target.goos, target.arch, map[string]string{target.key: target.value})
			if !strings.Contains(","+strings.Join(defines, ",")+",", ","+target.define+",") {
				t.Fatalf("resolved CPU define %s missing: %v", target.define, defines)
			}
			got, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
				FileName: "entry.s", Defines: defines,
				ReadInclude: func(parent, name string) (string, []byte, error) {
					body, err := os.ReadFile(filepath.Join(dir, name))
					return name, body, err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []struct{ name, body string }{{"original", source}, {"expanded", got}} {
				path := filepath.Join(dir, input.name+".s")
				if err := os.WriteFile(path, []byte(input.body), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"tool", "asm", "-S", "-p", "oracle", "-I", dir, "-o", filepath.Join(dir, input.name+".o")}
				for _, define := range defines {
					args = append(args, "-D", define)
				}
				args = append(args, path)
				command := exec.Command("go", args...)
				command.Dir = dir
				command.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.arch)
				out, err := command.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "2a 00 00 00") {
					t.Fatalf("%s actual Go object data: %v\n%s", input.name, err, out)
				}
			}
		})
	}
}

func TestGoAssemblerDefinesExplicitEnvironment(t *testing.T) {
	t.Setenv("GOAMD64", "v1")
	got := GoAssemblerDefinesWithEnv("linux", "amd64", map[string]string{"GOAMD64": "v3"})
	if strings.Join(got, ",") != "GOOS_linux,GOARCH_amd64,GOAMD64_v3" {
		t.Fatalf("defines use process rather than resolved configuration: %v", got)
	}
}

func TestPreprocessAssemblyGoControlTokenOracle(t *testing.T) {
	for _, name := range []string{"A·B", "A∕B", "·Start", "∕Start"} {
		t.Run(name, func(t *testing.T) {
			source := "#define " + name + " 1\n#ifdef " + name + "\n#define VALUE 42\n#endif\n#undef " + name + "\n#ifndef " + name +
				"\nDATA ·value(SB)/4,$VALUE\n#endif\nGLOBL ·value(SB),8,$4\n"
			runGoAssemblyControlOracle(t, source, true)
			got, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{})
			if err != nil || !strings.Contains(got, "$42") {
				t.Fatalf("Go assembly control identifier %q: %q, %v", name, got, err)
			}
		})
	}
	for _, source := range []string{
		"#ifdef\n#endif\n", "#ifndef A/B\n#endif\n", "#ifdef 42\n#endif\n",
		"#define A 1\n#undef A·\n", "#define A 1\n#undef A trailing\n", "#else extra\n", "#endif extra\n",
		"#line 337\n", "#line nope \"file.s\"\n", "#line 337 \"file.s\" trailing\n",
	} {
		runGoAssemblyControlOracle(t, source, false)
		if _, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{}); err == nil {
			t.Errorf("Go-rejected preprocessor control accepted: %q", source)
		}
	}
	const validLine = "#line 337 \"source name.s\"\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n"
	runGoAssemblyControlOracle(t, validLine, true)
	if got, err := PreprocessAssemblySource(validLine, AssemblyPreprocessOptions{}); err != nil || !strings.Contains(got, "$42") {
		t.Fatalf("valid Go #line: %q, %v", got, err)
	}
	const inactiveExpandedInclude = "#define BODY \\\n#ifdef ABSENT \\\n#include malformed missing operand \\\n#endif\nBODY\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n"
	runGoAssemblyControlOracle(t, inactiveExpandedInclude, true)
	if got, err := PreprocessAssemblySource(inactiveExpandedInclude, AssemblyPreprocessOptions{}); err != nil || !strings.Contains(got, "$42") {
		t.Errorf("inactive macro-expanded include parsed: %q, %v", got, err)
	}
	const invalidExpandedCondition = "#define BODY \\\n#ifdef ABSENT garbage \\\n#endif\nBODY\n"
	runGoAssemblyControlOracle(t, invalidExpandedCondition, false)
	if _, err := PreprocessAssemblySource(invalidExpandedCondition, AssemblyPreprocessOptions{}); err == nil {
		t.Fatal("Go-rejected macro-expanded condition accepted")
	}
}

func runGoAssemblyControlOracle(t *testing.T, source string, accepted bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "source.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "tool", "asm", "-S", "-p", "control", "-o", filepath.Join(dir, "go.o"), path)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := command.CombinedOutput()
	if (err == nil) != accepted {
		t.Fatalf("Go control oracle accepted=%v, want %v: %v\n%s", err == nil, accepted, err, out)
	}
	if accepted && !strings.Contains(string(out), "2a 00 00 00") {
		t.Fatalf("actual Go data bytes missing:\n%s", out)
	}
}
