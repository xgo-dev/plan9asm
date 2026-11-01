package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// EOF of an included tokenizer is not EOF of the cmd/asm input stack. These
// tests compare the original graph, not a version with appended newlines.
func TestPreprocessAssemblyDirectiveEOFGoOracle(t *testing.T) {
	const marker = "TEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n"
	tests := []struct {
		name, directive, suffix string
		rootOK                  bool
	}{
		{"empty-define", "#define EMPTY", "", true},
		{"empty-define-comment", "#define EMPTY // final comment", "", true},
		{"body-define", "#define VALUE 42", "", false},
		{"function-define", "#define EMPTY()", "", false},
		{"parameter-define", "#define ID(x) x", "", false},
		{"ifdef", "#ifdef PRESENT", "#endif\n", false},
		{"ifndef", "#ifndef ABSENT", "#endif\n", false},
		{"undef", "#undef PRESENT", "", false},
		{"else", "#ifdef ABSENT\n#else", "#endif\n", false},
		{"endif", "#ifdef ABSENT\n#endif", "", false},
		{"include", "#include \"inner.h\"", "", false},
		{"line", "#line 337 \"mapped.s\"", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, placement := range []string{"root", "header-newline", "header-token", "header-root-eof", "nested-header-newline"} {
				t.Run(placement, func(t *testing.T) {
					headers := map[string]string{"inner.h": "#define INNER 1\n"}
					source := "#define PRESENT 1\n" + marker
					accepted := false
					switch placement {
					case "root":
						source += tc.directive
						accepted = tc.rootOK
					case "header-newline":
						headers["eof.h"] = tc.directive
						source += "#include \"eof.h\"\n\n" + tc.suffix
						accepted = true
					case "header-token":
						headers["eof.h"] = tc.directive
						source += "#include \"eof.h\"\nUNEXPECTED\n" + tc.suffix
						// A macro body (including an empty object-like one) can
						// consume this token as replacement text until newline.
						accepted = strings.Contains(tc.name, "define")
					case "header-root-eof":
						headers["eof.h"] = tc.directive
						source += "#include \"eof.h\"\n"
						accepted = tc.rootOK
					case "nested-header-newline":
						headers["eof.h"] = "#include \"leaf.h\"\n"
						headers["leaf.h"] = tc.directive
						source += "#include \"eof.h\"\n\n" + tc.suffix
						accepted = true
					}
					assertDirectiveEOFGoOracle(t, source, headers, accepted)
					got, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
						FileName: "entry.s",
						ReadInclude: func(parent, name string) (string, []byte, error) {
							body, ok := headers[name]
							if !ok {
								return "", nil, fmt.Errorf("missing %s from %s", name, parent)
							}
							return name, []byte(body), nil
						},
					})
					if (err == nil) != accepted {
						t.Fatalf("preprocessor accepted=%t want Go=%t: %v\n%s", err == nil, accepted, err, got)
					}
					if accepted && (!strings.Contains(got, "$42") || strings.Contains(got, "UNEXPECTED")) {
						t.Fatalf("EOF directive leaked/swallowed assembly: %q", got)
					}
				})
			}
		})
	}
}

func assertDirectiveEOFGoOracle(t *testing.T, source string, headers map[string]string, accepted bool) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range headers {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "entry.s")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "tool", "asm", "-S", "-p", "eoforacle", "-I", dir, "-o", filepath.Join(dir, "go.o"), file)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := command.CombinedOutput()
	if (err == nil) != accepted {
		t.Fatalf("original Go EOF oracle accepted=%t want=%t: %v\n%s", err == nil, accepted, err, out)
	}
	if accepted && !strings.Contains(string(out), "2a 00 00 00") {
		t.Fatalf("actual Go marker data bytes missing: %s", out)
	}
}

func TestPreprocessAssemblyEOFIncludeRetainsDirectiveOrigin(t *testing.T) {
	const marker = "TEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n"
	headers := map[string]string{"eof.h": "#include \"inner.h\"", "inner.h": "#define INNER 1\n"}
	source := "#include \"eof.h\"\n\n" + marker
	assertDirectiveEOFGoOracle(t, source, headers, true)
	var calls []string
	_, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
		FileName: "entry.s",
		ReadInclude: func(parent, name string) (string, []byte, error) {
			calls = append(calls, parent+":"+name)
			body, ok := headers[name]
			if !ok {
				return "", nil, fmt.Errorf("missing %s", name)
			}
			return name, []byte(body), nil
		},
	})
	if err != nil || strings.Join(calls, ",") != "entry.s:eof.h,eof.h:inner.h" {
		t.Fatalf("EOF include changed its original source identity: %v %v", calls, err)
	}
}

func TestPreprocessAssemblyEOFMacroEscapeGoOracle(t *testing.T) {
	const marker = "TEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n"
	for _, tc := range []struct {
		name, header, parent string
		accepted             bool
	}{
		{"escape-newline", "#define BODY \\", "\nUNUSED\n", true},
		{"escape-backslash", "#define BODY \\\\", "UNUSED\n", true},
		{"invalid-escape-token", "#define BODY \\", "UNEXPECTED\n#define AFTER 1\n", false},
		{"invalid-escape-body", "#define BODY \\oops\n", "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"eof.h": tc.header}
			source := marker + "#include \"eof.h\"\n" + tc.parent
			assertDirectiveEOFGoOracle(t, source, headers, tc.accepted)
			got, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
				FileName: "entry.s",
				ReadInclude: func(parent, name string) (string, []byte, error) {
					return name, []byte(headers[name]), nil
				},
			})
			if (err == nil) != tc.accepted || err == nil && strings.Contains(got, "UNUSED") {
				t.Fatalf("macro EOF escape differs from Go: accepted=%t want=%t err=%v expanded=%q", err == nil, tc.accepted, err, got)
			}
		})
	}
}

func TestPreprocessAssemblyEOFMacroQuotedEscapes(t *testing.T) {
	const header = "#define VALUE \"a\\\\b\""
	const source = "TEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$42\nGLOBL ·value(SB),8,$4\n#include \"eof.h\"\n\nDATA ·quoted(SB)/3,$VALUE\nGLOBL ·quoted(SB),8,$3\n"
	assertDirectiveEOFGoOracle(t, source, map[string]string{"eof.h": header}, true)
	got, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
		FileName: "entry.s",
		ReadInclude: func(parent, name string) (string, []byte, error) {
			return name, []byte(header), nil
		},
	})
	if err != nil || !strings.Contains(got, `DATA ·quoted(SB)/3,$"a\\b"`) {
		t.Fatalf("macro escape processing changed a quoted token: %q %v", got, err)
	}
}

func TestPreprocessAssemblyEOFObjectsFiveArchitectures(t *testing.T) {
	llc, opt := findLLVM22Tool("llc"), findLLVM22Tool("opt")
	if llc == "" || opt == "" {
		t.Fatal("LLVM 22 llc and opt are required")
	}
	const source = "#include \"eof.h\"\n\nTEXT ·Probe(SB),$0-0\nRET\nDATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n"
	const header = "#ifndef ABSENT\n#define VALUE 42\n#endif"
	for _, tc := range []struct {
		arch         Arch
		goarch, goos string
		triple       string
	}{
		{ArchAMD64, "386", "linux", "i386-unknown-linux-gnu"},
		{ArchAMD64, "amd64", "linux", "x86_64-unknown-linux-gnu"},
		{ArchARM, "arm", "linux", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "arm64", "linux", "aarch64-unknown-linux-gnu"},
		{ArchWASM, "wasm", "js", "wasm32-unknown-unknown"},
	} {
		t.Run(tc.goarch, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "eof.h"), []byte(header), 0600); err != nil {
				t.Fatal(err)
			}
			expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
				FileName: "entry.s",
				ReadInclude: func(parent, name string) (string, []byte, error) {
					body, err := os.ReadFile(filepath.Join(dir, name))
					return name, body, err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []struct{ name, body string }{{"original", source}, {"expanded", expanded}} {
				file := filepath.Join(dir, input.name+".s")
				if err := os.WriteFile(file, []byte(input.body), 0600); err != nil {
					t.Fatal(err)
				}
				command := exec.Command("go", "tool", "asm", "-S", "-p", "eoforacle", "-I", dir, "-o", filepath.Join(dir, input.name+".o"), file)
				command.Env = append(os.Environ(), "GOOS="+tc.goos, "GOARCH="+tc.goarch)
				out, err := command.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "2a 00 00 00") {
					t.Fatalf("original/expanded %s Go object: %v\n%s", input.name, err, out)
				}
			}
			parsed, err := Parse(tc.arch, expanded)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(parsed, Options{
				Goarch: tc.goarch, TargetTriple: tc.triple,
				ResolveSym: testResolveSym("eoforacle"),
				Sigs:       map[string]FuncSig{"eoforacle.Probe": {Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			ll, optimized := filepath.Join(dir, "eof.ll"), filepath.Join(dir, "eof-o2.ll")
			if err := os.WriteFile(ll, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(opt, "-S", "-passes=default<O2>", ll, "-o", optimized).CombinedOutput(); err != nil {
				t.Fatalf("LLVM 22 optimize: %v\n%s", err, out)
			}
			object := filepath.Join(dir, "llvm.o")
			if out, err := exec.Command(llc, "-mtriple="+tc.triple, "-filetype=obj", optimized, "-o", object).CombinedOutput(); err != nil {
				t.Fatalf("LLVM 22 object: %v\n%s", err, out)
			}
			info, err := os.Stat(object)
			if err != nil || info.Size() == 0 {
				t.Fatalf("LLVM object absent/empty: %v", err)
			}
			t.Logf("original Go + expanded Go + Parse/Translate/O2/LLVM22 objects: %s %s", tc.goarch, tc.triple)
		})
	}
}
