package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type ppSemanticGoResult struct {
	stage, output string
	accepted      bool
}

// These regressions compare two real stock-Go objects or two real stock-Go
// source rejections. They do not execute the resulting assembly programs.
func ppSemanticGoObject(t *testing.T, stage, source string, headers map[string]string, defines []string) ppSemanticGoResult {
	t.Helper()
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	driver, err = filepath.Abs(driver)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, body := range headers {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	file, object := filepath.Join(directory, "entry.s"), filepath.Join(directory, "entry.o")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOTOOLCHAIN=local", "GOFLAGS=")
	run := func(arguments ...string) ([]byte, error) {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		command := exec.CommandContext(ctx, driver, arguments...)
		command.Dir, command.Env = directory, environment
		return runtimeOracleCombinedOutput(ctx, command)
	}
	version, err := run("version")
	if err != nil {
		t.Fatalf("actual selected Go version: %v\n%s", err, version)
	}
	toolDirectory, err := run("env", "GOTOOLDIR")
	if err != nil {
		t.Fatalf("actual selected Go tool directory: %v\n%s", err, toolDirectory)
	}
	assemblerName := "asm"
	if strings.HasSuffix(driver, ".exe") {
		assemblerName += ".exe"
	}
	assembler := filepath.Join(strings.TrimSpace(string(toolDirectory)), assemblerName)
	driverBytes, err := os.ReadFile(driver)
	if err != nil {
		t.Fatal(err)
	}
	assemblerBytes, err := os.ReadFile(assembler)
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"tool", "asm", "-S", "-p", "cppsemantic", "-I", directory, "-o", object}
	for _, definition := range defines {
		arguments = append(arguments, "-D", definition)
	}
	arguments = append(arguments, file)
	output, commandErr := run(arguments...)
	exit := 0
	if commandErr != nil {
		var actualExit *exec.ExitError
		if !errors.As(commandErr, &actualExit) || actualExit.ExitCode() != 1 ||
			!strings.Contains(string(output), file+":") {
			t.Fatalf("unknown original Go failure, not a source rejection: %v\n%s", commandErr, output)
		}
		exit = actualExit.ExitCode()
	}
	var objectBytes []byte
	if exit == 0 {
		objectBytes, err = os.ReadFile(object)
		if err != nil || len(objectBytes) == 0 {
			t.Fatalf("actual accepted Go object missing: %v", err)
		}
	}
	receipt, err := json.Marshal(struct {
		Stage, Version, Driver, Assembler, DriverSHA, AssemblerSHA string
		Arguments                                                  []string
		Source, Object                                             []byte
		Headers                                                    map[string]string
		Exit                                                       int
		Output                                                     string
	}{stage, strings.TrimSpace(string(version)), driver, assembler,
		fmt.Sprintf("%x", sha256.Sum256(driverBytes)), fmt.Sprintf("%x", sha256.Sum256(assemblerBytes)),
		arguments, []byte(source), objectBytes, headers, exit, string(output)})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CPP_ACTUAL_GO_RECEIPT %s", receipt)
	return ppSemanticGoResult{stage: stage, output: string(output), accepted: exit == 0}
}

func ppSemanticCompareAcceptance(t *testing.T, source string, accepted bool) {
	t.Helper()
	original := ppSemanticGoObject(t, "original", source, nil, nil)
	if original.accepted != accepted {
		t.Fatalf("original source expectation differs from actual Go: %s", original.output)
	}
	expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{FileName: "entry.s"})
	if err != nil {
		if accepted {
			t.Fatalf("Go-accepted source was rejected: %v", err)
		}
		return
	}
	normalized := ppSemanticGoObject(t, "normalized", expanded, nil, nil)
	if normalized.accepted != original.accepted {
		t.Fatalf("CPP changed actual Go source acceptance: original=%t normalized=%t\nsource=%q\nnormalized=%q",
			original.accepted, normalized.accepted, source, expanded)
	}
}

func TestPreprocessAssemblyCommentSeamsActualGo(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"block", "/ * RET * /\n"},
		{"line", "/ / BAD\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ppSemanticCompareAcceptance(t, "TEXT ·Probe(SB),$0-0\n"+test.body+"RET\n", false)
		})
	}
	t.Run("real-comment-control", func(t *testing.T) {
		ppSemanticCompareAcceptance(t, "TEXT ·Probe(SB),$0-0\n/* real comment */\nRET\n", true)
	})
}

func TestPreprocessAssemblyBuildCommentActualGo(t *testing.T) {
	for _, test := range []struct {
		name, source string
		accepted     bool
	}{
		{"after-code", "TEXT ·Probe(SB),$0-0\n//go:build amd64\nRET\n", false},
		{"first-line-cpp-control", "#define EMPTY\n//go:build amd64\nTEXT ·Probe(SB),$0-0\nRET\n", true},
		{"after-newline-cpp", "\n#define EMPTY\n//go:build amd64\nTEXT ·Probe(SB),$0-0\nRET\n", false},
		{"header-control", "//go:build amd64\n\nTEXT ·Probe(SB),$0-0\nRET\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ppSemanticCompareAcceptance(t, test.source, test.accepted)
		})
	}
}

func TestPreprocessAssemblyInstructionEOFActualGo(t *testing.T) {
	t.Run("instruction-eof", func(t *testing.T) {
		ppSemanticCompareAcceptance(t, "TEXT ·Probe(SB),$0-0\nRET", false)
	})
	t.Run("newline-control", func(t *testing.T) {
		ppSemanticCompareAcceptance(t, "TEXT ·Probe(SB),$0-0\nRET\n", true)
	})
	t.Run("empty-define-control", func(t *testing.T) {
		ppSemanticCompareAcceptance(t, "TEXT ·Probe(SB),$0-0\nRET\n#define EMPTY", true)
	})
}

func TestPreprocessAssemblyFunctionMacroLookaheadActualGo(t *testing.T) {
	const program = "TEXT ·Probe(SB),$0-0\nRET\n"
	for _, test := range []struct {
		name, source string
		accepted     bool
	}{
		{"bare-opcode", "#define RET(x) x\n" + program, false},
		{"bare-register", "#define AX(x) x\nTEXT ·Probe(SB),$0-0\nMOVQ $42, AX\nRET\n", false},
		{"inactive-newline", "#define F(x) x\n#ifdef ABSENT\nF\n#endif\n" + program, false},
		{"inactive-punctuation", "#define F(x) x\n#ifdef ABSENT\nF +\n#endif\n" + program, false},
		{"invoked-control", "#define EMIT(x) x\nTEXT ·Probe(SB),$0-0\nEMIT(RET)\n", true},
		{"inactive-invoked-control", "#define F() RET\n#ifdef ABSENT\nF()\n#endif\n" + program, true},
		{"ordinary-identifier-control", "#define F(x) x\n" + program, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ppSemanticCompareAcceptance(t, test.source, test.accepted)
		})
	}
}

func TestPreprocessAssemblyCanonicalIncludeActualGo(t *testing.T) {
	const marker = "DATA ·value(SB)/4,$VALUE\nGLOBL ·value(SB),8,$4\n"
	for _, spelling := range []string{"x·h", "x∕h"} {
		canonical := strings.NewReplacer("·", ".", "∕", "/").Replace(spelling)
		for _, style := range []string{"function-argument", "predefined", "macro-body"} {
			t.Run(style+"/"+spelling, func(t *testing.T) {
				headers := map[string]string{
					canonical: "#define VALUE 42\n",
					spelling:  "#define VALUE 13\n",
				}
				var source string
				var defines []string
				switch style {
				case "function-argument":
					source = "#define USE(P) \\\n#include P \\\n\nUSE(\"" + spelling + "\")\n" + marker
				case "predefined":
					defines = []string{"USE=#include \"" + spelling + "\"\n"}
					source = "USE\n" + marker
				case "macro-body":
					source = "#define USE \\\n#include \"" + spelling + "\" \\\n\nUSE\n" + marker
				}
				original := ppSemanticGoObject(t, "original", source, headers, defines)
				if !original.accepted || !strings.Contains(original.output, "2a 00 00 00") {
					t.Fatalf("original Go did not select its canonical include: %s", original.output)
				}
				var selected []string
				expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
					FileName: "entry.s", Defines: defines,
					ReadInclude: func(parent, name string) (string, []byte, error) {
						selected = append(selected, name)
						body, ok := headers[name]
						if !ok || parent != "entry.s" {
							return "", nil, fmt.Errorf("unbound include %s from %s", name, parent)
						}
						return name, []byte(body), nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				normalized := ppSemanticGoObject(t, "normalized", expanded, nil, nil)
				if !normalized.accepted || !strings.Contains(normalized.output, "2a 00 00 00") ||
					strings.Join(selected, ",") != canonical {
					t.Fatalf("CPP changed actual include/object identity: selected=%v want=%q\n%s", selected, canonical, normalized.output)
				}
			})
		}
	}
}
