package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/scanner"
)

type ppMacroControlFixture struct {
	name, prefix, replacement, argument, suffix string
}

func ppMacroControlFixtures() []ppMacroControlFixture {
	const data = "DATA ·value(SB)/4,$42\n"
	return []ppMacroControlFixture{
		{"define", "", "#define VALUE P\n", "42", "DATA ·value(SB)/4,$VALUE\n"},
		{"undef", "#define LEAK 1\n", "#undef P\n", "LEAK", "#ifndef LEAK\n" + data + "#endif\n"},
		{"include", "", "#include P\n", `"choice.h"`, "DATA ·value(SB)/4,$VALUE\n"},
		{"line", "", "#line P \"logical source.s\"\n", "337", data},
		{"ifdef", "#define PRESENT 1\n", "#ifdef P\n" + data + "#else\nDATA ·value(SB)/4,$13\n#endif\n", "PRESENT", ""},
		{"ifndef", "", "#ifndef P\n" + data + "#else\nDATA ·value(SB)/4,$13\n#endif\n", "ABSENT", ""},
		{"open-parent-condition", "#define PRESENT 1\n", "#ifdef P\n", "PRESENT", data + "#else\nDATA ·value(SB)/4,$13\n#endif\n"},
		{"inactive-invocation", "", "#else\n", "", data + "#endif\n"},
	}
}

func ppMacroControlSource(fixture ppMacroControlFixture, style string) string {
	body, definition, invocation := fixture.replacement, "APPLY", "APPLY"
	if style == "function" {
		definition += "(P)"
		invocation += "(" + fixture.argument + ")"
	} else {
		body = strings.ReplaceAll(body, "P", fixture.argument)
	}
	if style == "alias" {
		invocation = "INVOKE"
	}
	var source strings.Builder
	source.WriteString(fixture.prefix)
	source.WriteString("#define " + definition + " \\\n")
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		source.WriteString(line + " \\\n")
	}
	source.WriteByte('\n')
	if style == "alias" {
		source.WriteString("#define INVOKE APPLY\n")
	}
	source.WriteString("TEXT ·Probe(SB),$0-0\nRET\n")
	if fixture.name == "inactive-invocation" {
		source.WriteString("#ifdef ABSENT\n")
	}
	source.WriteString(invocation + "\n")
	source.WriteString(fixture.suffix)
	source.WriteString("GLOBL ·value(SB),8,$4\n")
	return source.String()
}

func TestPreprocessAssemblyGeneratedControlGoOracle(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			for _, fixture := range ppMacroControlFixtures() {
				t.Run(fixture.name, func(t *testing.T) {
					for _, style := range []string{"object", "alias", "function"} {
						t.Run(style, func(t *testing.T) {
							source := ppMacroControlSource(fixture, style)
							headers := map[string]string{"choice.h": "#define VALUE 42\n"}
							listing := ppMacroControlGoObject(t, target, source, headers, "original")
							if !strings.Contains(string(listing), "2a 00 00 00") {
								t.Fatalf("actual Go did not select the expected marker: %s", listing)
							}
							t.Logf("original Go accepted %s %s/%s source_sha=%x listing_sha=%x",
								target, fixture.name, style, sha256.Sum256([]byte(source)), sha256.Sum256(listing))
							var includes []string
							expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
								FileName: "entry.s",
								ReadInclude: func(parent, name string) (string, []byte, error) {
									includes = append(includes, parent+":"+name)
									body, ok := headers[name]
									if !ok {
										return "", nil, fmt.Errorf("missing exact header %s", name)
									}
									return name, []byte(body), nil
								},
							})
							if err != nil {
								t.Fatalf("Go-accepted generated control failed preprocessing: %v", err)
							}
							if fixture.name == "include" && strings.Join(includes, ",") != "entry.s:choice.h" {
								t.Fatalf("generated include changed its physical invocation origin: %v", includes)
							}
							listing = ppMacroControlGoObject(t, target, expanded, nil, "expanded")
							if !strings.Contains(string(listing), "2a 00 00 00") {
								t.Fatalf("expanded Go marker differs from original: %s", listing)
							}
						})
					}
				})
			}
		})
	}
}

func ppMacroControlGoObject(t *testing.T, target, source string, headers map[string]string, stage string) []byte {
	t.Helper()
	directory := t.TempDir()
	for name, body := range headers {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(directory, "entry.s")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(target, "/")
	object := filepath.Join(directory, stage+".o")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "macrooracle", "-I", directory,
		"-o", object, file)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOOS="+parts[0], "GOARCH="+parts[1], "GOENV=off", "GOTOOLCHAIN=local")
	listing, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("%s original-source Go object %s: %v\n%s\nsource:\n%s", stage, target, err, listing, source)
	}
	objectBytes, err := os.ReadFile(object)
	if err != nil || len(objectBytes) == 0 {
		t.Fatalf("%s Go object %s missing or empty: %v", stage, target, err)
	}
	t.Logf("CPP_GO_OBJECT_RECEIPT target=%s stage=%s source_sha=%x object_sha=%x listing_sha=%x",
		target, stage, sha256.Sum256([]byte(source)), sha256.Sum256(objectBytes), sha256.Sum256(listing))
	return listing
}

func TestPreprocessAssemblyTokenBoundaries(t *testing.T) {
	for _, source := range []string{
		"MOVQ $1 << 2, AX\n",
		"MOVQ $1 < < 2, AX\n",
		"MOVD R1 @ > 2, R0\n",
		"MOVD R1 - > 2, R0\n",
		"DATA ·value(SB)/8,$0 .5\n",
		"DATA ·value(SB)/8,$1 . 0\n",
		"TEXT ·Probe(SB),$0-0\nloop: MOVQ AX, BX; RET\n",
		"MOVW R0, R1:R2\n",
		"DATA ·value(SB)/8,$\"a // b /* c */\"\n",
	} {
		expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{})
		if err != nil {
			t.Fatal(err)
		}
		original := ppMacroControlTokens(t, source)
		normalized := ppMacroControlTokens(t, expanded)
		if strings.Join(original, "\n") != strings.Join(normalized, "\n") {
			t.Fatalf("normalization manufactured or removed lexical tokens:\n%q\n%q\n%v\n%v", source, expanded, original, normalized)
		}
	}
}

func ppMacroControlTokens(t *testing.T, source string) []string {
	t.Helper()
	reader := newPPGoReader("entry.s", source)
	var tokens []string
	for {
		token, err := reader.next()
		if err != nil {
			t.Fatal(err)
		}
		if token.kind == scanner.EOF {
			return tokens
		}
		if token.kind != '\n' {
			tokens = append(tokens, fmt.Sprintf("%d:%s", token.kind, token.value))
		}
	}
}

func TestPreprocessAssemblyGeneratedIncludeRetainsErrorChain(t *testing.T) {
	witness := fmt.Errorf("exact include error: %w", os.ErrNotExist)
	const source = "#define INCLUDE #include \"missing.h\" \\\n\nINCLUDE\n"
	_, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
		FileName: "original.s",
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if parent != "original.s" || name != "missing.h" {
				t.Fatalf("unbound generated include origin: %q %q", parent, name)
			}
			return "", nil, witness
		},
	})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "original.s:3") {
		t.Fatalf("generated include lost its original error or physical invocation: %v", err)
	}
}

func TestPreprocessAssemblyGeneratedControlLLVMObjectsFiveArchitectures(t *testing.T) {
	llc, optimizer := findLLVM22Tool("llc"), findLLVM22Tool("opt")
	if llc == "" || optimizer == "" {
		t.Fatal("LLVM 22 llc and opt are required")
	}
	fixture := ppMacroControlFixture{
		name: "complete-controls", prefix: "#define LEAK 1\n",
		replacement: "#include \"choice.h\"\n#undef LEAK\n#ifndef LEAK\n" +
			"#define VALUE P\n#else\n#define VALUE 13\n#endif\n#line 337 \"logical source.s\"\n",
		argument: "42", suffix: "DATA ·value(SB)/4,$VALUE\n",
	}
	headers := map[string]string{"choice.h": "#ifndef CHOSEN\n#define CHOSEN 1\n#endif\n"}
	source := ppMacroControlSource(fixture, "function")
	for _, target := range []struct {
		arch                 Arch
		goos, goarch, triple string
	}{
		{ArchAMD64, "linux", "386", "i386-unknown-linux-gnu"},
		{ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu"},
		{ArchARM, "linux", "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu"},
		{ArchWASM, "js", "wasm", "wasm32-unknown-unknown"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			platform := target.goos + "/" + target.goarch
			original := ppMacroControlGoObject(t, platform, source, headers, "original")
			if !strings.Contains(string(original), "2a 00 00 00") {
				t.Fatalf("original source marker differs: %s", original)
			}
			expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
				FileName: "entry.s",
				ReadInclude: func(parent, name string) (string, []byte, error) {
					body, ok := headers[name]
					if !ok || parent != "entry.s" {
						return "", nil, fmt.Errorf("missing exact generated include %s from %s", name, parent)
					}
					return name, []byte(body), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			normalized := ppMacroControlGoObject(t, platform, expanded, nil, "expanded")
			if !strings.Contains(string(normalized), "2a 00 00 00") {
				t.Fatalf("normalized source marker differs: %s", normalized)
			}
			parsed, err := Parse(target.arch, expanded)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(parsed, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				ResolveSym: testResolveSym("macrooracle"),
				Sigs:       map[string]FuncSig{"macrooracle.Probe": {Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if target.goarch == "wasm" && strings.Contains(ir, "blockaddress") {
				t.Fatal("macro preprocessing introduced a native code address into wasm")
			}
			directory := t.TempDir()
			ll := filepath.Join(directory, "generated.ll")
			optimized := filepath.Join(directory, "generated-o2.ll")
			object := filepath.Join(directory, "generated.o")
			if err := os.WriteFile(ll, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			for _, command := range []struct {
				name string
				args []string
			}{
				{optimizer, []string{"-S", "-passes=default<O2>", ll, "-o", optimized}},
				{llc, []string{"-mtriple=" + target.triple, "-filetype=obj", optimized, "-o", object}},
			} {
				ctx, cancel := runtimeOracleStageContext(t)
				process := exec.CommandContext(ctx, command.name, command.args...)
				output, err := runtimeOracleCombinedOutput(ctx, process)
				cancel()
				if err != nil {
					t.Fatalf("LLVM 22 generated-control pipeline: %v\n%s", err, output)
				}
			}
			info, err := os.Stat(object)
			if err != nil || info.Size() == 0 {
				t.Fatalf("LLVM 22 object absent or empty: %v", err)
			}
			t.Logf("original Go, normalized Go, Parse/Translate/O2/LLVM22 object: %s source_sha=%x",
				platform, sha256.Sum256([]byte(source)))
		})
	}
}
