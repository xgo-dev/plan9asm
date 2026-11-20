package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func testEmbedFixture(t *testing.T, directive string) (PackageProof, *TestEmbedSelection, *ConsumerInput, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]string{
		"source.go":          "package actualembed\nimport _ \"embed\"\n" + directive + "\nvar Data []byte\n",
		"plain.bin":          "original plain bytes",
		"space name":         "quoted original bytes",
		"assets/a.bin":       "a",
		"assets/.hidden":     "dot",
		"assets/_hidden":     "underscore",
		"assets/sub/b.bin":   "b",
		"assets/sub/.hidden": "nested dot",
	}
	pkg := PackageProof{
		GoFiles: []string{"source.go"}, CompiledGoFiles: []string{"source.go"},
		SourceSHA256: make(map[string]string),
	}
	proof := &TestEmbedSelection{Protocol: TestEmbedProtocol, Directives: make(map[string]string), Files: make(map[string]string)}
	view := &ConsumerInput{Sources: make(map[string]string), Headers: make(map[string]string), Directories: make(map[string][]string)}
	for file, text := range data {
		name := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		view.Sources[file] = bytesSHA256([]byte(text))
	}
	if err := filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		dir, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		members, err := os.ReadDir(name)
		if err != nil {
			return err
		}
		for _, member := range members {
			view.Directories[filepath.ToSlash(dir)] = append(view.Directories[filepath.ToSlash(dir)], member.Name())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	header, err := TestSelectionHeader("source.go", []byte(data["source.go"]))
	if err != nil {
		t.Fatal(err)
	}
	view.Headers["source.go"] = header
	pkg.SourceSHA256["source.go"] = view.Sources["source.go"]
	proof.Directives["source.go"], err = TestEmbedDirectives("source.go", []byte(data["source.go"]))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := build.Default.ImportDir(root, build.IgnoreVendor)
	if err != nil {
		t.Fatal(err)
	}
	proof.Patterns = actual.EmbedPatterns
	proof.Files, _, err = resolveTestEmbedFiles(".", proof.Patterns, view.Directories, view.Sources)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, proof, view, root
}

func TestTestDependencyEmbedGrammarAndSelection(t *testing.T) {
	for _, axis := range []struct {
		directive string
		files     []string
	}{
		{"//go:embed plain.bin", []string{"plain.bin"}},
		{"//go:embed \"space name\"", []string{"space name"}},
		{"//go:embed `space name`", []string{"space name"}},
		{"//go:embed assets", []string{"assets/a.bin", "assets/sub/b.bin"}},
		{"//go:embed all:assets", []string{"assets/.hidden", "assets/_hidden", "assets/a.bin", "assets/sub/.hidden", "assets/sub/b.bin"}},
		{"//go:embed assets/*", []string{"assets/.hidden", "assets/_hidden", "assets/a.bin", "assets/sub/b.bin"}},
		{"//go:embed plain.bin\n//go:embed plain.bin assets/*.bin", []string{"assets/a.bin", "plain.bin"}},
		{"", nil},
	} {
		t.Run(axis.directive, func(t *testing.T) {
			pkg, proof, view, root := testEmbedFixture(t, axis.directive)
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			var replay TestEmbedSelection
			if err := json.Unmarshal(data, &replay); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateTestEmbedSelection(pkg, &replay, view); err != nil {
				t.Fatal(err)
			}
			if err := VerifyTestEmbedDirectives(pkg, &replay, root); err != nil {
				t.Fatal(err)
			}
			var actual []string
			for file := range replay.Files {
				actual = append(actual, file)
			}
			sort.Strings(actual)
			if !reflect.DeepEqual(actual, axis.files) {
				t.Fatalf("embedded bytes = %q, independent expected %q", actual, axis.files)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, _, err := RunBounded(ctx, root, append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local"), "go", "list", "-e", "-json", ".")
			if err != nil {
				t.Fatal(err)
			}
			var selected struct {
				EmbedFiles []string
				Error      *struct{ Err string }
			}
			if err := json.Unmarshal(output, &selected); err != nil || selected.Error != nil || !reflect.DeepEqual(actual, selected.EmbedFiles) {
				t.Fatalf("stock Go selected original embed files = %q, replay = %q, error = %v/%#v", selected.EmbedFiles, actual, err, selected.Error)
			}
		})
	}
}

func TestTestDependencyEmbedDirectiveWhitespaceMatchesActualGo(t *testing.T) {
	for _, separator := range []string{" ", "\t", "\v", "\f", "\u00a0", "\u2003"} {
		t.Run(fmt.Sprintf("U+%04X", []rune(separator)[0]), func(t *testing.T) {
			pkg, proof, view, root := testEmbedFixture(t, "//go:embed"+separator+"plain.bin")
			if _, err := ValidateTestEmbedSelection(pkg, proof, view); err != nil {
				t.Fatalf("actual stock Go patterns %q cannot be replayed: %v", proof.Patterns, err)
			}
			var selectedFiles []string
			if len(proof.Patterns) != 0 {
				selectedFiles = []string{"plain.bin"}
			}
			captured, err := CaptureTestEmbedSelection(pkg, root, proof.Patterns, selectedFiles)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.Patterns) == 0 {
				// Historical Go parsers may ignore this separator. Their actual
				// empty selection must remain empty, not acquire a future rule.
				if len(captured.Files) != 0 {
					t.Fatal("empty actual selection acquired embedded bytes")
				}
			}
			if _, err := ValidateTestEmbedSelection(pkg, captured, view); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, _, err := RunBounded(ctx, root, append(os.Environ(), "GO111MODULE=off", "GOTOOLCHAIN=local"), "go", "list", "-e", "-json", ".")
			if err != nil {
				t.Fatal(err)
			}
			var actual struct {
				EmbedPatterns []string
				EmbedFiles    []string
				Error         *struct{ Err string }
			}
			if err := json.Unmarshal(output, &actual); err != nil || actual.Error != nil || !reflect.DeepEqual(actual.EmbedPatterns, captured.Patterns) {
				t.Fatalf("actual Go directive selection disagrees: %s, %v", output, err)
			}
			files, err := CaptureTestEmbedSelection(pkg, root, actual.EmbedPatterns, actual.EmbedFiles)
			if err != nil || !reflect.DeepEqual(files, captured) {
				t.Fatalf("actual Go asset selection disagrees: %#v, %v", files, err)
			}
		})
	}
}

func TestTestDependencyEmbedRejectsMissingOrMutatedWitness(t *testing.T) {
	for name, mutate := range map[string]func(*PackageProof, *TestEmbedSelection, *ConsumerInput){
		"old protocol":               func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) { p.Protocol = "" },
		"missing all directives":     func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) { p.Directives = nil },
		"missing selected directive": func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) { delete(p.Directives, "source.go") },
		"directive changed only": func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) {
			p.Directives["source.go"] = "//go:embed plain.bin\n"
		},
		"pattern changed only":  func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) { p.Patterns = []string{"plain.bin"} },
		"missing selected file": func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) { delete(p.Files, "assets/a.bin") },
		"changed selected file bytes": func(_ *PackageProof, p *TestEmbedSelection, _ *ConsumerInput) {
			p.Files["assets/a.bin"] = strings.Repeat("0", 64)
		},
		"missing nested directory": func(_ *PackageProof, _ *TestEmbedSelection, v *ConsumerInput) { delete(v.Directories, "assets/sub") },
		"same hash missing member": func(_ *PackageProof, _ *TestEmbedSelection, v *ConsumerInput) {
			v.Directories["assets"] = []string{".hidden", "_hidden", "sub"}
		},
		"truncated directory":  func(_ *PackageProof, _ *TestEmbedSelection, v *ConsumerInput) { delete(v.Directories, ".") },
		"fake original source": func(p *PackageProof, _ *TestEmbedSelection, _ *ConsumerInput) { p.SourceSHA256 = nil },
		"malformed directory member": func(_ *PackageProof, _ *TestEmbedSelection, v *ConsumerInput) {
			v.Directories["assets"] = []string{"../escape"}
		},
		"file masquerades as directory": func(_ *PackageProof, _ *TestEmbedSelection, v *ConsumerInput) {
			v.Directories["assets/a.bin"] = []string{}
		},
		"mixed nested module": func(_ *PackageProof, _ *TestEmbedSelection, v *ConsumerInput) {
			v.Sources["assets/go.mod"] = bytesSHA256([]byte("module example.invalid/foreign\n"))
			v.Directories["assets"] = append(v.Directories["assets"], "go.mod")
			sort.Strings(v.Directories["assets"])
		},
	} {
		t.Run(name, func(t *testing.T) {
			pkg, proof, view, _ := testEmbedFixture(t, "//go:embed assets")
			mutate(&pkg, proof, view)
			if _, err := ValidateTestEmbedSelection(pkg, proof, view); err == nil {
				t.Fatal("accepted incomplete/changed embed selection")
			}
		})
	}
	t.Run("paired deletion", func(t *testing.T) {
		pkg, _, view, _ := testEmbedFixture(t, "//go:embed assets")
		if _, err := ValidateTestEmbedSelection(pkg, nil, view); err == nil {
			t.Fatal("paired input/consumer deletion downgraded the required embed role")
		}
	})
}

func TestTestDependencyEmbedOriginalDirectiveBytesAndGrammar(t *testing.T) {
	pkg, proof, _, root := testEmbedFixture(t, "//go:embed assets")
	proof.Directives["source.go"] = "//go:embed plain.bin\n"
	if err := VerifyTestEmbedDirectives(pkg, proof, root); err == nil {
		t.Fatal("arbitrary directive kept full-file SHA but passed actual byte comparison")
	}
	for _, source := range []string{
		"package p\nvar s = `//go:embed fake`\n",
		"package p\n/* //go:embed fake */\n",
		"package p\n//go:embedded fake\n",
	} {
		actual, err := TestEmbedDirectives("source.go", []byte(source))
		if err != nil || actual != "" {
			t.Fatalf("non-directive received source authority: %q, %v", actual, err)
		}
	}
	for _, directive := range []string{"//go:embed \"unterminated", "//go:embed \"x\"trailing", "//go:embed ../bad", "//go:embed .", "//go:embed [", "//go:embed absent"} {
		pkg, proof, view, _ := testEmbedFixture(t, "//go:embed plain.bin")
		proof.Directives["source.go"] = directive + "\n"
		proof.Patterns = []string{strings.TrimPrefix(directive, "//go:embed ")}
		if _, err := ValidateTestEmbedSelection(pkg, proof, view); err == nil {
			t.Errorf("accepted malformed/empty original pattern %q", directive)
		}
	}
	if path.Dir(pkg.GoFiles[0]) != "." {
		t.Fatal("fixture changed package directory identity")
	}
}

func TestTestDependencyEmbedActualCaptureRejectsOtherRootAndDuplicates(t *testing.T) {
	pkg, proof, _, root := testEmbedFixture(t, "//go:embed plain.bin")
	outside := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(outside, []byte("original plain bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureTestEmbedSelection(pkg, root, proof.Patterns, []string{outside}); err == nil {
		t.Fatal("identical asset bytes from another module acquired original membership")
	}
	if _, err := CaptureTestEmbedSelection(pkg, root, []string{"plain.bin", "plain.bin"}, nil); err == nil {
		t.Fatal("noncanonical actual duplicate patterns were accepted")
	}
	if _, err := CaptureTestEmbedSelection(pkg, root, proof.Patterns, []string{"plain.bin", "plain.bin"}); err == nil {
		t.Fatal("noncanonical actual duplicate asset roles were accepted")
	}
}

func TestTestDependencyEmbedMatchingWorkIsBounded(t *testing.T) {
	const count = 2050
	var patterns []string
	directories, sources := map[string][]string{".": {}}, make(map[string]string)
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("file-%04d.bin", index)
		directories["."] = append(directories["."], name)
		sources[name] = bytesSHA256(nil)
		patterns = append(patterns, name)
	}
	_, _, err := resolveTestEmbedFiles(".", patterns, directories, sources)
	if err == nil || !strings.Contains(err.Error(), "matching-work bound") {
		t.Fatalf("large valid inventory did not retain the explicit resource failure: %v", err)
	}
}
