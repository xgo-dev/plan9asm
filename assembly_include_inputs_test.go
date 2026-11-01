package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestReadGoAssemblySourceInputsShareExactExpansion(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"entry_amd64.s": "#include \"middle.inc\"\n#include \"go_asm.h\"\nTEXT ·Value(SB),$0-0\nRET\n",
		"middle.inc":    "#include \"value.inc\"\n", "value.inc": "#define BIAS 7\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(root, "entry_amd64.s")
	plain, err := ReadGoAssemblySource(input, root)
	if err != nil {
		t.Fatal(err)
	}
	observed, inputs, err := ReadGoAssemblySourceWithReport(input, root)
	if err != nil || !reflect.DeepEqual(plain, observed) {
		t.Fatalf("input inventory altered the existing source expansion: %v", err)
	}
	want := make(map[string]string)
	for name, data := range files {
		physical, err := sourcepath.Resolve(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		want[physical] = fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
	}
	physicalEntry, err := sourcepath.Resolve(input)
	if err != nil {
		t.Fatal(err)
	}
	want[input] = want[physicalEntry] // The original top-level request stays visible.
	if !reflect.DeepEqual(inputs.Inputs, want) {
		t.Fatalf("missing generated source invented or actual nested inputs lost: got=%v want=%v", inputs, want)
	}
	wantMiss := filepath.Join(filepath.Dir(physicalEntry), "go_asm.h")
	if !reflect.DeepEqual(inputs.SearchMisses, []string{wantMiss}) {
		t.Fatalf("unread generated header absence disappeared: %v", inputs.SearchMisses)
	}
}

func TestReadGoAssemblySourceInputsRetainRequestedAliases(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "entry_amd64.s")
	include := filepath.Join(root, "alias.inc")
	target := filepath.Join(root, "actual.inc")
	const data = "#define BIAS 7\n"
	if err := os.WriteFile(target, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, include); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("#include \"alias.inc\"\nTEXT ·Value(SB),$0-0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, inputs, err := ReadGoAssemblySourceWithReport(entry, root)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := sourcepath.Resolve(target)
	if err != nil {
		t.Fatal(err)
	}
	physicalDirectory, err := sourcepath.Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	requestedInclude := filepath.Join(physicalDirectory, filepath.Base(include))
	if inputs.Inputs[requestedInclude] != fmt.Sprintf("%x", sha256.Sum256([]byte(data))) || inputs.Inputs[physical] != inputs.Inputs[requestedInclude] {
		t.Fatal("original include alias/actual target disappeared from the same read inventory", inputs)
	}
}

func TestReadGoAssemblySourceReportSeparatesFallbackSearchMiss(t *testing.T) {
	for _, include := range []string{"fallback.inc", "missing/fallback.inc"} {
		t.Run(include, func(t *testing.T) {
			root, sdk := t.TempDir(), t.TempDir()
			entry := filepath.Join(root, "entry_amd64.s")
			fallback := filepath.Join(sdk, "pkg", "include", filepath.FromSlash(include))
			if err := os.MkdirAll(filepath.Dir(fallback), 0700); err != nil {
				t.Fatal(err)
			}
			const data = "#define BIAS 7\n"
			if err := os.WriteFile(fallback, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(entry, []byte("#include \""+include+"\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			// This filesystem-only read report makes no compiler/source claim.
			report := &GoAssemblySourceReadReport{Inputs: make(map[string]string)}
			observed, err := readGoAssemblySource(entry, root, sdk, report)
			plain, plainErr := ReadGoAssemblySourceAtGOROOT(entry, root, sdk)
			if err != nil || plainErr != nil || string(observed) != data || !reflect.DeepEqual(plain, observed) {
				t.Fatalf("same-pass fallback changed expansion: %q %v %v", observed, err, plainErr)
			}
			physicalRoot, err := sourcepath.Resolve(root)
			if err != nil {
				t.Fatal(err)
			}
			miss := filepath.Join(physicalRoot, filepath.FromSlash(include))
			if _, invented := report.Inputs[miss]; invented || !reflect.DeepEqual(report.SearchMisses, []string{miss}) {
				t.Fatalf("search miss became read input or disappeared: %+v", report)
			}
			physicalFallback, err := sourcepath.Resolve(fallback)
			if err != nil || report.Inputs[physicalFallback] != fmt.Sprintf("%x", sha256.Sum256([]byte(data))) {
				t.Fatalf("actual fallback bytes absent: %+v %v", report, err)
			}
		})
	}
}

func TestReadGoAssemblySourceReportErrorReturnsNoInventory(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "entry_amd64.s")
	if err := os.WriteFile(entry, []byte("#include \"cycle.inc\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cycle.inc"), []byte("#include \"cycle.inc\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, report, err := ReadGoAssemblySourceWithReport(entry, root)
	if err == nil || data != nil || report != nil {
		t.Fatalf("partial read became successful inventory: %q %+v %v", data, report, err)
	}
}
