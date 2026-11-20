package gotoolprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This low-level source-retention fixture copies only the original driver
// registration source files. It is not a public SDK observation or frame owner.
func sdkDependencyIncludeFixture(t *testing.T, assembly string) (amd64OriginalListPackage, string, *Observation, *amd64OriginalObservationFiles) {
	t.Helper()
	request := amd64OriginalObservationFixture(t, "bodyful")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	profile, err := Capture(ctx, request.GoBinary, t.TempDir(), request.Environment, request.Target, nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	macros, err := CaptureAssemblerMacros(runtime.GOROOT(), profile, "fixture/sdk")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for source := range macros.ToolSourceSHA256 {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(source)))
		if err != nil {
			t.Fatal(err)
		}
		writeSDKIncludeFixture(t, root, source, string(data))
	}
	writeSDKIncludeFixture(t, root, "src/fixture/sdk/value_amd64.s", assembly)
	writeSDKIncludeFixture(t, root, "src/fixture/sibling/value.h", "#define VALUE 7\n")
	writeSDKIncludeFixture(t, root, "pkg/include/shared.h", "#define SHARED 11\n")
	pkg := amd64OriginalListPackage{Standard: true}
	pkg.ImportPath, pkg.Dir, pkg.SFiles = "fixture/sdk", filepath.Join(root, "src", "fixture", "sdk"), []string{"value_amd64.s"}
	files := newAMD64OriginalObservationFiles()
	if err := retainAMD64OriginalPackageDirectory(pkg, pkg.Dir, files); err != nil {
		t.Fatal(err)
	}
	return pkg, root, profile, files
}

// These source-only tests do not mint an SDK package or compiler-export role.
// Actual selected SDK packages and the ordinary consumer are exercised by the
// independent three-platform observation and factory tests.
func sdkIncludeSourceFixture(t *testing.T, assembly string, sources map[string]string) (amd64OriginalListPackage, string, *amd64OriginalObservationFiles) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeSDKIncludeFixture(t, root, "src/fixture/sdk/value_amd64.s", assembly)
	writeSDKIncludeFixture(t, root, "pkg/include/shared.h", "#define SHARED 11\n")
	for name, source := range sources {
		writeSDKIncludeFixture(t, root, name, source)
	}
	pkg := amd64OriginalListPackage{Standard: true}
	pkg.ImportPath, pkg.Dir = "fixture/sdk", filepath.Join(root, "src", "fixture", "sdk")
	pkg.SFiles = []string{"value_amd64.s"}
	files := newAMD64OriginalObservationFiles()
	if err := retainAMD64OriginalPackageDirectory(pkg, pkg.Dir, files); err != nil {
		t.Fatal(err)
	}
	if err := files.directory(filepath.Join(root, "pkg", "include"), true); err != nil {
		t.Fatal(err)
	}
	return pkg, root, files
}

func TestAMD64OriginalSDKIncludeSearchAndMutation(t *testing.T) {
	for _, test := range []struct {
		name, assembly string
		sources        map[string]string
		retained       []string
		mutation       string
	}{
		{
			name: "nested package CWD, not including directory",
			assembly: "#include \"../sibling/outer.h\"\nTEXT ·Value(SB),4,$0-0\n" +
				"MOVQ $VALUE,AX\nRET\n",
			sources: map[string]string{
				"src/fixture/sibling/outer.h":  "#include \"chosen.h\"\n",
				"src/fixture/sdk/chosen.h":     "#define VALUE 7\n",
				"src/fixture/sibling/chosen.h": "not valid assembly\n",
			},
			retained: []string{"src/fixture/sibling/outer.h", "src/fixture/sdk/chosen.h"},
			mutation: "src/fixture/sibling/outer.h",
		},
		{
			name:     "shared fallback and late package shadow",
			assembly: "#include \"shared.h\"\n",
			retained: []string{"pkg/include/shared.h"},
			mutation: "src/fixture/sdk/shared.h",
		},
		{
			name:     "package header shadows shared",
			assembly: "#include \"shared.h\"\n",
			sources:  map[string]string{"src/fixture/sdk/shared.h": "#define SHARED 13\n"},
			retained: []string{"src/fixture/sdk/shared.h"},
			mutation: "src/fixture/sdk/shared.h",
		},
		{
			name:     "both physical branches guarded",
			assembly: "#ifdef CONDITIONAL\n#include \"../sibling/yes.h\"\n#else\n#include \"../sibling/no.h\"\n#endif\n",
			sources: map[string]string{
				"src/fixture/sibling/yes.h": "#define VALUE 7\n",
				"src/fixture/sibling/no.h":  "#define VALUE 9\n",
			},
			retained: []string{"src/fixture/sibling/yes.h", "src/fixture/sibling/no.h"},
			mutation: "src/fixture/sibling/no.h",
		},
		{
			name:     "checked-in generated-header spelling is traversed",
			assembly: "#include \"go_asm.h\"\n",
			sources: map[string]string{
				"src/fixture/sdk/go_asm.h":   "#include \"../sibling/size.h\"\n",
				"src/fixture/sibling/size.h": "#define Type__size 8\n",
			},
			retained: []string{"src/fixture/sdk/go_asm.h", "src/fixture/sibling/size.h"},
			mutation: "src/fixture/sibling/size.h",
		},
		{
			name:     "compiler-generated header absence is guarded",
			assembly: "#include \"go_asm.h\"\n",
			mutation: "src/fixture/sdk/go_asm.h",
		},
		{
			name:     "escaped literal and repeated include",
			assembly: "#include \"../sibling/\\x76alue.h\" // comment\n#include \"../sibling/value.h\"\n",
			sources:  map[string]string{"src/fixture/sibling/value.h": "#define VALUE 7\n"},
			retained: []string{"src/fixture/sibling/value.h"},
			mutation: "src/fixture/sibling/new.h",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg, root, files := sdkIncludeSourceFixture(t, test.assembly, test.sources)
			if err := captureAMD64SDKIncludeSources(pkg, root, files); err != nil {
				t.Fatal(err)
			}
			for _, name := range test.retained {
				if files.hashes[filepath.Join(root, filepath.FromSlash(name))] == "" {
					t.Errorf("missing guarded header %s", name)
				}
			}
			if len(files.cpp) != 0 {
				t.Fatal("source closure minted ordinary CPP permission")
			}
			if err := files.verify(); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(test.name, "nested package") {
				request := amd64OriginalObservationFixture(t, "bodyful")
				ctx, cancel := amd64OriginalObservationContext(t)
				defer cancel()
				output, diagnostic, err := RunBounded(ctx, pkg.Dir, request.Environment, request.GoBinary,
					"tool", "asm", "-p", pkg.ImportPath, "-o", filepath.Join(t.TempDir(), "original.o"), pkg.SFiles[0])
				if err != nil {
					t.Fatalf("original Go fixed-CWD nested include: %v\n%s\n%s", err, output, diagnostic)
				}
				if files.hashes[filepath.Join(root, "src", "fixture", "sibling", "chosen.h")] != "" {
					t.Fatal("nested include resolved relative to including header")
				}
			}
			writeSDKIncludeFixture(t, root, test.mutation, "// changed original source or search membership\n")
			if err := files.verify(); err == nil {
				t.Fatal("changed source/search closure escaped verification")
			}
		})
	}
}

func TestAMD64OriginalSDKIncludeUnclosedSourcesFail(t *testing.T) {
	for _, test := range []struct{ name, source string }{
		{"dynamic", "#define HEADER \"shared.h\"\n#include HEADER\n"},
		{"macro-generated directive", "#define LOAD #include \"shared.h\"\nLOAD\n"},
		{"embedded directive", "MOVQ #include \"shared.h\"\n"},
		{"absolute path", "#include \"/outside.h\"\n"},
		{"root escape", "#include \"../../../../outside.h\"\n"},
		{"missing header", "#include \"missing.h\"\n"},
		{"missing directory", "#include \"missing/header.h\"\n"},
		{"extra operand", "#include \"shared.h\" extra\n"},
		{"angle operand", "#include <shared.h>\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg, root, files := sdkIncludeSourceFixture(t, test.source, nil)
			if err := captureAMD64SDKIncludeSources(pkg, root, files); err == nil {
				t.Fatal("unclosed include source accepted")
			}
		})
	}
	for _, kind := range []string{"symlink", "directory", "changed selected source"} {
		t.Run(kind, func(t *testing.T) {
			pkg, root, files := sdkIncludeSourceFixture(t, "#include \"../sibling/value.h\"\n", map[string]string{
				"src/fixture/sibling/neighbor.h": "// retain sibling directory\n",
			})
			name := filepath.Join(root, "src", "fixture", "sibling", "value.h")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(filepath.Join(root, "pkg", "include", "shared.h"), name)
			case "directory":
				err = os.Mkdir(name, 0700)
			default:
				err = os.WriteFile(filepath.Join(pkg.Dir, pkg.SFiles[0]), []byte("// changed\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := captureAMD64SDKIncludeSources(pkg, root, files); err == nil {
				t.Fatal("unbound source role accepted")
			}
		})
	}
}

func TestAMD64OriginalSDKIncludeSourceBounds(t *testing.T) {
	t.Run("distinct file limit", func(t *testing.T) {
		pkg, root, files := sdkIncludeSourceFixture(t, "// original source\n", nil)
		// The same enqueue bound covers initial selection and recursive
		// includes. Check it before any path can acquire a source role.
		for index := 0; index < 4096; index++ {
			pkg.SFiles = append(pkg.SFiles, fmt.Sprintf("unretained-%04d.s", index))
		}
		if err := captureAMD64SDKIncludeSources(pkg, root, files); err == nil || !strings.Contains(err.Error(), "file bound") {
			t.Fatalf("missing explicit file bound: %v", err)
		}
	})
	t.Run("duplicate paths do not consume the distinct limit", func(t *testing.T) {
		pkg, root, files := sdkIncludeSourceFixture(t, "#include \"shared.h\"\n", nil)
		for index := 0; index < 4096; index++ {
			pkg.SFiles = append(pkg.SFiles, pkg.SFiles[0])
		}
		if err := captureAMD64SDKIncludeSources(pkg, root, files); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("total byte limit", func(t *testing.T) {
		pkg, root, files := sdkIncludeSourceFixture(t, "#include \"large.h\"\n", map[string]string{
			"src/fixture/sdk/large.h": "//" + strings.Repeat("x", (16<<20)-2),
		})
		if err := captureAMD64SDKIncludeSources(pkg, root, files); err == nil || !strings.Contains(err.Error(), "byte bound") {
			t.Fatalf("missing explicit byte bound: %v", err)
		}
	})
}

func writeSDKIncludeFixture(t *testing.T, root, name, source string) {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAMD64OriginalSDKIncludeSiblingSourceClosure(t *testing.T) {
	assembly := "#include \"../sibling/value.h\"\nTEXT ·Value(SB),4,$0-0\nMOVQ $VALUE,AX\nRET\n"
	pkg, root, profile, files := sdkDependencyIncludeFixture(t, assembly)
	request := amd64OriginalObservationFixture(t, "bodyful")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	object := filepath.Join(t.TempDir(), "original.o")
	output, diagnostic, err := RunBounded(ctx, pkg.Dir, request.Environment, request.GoBinary,
		"tool", "asm", "-p", pkg.ImportPath, "-o", object, "value_amd64.s")
	if err != nil {
		t.Fatalf("original Go sibling include: %v\n%s\n%s", err, output, diagnostic)
	}
	if info, err := os.Stat(object); err != nil || info.Size() == 0 {
		t.Fatalf("original Go did not produce the sibling-include object: %v", err)
	}
	if err := captureAMD64OriginalSDKDependency(pkg, root, profile, files); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(root, "src", "fixture", "sibling", "value.h")
	if files.hashes[header] == "" {
		t.Fatal("actual original Go include outside package/shared roots has no byte guard")
	}
	if len(files.cpp) != 0 {
		t.Fatal("dependency include retention minted ordinary CPP authority")
	}
	writeSDKIncludeFixture(t, root, "src/fixture/sibling/value.h", "#define VALUE 9\n")
	if err := files.verify(); err == nil {
		t.Fatal("changed SDK sibling include escaped original source verification")
	}
}
