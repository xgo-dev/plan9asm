package gotoolprofile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInstrumentationTypeNamesPhysicalSourceIdentity(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{root, foreign} {
		if err := os.WriteFile(filepath.Join(directory, "source.go"), []byte("package source\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(t.TempDir(), "module")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(root, "redirect.go")
	if err := os.Symlink(filepath.Join(foreign, "source.go"), redirect); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory.go"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, directory, root string
		files                 []string
		want                  []string
	}{
		{"canonical relative", root, root, []string{"source.go"}, []string{"source.go"}},
		{"logical root physical file", root, alias, []string{filepath.Join(root, "source.go")}, []string{"source.go"}},
		{"logical directory physical root", alias, root, []string{"source.go"}, []string{"source.go"}},
		{"logical absolute file", alias, root, []string{filepath.Join(alias, "source.go")}, []string{"source.go"}},
		{"valid empty", root, root, nil, []string{}},
		{"equal-byte foreign root", foreign, root, []string{"source.go"}, nil},
		{"absolute foreign file", root, root, []string{filepath.Join(foreign, "source.go")}, nil},
		{"source symlink escape", root, root, []string{"redirect.go"}, nil},
		{"missing source", root, root, []string{"missing.go"}, nil},
		{"nonregular source", root, root, []string{"directory.go"}, nil},
		{"missing root", root, filepath.Join(root, "missing"), nil, nil},
		{"nonregular root", root, filepath.Join(root, "source.go"), nil, nil},
		{"relative root", root, ".", []string{"source.go"}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := instrumentationTypeNames(test.files, test.directory, test.root); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("physical source selection: got %v (nil=%t), want %v (nil=%t)", got, got == nil, test.want, test.want == nil)
			}
		})
	}
}
