package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestCollectAsmTasksExplicitNonemptyScope(t *testing.T) {
	dir := t.TempDir()
	var selected []string
	for file, body := range map[string]string{
		"cpu.s": "// original nonempty placeholder\n", "white.s": "\n \t\n", "empty.s": "",
		"probe.s": "TEXT ·Probe(SB),4,$0-0\nRET\n", "unselected.s": "// not selected by Go\n",
	} {
		name := filepath.Join(dir, file)
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if file != "unselected.s" {
			selected = append(selected, name)
		}
	}
	pkg := &packages.Package{
		PkgPath: "example.invalid/scope", OtherFiles: selected,
		Module: &packages.Module{Path: "example.invalid/scope", Dir: dir},
	}
	tasks, _ := collectAsmTasks([]*packages.Package{pkg}, t.TempDir(),
		[]string{"cpu.s", "white.s", "empty.s", "probe.s", "unselected.s"})
	var files []string
	for _, task := range tasks {
		files = append(files, filepath.Base(task.AsmFile))
	}
	if want := []string{"cpu.s", "probe.s", "white.s"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("explicit scope lost selected nonzero originals or injected an unselected file: %v, want %v", files, want)
	}
	tasks, _ = collectAsmTasks([]*packages.Package{pkg}, t.TempDir(), nil)
	if len(tasks) != 1 || filepath.Base(tasks[0].AsmFile) != "probe.s" {
		t.Fatalf("legacy unscoped heuristic changed: %#v", tasks)
	}
}
