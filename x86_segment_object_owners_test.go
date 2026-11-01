package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var x86SegmentObjectOwners = map[string]string{
	"TestX86SegmentMOVLinux386CompleteObjects":     "i386-unknown-linux-gnu",
	"TestX86SegmentMOVWindows386CompleteObjects":   "i686-pc-windows-msvc",
	"TestX86SegmentMOVDarwinAMD64CompleteObjects":  "x86_64-apple-darwin",
	"TestX86SegmentMOVLinuxAMD64CompleteObjects":   "x86_64-unknown-linux-gnu",
	"TestX86SegmentMOVWindowsAMD64CompleteObjects": "x86_64-pc-windows-msvc",
}

func x86SegmentObjectOwnerSourceError(source string) error {
	file, err := parser.ParseFile(token.NewFileSet(), "objects_test.go", source, parser.AllErrors)
	if err != nil {
		return err
	}
	targets := make(map[string]string)
	for _, target := range x86RawReturnTargets {
		if targets[target.triple] != "" {
			return fmt.Errorf("duplicate complete target %s", target.triple)
		}
		targets[target.triple] = target.arch
	}
	seen := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fn.Name.Name, "TestX86SegmentMOV") ||
			!strings.HasSuffix(fn.Name.Name, "CompleteObjects") {
			continue
		}
		triple, expected := x86SegmentObjectOwners[fn.Name.Name]
		if !expected || seen[triple] || fn.Body == nil || len(fn.Body.List) != 1 {
			return fmt.Errorf("missing, duplicate or noncanonical complete owner %s", fn.Name.Name)
		}
		statement, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return fmt.Errorf("owner %s does not execute its target", fn.Name.Name)
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return fmt.Errorf("owner %s has no complete target call", fn.Name.Name)
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != "x86SegmentMOVTargetCompleteObjects" {
			return fmt.Errorf("owner %s substituted its executor", fn.Name.Name)
		}
		for index, expected := range []string{targets[triple], triple} {
			literal, ok := call.Args[index+1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return fmt.Errorf("owner %s has no literal target", fn.Name.Name)
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil || expected == "" || value != expected {
				return fmt.Errorf("owner %s changed target axis", fn.Name.Name)
			}
		}
		seen[triple] = true
	}
	if len(seen) != len(targets) || len(seen) != len(x86SegmentObjectOwners) {
		return fmt.Errorf("complete object owner union is %d, want all %d targets", len(seen), len(targets))
	}
	return nil
}

func TestX86SegmentMOVObjectOwnersCoverFullMatrix(t *testing.T) {
	source, err := os.ReadFile("x86_segment_mov_objects_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := x86SegmentObjectOwnerSourceError(string(source)); err != nil {
		t.Fatal(err)
	}
}

func TestX86SegmentMOVObjectOwnersRejectMissingOrCroppedTargets(t *testing.T) {
	var source strings.Builder
	source.WriteString("package plan9asm\n")
	names := make([]string, 0, len(x86SegmentObjectOwners))
	for name := range x86SegmentObjectOwners {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		triple, arch := x86SegmentObjectOwners[name], "amd64"
		if strings.HasPrefix(triple, "i") {
			arch = "386"
		}
		fmt.Fprintf(&source, "func %s(t *testing.T) {\nx86SegmentMOVTargetCompleteObjects(t,%q,%q)\n}\n",
			name, arch, triple)
	}
	base := source.String()
	if err := x86SegmentObjectOwnerSourceError(base); err != nil {
		t.Fatal("independent complete owner fixture rejected", err)
	}
	for name, changed := range map[string]string{
		"missing":        strings.Replace(base, names[0], "TestMissingTarget", 1),
		"duplicate":      base + strings.SplitN(base, "package plan9asm\n", 2)[1],
		"architecture":   strings.Replace(base, `"amd64"`, `"386"`, 1),
		"triple":         strings.Replace(base, `"x86_64-apple-darwin"`, `"x86_64-unknown-linux-gnu"`, 1),
		"executor":       strings.Replace(base, "x86SegmentMOVTargetCompleteObjects(", "unrelatedExecutor(", 1),
		"skip":           strings.Replace(base, "{\n", "{\nt.Skip(\"cropped\")\n", 1),
		"partial-target": strings.Replace(base, `"i386-unknown-linux-gnu"`, `"i386-unknown-linux-gnu/text"`, 1),
	} {
		if changed == base || x86SegmentObjectOwnerSourceError(changed) == nil {
			t.Error("object owner mechanism accepted mutation", name)
		}
	}
}
