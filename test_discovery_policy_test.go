package plan9asm

import (
	"go/build/constraint"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests may need a particular OS or Go API version, but must remain visible to
// llgo. Until llgo can run a test, execute it with Go instead of hiding it from
// the other compiler with a source-level exclusion.
func TestRegressionTestsRemainDiscoverableByLLGo(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != "." && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "_out" || entry.Name() == "testdata" || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(source), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "package ") {
				break
			}
			if !constraint.IsGoBuild(line) && !constraint.IsPlusBuild(line) {
				continue
			}
			expression, err := constraint.Parse(line)
			if err != nil {
				t.Errorf("%s: invalid build constraint: %v", path, err)
				continue
			}
			if excludesLLGoTests(expression, false) {
				t.Errorf("%s: tests must remain discoverable by llgo; remove %q", path, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func excludesLLGoTests(expression constraint.Expr, negated bool) bool {
	switch expr := expression.(type) {
	case *constraint.TagExpr:
		return expr.Tag == "llgo" && negated
	case *constraint.NotExpr:
		return excludesLLGoTests(expr.X, !negated)
	case *constraint.AndExpr:
		return excludesLLGoTests(expr.X, negated) || excludesLLGoTests(expr.Y, negated)
	case *constraint.OrExpr:
		return excludesLLGoTests(expr.X, negated) || excludesLLGoTests(expr.Y, negated)
	default:
		return false
	}
}

func TestLLGoTestConstraintPolicy(t *testing.T) {
	for _, tc := range []struct {
		expression string
		want       bool
	}{
		{"!llgo", true},
		{"go1.27 && !llgo", true},
		{"!windows && !llgo", true},
		{"!(llgo || windows)", true},
		{"linux || (darwin && !llgo)", true},
		{"go1.27 && !windows", false},
		{"llgo", false},
		{"linux || darwin", false},
	} {
		expression, err := constraint.Parse("//go:build " + tc.expression)
		if err != nil {
			t.Fatal(err)
		}
		if got := excludesLLGoTests(expression, false); got != tc.want {
			t.Errorf("constraint %q: exclusion=%v, want %v", tc.expression, got, tc.want)
		}
	}
}
