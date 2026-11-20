package main

import "testing"

func TestRunnerInheritedBuildContextIsExplicitAndNarrow(t *testing.T) {
	for _, flags := range [][]string{
		{"-tags=byollvm"},
		{"-tags", "byollvm", "-p=2", "-coverprofile=complete.cover"},
	} {
		if err := validateRunnerGoFlags("windows", "-tags=byollvm", flags); err != nil {
			t.Fatal("declared Windows binding context", err)
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if err := validateRunnerGoFlags(goos, "", nil); err != nil {
			t.Fatal("ordinary empty environment changed", err)
		}
		for _, inherited := range []string{
			"-run=TestOne", "-count=0", "-tags=byollvm -run=TestOne",
			"-tags=byollvm ", "-tags=byollvm,foreign", "-tags byollvm",
		} {
			if err := validateRunnerGoFlags(goos, inherited, []string{"-tags=byollvm"}); err == nil {
				t.Fatalf("hidden/filtering environment accepted: %s %q", goos, inherited)
			}
		}
		if goos != "windows" {
			if err := validateRunnerGoFlags(goos, "-tags=byollvm", []string{"-tags=byollvm"}); err == nil {
				t.Fatal("Windows exception leaked to another host", goos)
			}
		}
	}
	for _, flags := range [][]string{
		nil, {"-tags"}, {"-tags=foreign"}, {"-tags=byollvm,foreign"},
		{"-tags=byollvm", "-tags=byollvm"}, {"-tags=byollvm", "-tags=foreign"},
		{"-tags=byollvm", "-run=TestOne"}, {"-tags=byollvm", "-count=0"},
		{"-gcflags", "-tags=byollvm"}, {"-ldflags", "-tags=byollvm"},
	} {
		if err := validateRunnerGoFlags("windows", "-tags=byollvm", flags); err == nil {
			t.Fatalf("undeclared/conflicting/filtered build selection accepted: %v", flags)
		}
	}
}
