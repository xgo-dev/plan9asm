package diffreport

import "testing"

func TestMergeRequiresConsistentEvidence(t *testing.T) {
	batch := func(id string) Report {
		return Report{SchemaVersion: 1, Goarch: "amd64", Goos: "linux", GoVersion: "go1.27.3", LLVMVersion: "Debian LLVM version 22.1.8", NativeOracleRan: true,
			TotalInputs: 3, ComparedInputs: 3,
			Cases: []Case{{ID: id, Status: "passed", VerificationMode: "native_diff", ExecutedInputs: 3, ComparedInputs: 3}}}
	}
	for name, change := range map[string]func(*Report){
		"GOOS":         func(r *Report) { r.Goos = "darwin" },
		"GOARCH":       func(r *Report) { r.Goarch = "386" },
		"Go":           func(r *Report) { r.GoVersion = "go1.27.4" },
		"LLVM":         func(r *Report) { r.LLVMVersion = "Debian LLVM version 22.1.7" },
		"duplicate ID": func(r *Report) { r.Cases[0].ID = "z" },
		"prior totals": func(r *Report) { r.FailedInputs = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			first, second := batch("z"), batch("a")
			change(&second)
			if err := first.Merge(second); err == nil {
				t.Fatal("accepted inconsistent reports")
			}
			if first.TotalInputs != 3 || len(first.Cases) != 1 {
				t.Fatal("failed merge modified the report")
			}
		})
	}
	first := batch("z")
	if err := first.Merge(batch("a")); err != nil {
		t.Fatal(err)
	}
	if first.ComparedInputs != 6 || first.TotalInputs != 6 || len(first.Cases) != 2 || first.Cases[0].ID != "a" {
		t.Fatalf("wrong merged evidence: %+v", first)
	}
}

func TestLLVM22PrereleaseBanner(t *testing.T) {
	for _, v := range []string{"22.1.0rc1", "22.0.0git", "22.1.8", "23.1.0rc1", "220.0.0"} {
		got := LLVM22("LLVM version " + v + "\n")
		if v[:3] == "22." && got != v || v[:3] != "22." && got != "" {
			t.Errorf("version %s: %q", v, got)
		}
	}
}
