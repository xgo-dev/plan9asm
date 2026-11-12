package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInventoryIsActualCompleteAndCanonical(t *testing.T) {
	const listing = "TestZ\nFuzzSeeds\nExample\nTestA\nBenchmarkIgnored\nok\texample.org/root\t0.003s\n"
	pkg, names, benchmarks, err := parseList(listing)
	if err != nil || pkg != "example.org/root" || !reflect.DeepEqual(names, []string{"Example", "FuzzSeeds", "TestA", "TestZ"}) || !reflect.DeepEqual(benchmarks, []string{"BenchmarkIgnored"}) {
		t.Fatalf("actual inventory: %q %v %v", pkg, names, err)
	}

	for _, bad := range []string{
		"", "ok\texample.org/root\t0.003s\n", "TestA\n", "TestA\nTestA\nok\tp\t0s\n",
		"BenchmarkA\nok\tp\t0s\n", "TestA\nFAIL\tp\t0s\n",
		"TestA\nok\tp\t0s\nTestB\n", "TestA\nok\tp\t0s\nok\tq\t0s\n",
		"TestA/sub\nok\tp\t0s\n", "TestA\nunknown diagnostic\nok\tp\t0s\n",
		"TestA\nok\tp\tgarbage\n", "TestA\nok\tp\t0s trailing corruption\n",
	} {
		if _, _, _, err := parseList(bad); err == nil {
			t.Errorf("accepted damaged/empty inventory %q", bad)
		}
	}

	first, err := partition(names, 7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := partition([]string{"TestZ", "TestA", "FuzzSeeds", "Example"}, 7)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("unstable hash partition: %v %v %v", first, second, err)
	}
	seen := make(map[string]int)
	for _, shard := range first {
		for _, name := range shard {
			seen[name]++
		}
	}
	if len(seen) != len(names) {
		t.Fatalf("partition lost inventory: %v", first)
	}
	for _, name := range names {
		if seen[name] != 1 {
			t.Fatalf("partition duplicates/omits %s: %v", name, first)
		}
	}
	for _, bad := range [][]string{nil, {"TestA", "TestA"}, {"TestA", "not-a-test"}} {
		if _, err := partition(bad, 7); err == nil {
			t.Errorf("partition accepted invalid plan %v", bad)
		}
	}
	if _, err := partition(names, 0); err == nil {
		t.Fatal("accepted zero shards")
	}
}

func events(actions ...string) string {
	var out strings.Builder
	for _, action := range actions {
		fields := strings.SplitN(action, " ", 2)
		event := map[string]string{"Action": fields[0], "Package": "p"}
		if len(fields) == 2 {
			event["Test"] = fields[1]
		}
		data, _ := json.Marshal(event)
		out.Write(data)
		out.WriteByte('\n')
	}
	return out.String()
}

func TestJSONExactlyMatchesPlanIncludingFuzzSeedsAndSubtests(t *testing.T) {
	good := events("start", "run TestA", "run TestA/sub", "pass TestA/sub", "pass TestA", "run FuzzSeeds", "run FuzzSeeds/seed#0", "pass FuzzSeeds/seed#0", "pass FuzzSeeds", "run Example", "pass Example", "pass")
	outcomes, err := validateEvents(strings.NewReader(good), "p", []string{"Example", "FuzzSeeds", "TestA"})
	if err != nil || len(outcomes) != 5 || outcomes["FuzzSeeds/seed#0"] != "pass" {
		t.Fatalf("lost actual seed/subtest execution: %v %v", outcomes, err)
	}
	for _, bad := range []string{
		"", good + "{", strings.Replace(good, "\"Package\":\"p\"", "\"Package\":\"q\"", 1),
		events("start", "run TestA", "pass TestA", "output TestA", "pass"),
		events("start", "run TestA", "run TestA", "pass TestA", "pass"),
		events("start", "run TestA", "pass TestA", "pass TestA", "pass"),
		events("start", "pass TestA", "pass"),
		events("start", "run TestA", "run TestA/sub", "pass TestA", "pass"),
		events("start", "run TestUnknown", "pass TestUnknown", "pass"),
		events("start", "run TestA", "fail TestA", "pass"),
		events("start", "run TestA", "pass TestA", "fail"),
		events("start", "run TestA", "pass TestA"),
		events("start", "run TestA", "pass TestA", "pass", "pass"),
		events("start", "run TestA", "unknown TestA", "pass"),
	} {
		if _, err := validateEvents(strings.NewReader(bad), "p", []string{"TestA"}); err == nil {
			t.Errorf("accepted incomplete/corrupt JSON %q", bad)
		}
	}
	if _, err := runPattern([]string{strings.Repeat("a", 16001)}); err == nil {
		t.Fatal("oversized Windows-safe regex silently accepted")
	}
	if _, err := validateEvents(strings.NewReader(events("start", "run TestA", "pass TestA", "pass")), "p", []string{"TestA", "Example"}); err == nil {
		t.Fatal("accepted omitted planned example")
	}
	if states, err := validateEvents(strings.NewReader(events("start", "run TestA", "skip TestA", "pass")), "p", []string{"TestA"}); err != nil || states["TestA"] != "skip" {
		t.Fatalf("must retain existing Go skip distinctly: %v %v", states, err)
	}
	// Slashes may be part of one Go subtest name, not a real intermediate
	// parent. Do not invent missing-parent failures from string spelling.
	if _, err := validateEvents(strings.NewReader(events("start", "run TestA", "run TestA/path/leaf", "pass TestA/path/leaf", "pass TestA", "pass")), "p", []string{"TestA"}); err != nil {
		t.Fatal(err)
	}
}

func TestSelectionAndFuzzingFlagsCannotReduceInventory(t *testing.T) {
	for _, flag := range []string{"-run=TestA", "-skip=TestA", "-list=.", "-fuzz=FuzzA", "-bench=.", "-count=2", "-exec=echo", "-c", "-args", "./..."} {
		if _, _, err := validateFlags([]string{flag}); err == nil {
			t.Errorf("accepted scope-changing flag %q", flag)
		}
	}
	args := []string{"-race", "-covermode=atomic", "-coverpkg=./...", "-tags", "fixture", "-p=1", "-coverprofile=coverage.out"}
	got, profile, err := validateFlags(args)
	if err != nil || profile != "coverage.out" || !reflect.DeepEqual(got, args[:len(args)-1]) {
		t.Fatalf("lost instrumentation/build flags: %v %q %v", got, profile, err)
	}
}

func TestCoverageMergeRetainsExactBlocksAndCounters(t *testing.T) {
	write := func(name, data string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a := write("a", "mode: atomic\np/a.go:1.1,2.1 2 3\np/a.go:3.1,4.1 1 0\n")
	b := write("b", "mode: atomic\np/a.go:3.1,4.1 1 2\np/a.go:1.1,2.1 2 4\n")
	merged, err := mergeCoverage([]string{a, b})
	if err != nil || string(merged) != "mode: atomic\np/a.go:1.1,2.1 2 7\np/a.go:3.1,4.1 1 2\n" {
		t.Fatalf("coverage merge: %q %v", merged, err)
	}
	for _, bad := range []string{
		"mode: set\np/a.go:1.1,2.1 2 1\np/a.go:3.1,4.1 1 1\n",
		"mode: atomic\np/a.go:1.1,2.1 2 1\n",
		"mode: atomic\np/a.go:1.1,2.1 3 1\np/a.go:3.1,4.1 1 1\n",
		"mode: atomic\np/a.go:1.1,2.1 2 1\np/a.go:1.1,2.1 2 1\n",
		"mode: atomic\np/a.go:1.1,2.1 2 18446744073709551615\np/a.go:3.1,4.1 1 1\n",
		"mode: atomic\np/a.go:1.1,2.1 2 -1\np/a.go:3.1,4.1 1 1\n",
	} {
		if _, err := mergeCoverage([]string{a, write("bad", bad)}); err == nil {
			t.Errorf("accepted damaged/incompatible coverage %q", bad)
		}
	}
}

func TestCoverageSetModeAndZeroStatementBlocks(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, []byte("mode: set\np/a.go:1.1,1.1 0 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := mergeCoverage([]string{a, b})
	if err != nil || string(merged) != "mode: set\np/a.go:1.1,1.1 0 1\n" {
		t.Fatalf("set counters must OR, not add: %q %v", merged, err)
	}
}
