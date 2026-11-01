package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	mode := os.Getenv("GO_ORACLE_CONTROL")
	if mode == "" {
		os.Exit(m.Run())
	}
	source, object := os.Args[len(os.Args)-1], os.Args[len(os.Args)-2]
	switch mode {
	case "exit1":
		os.Exit(1)
	case "exit2":
		os.Exit(2)
	case "footer":
		fmt.Fprintln(os.Stderr, "asm: assembly failed")
	case "foreign":
		fmt.Fprintln(os.Stderr, "foreign.s:3: bad operand")
	case "foreign-prefix":
		fmt.Fprintln(os.Stderr, "foreign"+source+":3: bad operand")
	case "wrong-listing":
		fmt.Fprintln(os.Stderr, "asm: illegal combination: 00000 ("+source+":3) MOVK $65537,R0")
	case "bad-PC":
		fmt.Fprintln(os.Stderr, "asm: illegal combination: 000000 ("+source+":3) MOVD R0,R1")
	case "panic":
		fmt.Fprintln(os.Stderr, source+":3: bad operand\npanic: compiler bug")
	case "line":
		fmt.Fprintln(os.Stderr, source+":9999: bad operand")
	case "column":
		fmt.Fprintln(os.Stderr, source+":3:9999: bad operand")
	case "header":
		fmt.Fprintln(os.Stderr, source+":1: bad operand")
	case "blank":
		fmt.Fprintln(os.Stderr, source+":5: bad operand")
	case "split":
		fmt.Fprint(os.Stdout, source+":3:")
		fmt.Fprintln(os.Stderr, " bad operand")
	case "missing-object":
		os.Exit(0)
	case "empty-object":
		_ = os.WriteFile(object, nil, 0600)
		os.Exit(0)
	case "directory-object":
		_ = os.Mkdir(object, 0700)
		os.Exit(0)
	case "wrong-kind":
		_ = os.WriteFile(object, []byte("not a Go object"), 0600)
		os.Exit(0)
	case "stale-object":
		data, err := base64.StdEncoding.DecodeString(os.Getenv("GO_ORACLE_OLD_OBJECT"))
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(object, data, 0600); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	case "timeout":
		time.Sleep(time.Minute)
	default:
		os.Exit(2)
	}
	os.Exit(1)
}

func canonicalTemp(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func actualInputs(t *testing.T) (*inputTransaction, options) {
	t.Helper()
	dir := canonicalTemp(t)
	cases, families := filepath.Join(dir, "cases.txt"), filepath.Join(dir, "families.txt")
	for name, data := range map[string]string{cases: "00000000 | MOVD R0,R1\n", families: "MOVD\n"} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := filepath.EvalSymlinks(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	driver := filepath.Join(root, "bin", "go")
	if runtime.GOOS == "windows" {
		driver += ".exe"
	}
	opt := options{cases: cases, families: families, driver: driver, goroot: root}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	inputs, err := captureInputs(ctx, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range inputs.record.Commands {
		data, _ := json.Marshal(command.Observation)
		t.Logf("ORACLE_CHILD %s", data)
	}
	return inputs, opt
}

func logProbe(t *testing.T, value result) {
	t.Helper()
	data, _ := json.Marshal(value)
	t.Logf("ORACLE_CASE %s", data)
}

func TestReportCompletenessIsNotCounting(t *testing.T) {
	item := result{Status: "accepted", Attempted: true, Waited: true, Complete: true, Reported: true}
	for _, test := range []struct {
		name     string
		edit     func(*report)
		stable   bool
		deadline error
		want     bool
	}{
		{"complete", func(_ *report) {}, true, nil, true},
		{"global-change", func(_ *report) {}, false, nil, false},
		{"case-report", func(r *report) { r.ReportFailures = 1; r.Results[0].Reported = false }, true, nil, false},
		{"unattempted", func(r *report) { r.Results[0].Attempted = false }, true, nil, false},
		{"unwaited", func(r *report) { r.Results[0].Waited = false }, true, nil, false},
		{"unclosed", func(r *report) { r.Results[0].Complete = false }, true, nil, false},
		{"timeout", func(r *report) { r.Results[0].TimedOut = true }, true, context.DeadlineExceeded, false},
		{"unrecorded", func(r *report) { r.Results = nil }, true, nil, false},
		{"failed", func(r *report) { r.Results[0].Status = "failed" }, true, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := report{Selected: 1, Results: []result{item}}
			test.edit(&r)
			finalize(&r, test.stable, test.deadline)
			if r.Passed != test.want || r.Verified != test.want {
				t.Fatalf("false report pass: %+v", r)
			}
			if r.Unattempted != 1-r.Attempted {
				t.Fatal("missing/unattempted denominator lost")
			}
		})
	}
	dir := canonicalTemp(t)
	if err := os.Mkdir(filepath.Join(dir, "result.json"), 0700); err != nil {
		t.Fatal(err)
	}
	r := report{Selected: 1}
	item.directory, _ = os.Lstat(dir)
	if retainResult(&r, dir, item) == nil {
		t.Fatal("actual case report write did not fail")
	}
	finalize(&r, true, nil)
	if r.InventoryComplete || r.Passed || r.ReportFailures != 1 {
		t.Fatalf("write failure became complete: %+v", r)
	}
}

func TestWholeFamilySelectorPreservesRows(t *testing.T) {
	rows := []string{"000 | MOVD R0,R1", "000 | MOVD R0,R1", "001 | MOVD.P R0,8(R1)", "002 | ADD $1,R0", "not a row", "003 | RET"}
	want := rows[:3]
	if got := selectedRows([]byte(strings.Join(rows, "\n")), []byte("# source families\nMOVD\n")); !reflect.DeepEqual(got, want) {
		t.Fatalf("complete selection changed row order/denominator: %q", got)
	}
}

func TestRetainResultRefusesUnownedCaseDirectory(t *testing.T) {
	dir := canonicalTemp(t)
	r := report{Selected: 1}
	item := result{Status: "failed", Failure: "case directory never acquired"}
	if retainResult(&r, dir, item) == nil {
		t.Fatal("result written into a directory without the case's owned identity")
	}
	if _, err := os.Lstat(filepath.Join(dir, "result.json")); !os.IsNotExist(err) {
		t.Fatalf("unowned result target was accessed/written: %v", err)
	}
}
