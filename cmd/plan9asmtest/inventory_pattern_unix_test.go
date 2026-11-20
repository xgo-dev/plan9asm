//go:build unix

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActualGoCompactedPatternRetainsEveryShardRoot(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	var source strings.Builder
	source.WriteString("package fixture\nimport \"testing\"\n")
	prefix := "TestGoAMD64FixedLocal" + strings.Repeat("CompleteOriginalSource", 3)
	const count = 480
	for index := 0; index < count; index++ {
		fmt.Fprintf(&source, "func %sFamily%03d(t *testing.T) { t.Run(\"child\",func(t *testing.T){}) }\n", prefix, index)
	}
	directory := fixture(t, source.String())
	out := filepath.Join(t.TempDir(), "receipts")
	err := runSuite(context.Background(), config{Go: "go", Dir: directory, Package: ".",
		Out: out, Shards: 2, Timeout: time.Minute, Flags: []string{"-p=1"}})
	if err != nil {
		t.Fatal("actual Go rejected the exact factored selector", err)
	}
	report := readReport(t, out)
	if report.Status != "passed" || len(report.Names) != count || report.RootPassed != count ||
		report.ChildPassed != count || report.RootFailed != 0 || report.RootSkipped != 0 || report.RootMissing != 0 {
		t.Fatalf("compressed selection lost actual roots or child outcomes: %+v", report)
	}
	for _, shard := range report.Shards {
		if len(strings.Join(shard.Names, "|")) <= 16000 || shard.Status != "passed" {
			t.Fatal("each actual shard must exercise exact selector factoring", shard.Status, len(shard.Names))
		}
	}
}
