//go:build unix

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Use the actual CLI and an actual first-party main module. Invalid split
// requests must fail at role validation, not because the flags are absent or
// a missing LLVM/Node/source input happens to stop execution later.
func TestModuleRootPartitionCLIRejectsInvalidRolesBeforeIO(t *testing.T) {
	moduleFixtureEnvironment(t)
	binary := parallelFixtureCLI(t)
	dir := moduleFixture(t, false)
	cases := []struct {
		name string
		args []string
	}{
		{"missing-part", []string{"-module", "-module-owner=0", "-module-root-partitions=8"}},
		{"out-of-range", []string{"-module", "-module-owner=0", "-module-root-partitions=8", "-module-root-partition=8"}},
		{"profile-part", []string{"-module", "-module-owner=1", "-module-root-partitions=8", "-module-root-partition=0"}},
		{"other-part", []string{"-module", "-module-owner=2", "-module-root-partitions=8", "-module-root-partition=0"}},
		{"ordinary-part", []string{"-module-root-partitions=8", "-module-root-partition=0"}},
		{"local-part", []string{"-module", "-module-root-partitions=8", "-module-root-partition=0"}},
		{"aggregate-part", []string{"-module", "-verify-module=missing", "-module-root-partitions=8", "-module-root-partition=0"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "must-not-exist")
			stem := filepath.Join(t.TempDir(), "cli")
			args := append([]string(nil), test.args...)
			args = append(args, "-dir", dir, "-out", out, "-shards=32", "-workers=2", "-timeout=2m")
			_, err := captureCommand(context.Background(), 30*time.Second, ".", binary, args, stem)
			stderr, readErr := os.ReadFile(stem + ".stderr")
			if err == nil || err.Error() != "exit status 1" || readErr != nil || !strings.Contains(string(stderr), "root partition scheduling") {
				t.Fatalf("actual invalid role did not reach explicit split validation: %v, read=%v\n%s", err, readErr, stderr)
			}
			if strings.Contains(string(stderr), "flag provided but not defined") {
				t.Fatalf("missing CLI grammar, not the requested role guard:\n%s", stderr)
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatalf("invalid scheduling role performed output IO: %v", err)
			}
		})
	}
}

// One independent first-party Test root per ordinary hash shard. The selector
// denominator comes from real Go -list output, not a checked-in library list.
func moduleRootPartitionFixture(t *testing.T) string {
	t.Helper()
	return moduleRootPartitionFixtureForShards(t, 32)
}

func moduleRootPartitionFixtureForShards(t *testing.T, shards int) string {
	t.Helper()
	if shards != 8 && shards != 32 && shards != 64 {
		t.Fatal("first-party witness fixture requires a complete 8-, 32- or 64-shard plan")
	}
	dir := moduleFixture(t, false)
	path := filepath.Join(dir, "value_test.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]bool, shards)
	remaining := len(seen)
	for candidate := 0; remaining != 0; candidate++ {
		if candidate >= 4096 {
			t.Fatal("bounded first-party witnesses did not fill the complete shard plan", shards)
		}
		name := fmt.Sprintf("TestRootShardWitness%d", candidate)
		hash := sha256.Sum256([]byte(name))
		index := binary.BigEndian.Uint64(hash[:8]) % uint64(len(seen))
		if seen[index] {
			continue
		}
		seen[index] = true
		remaining--
		source = append(source, []byte(fmt.Sprintf(
			"\nfunc %s(t *testing.T) { t.Run(\"child\", func(t *testing.T) { if Value() != 7 { t.Fatal(\"value\") } }) }\n", name))...)
	}
	if err := os.WriteFile(path, source, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Catch witness-generation mistakes without first executing every owner. The
// complete CLI union below still independently lists and executes these roots.
func TestModuleRootPartitionWitnessFixturesFillEveryShard(t *testing.T) {
	for _, shards := range []int{8, 32, 64} {
		t.Run(fmt.Sprint(shards), func(t *testing.T) {
			dir := moduleRootPartitionFixtureForShards(t, shards)
			syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, "value_test.go"), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			seen := make([]int, shards)
			for _, declaration := range syntax.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || !strings.HasPrefix(function.Name.Name, "TestRootShardWitness") {
					continue
				}
				hash := sha256.Sum256([]byte(function.Name.Name))
				seen[binary.BigEndian.Uint64(hash[:8])%uint64(shards)]++
			}
			for shard, count := range seen {
				if count != 1 {
					t.Fatal("each actual shard needs its own complete witness", shard, count)
				}
			}
		})
	}
}

func TestModuleRootPartitionCLIActualOwnedSubset(t *testing.T) {
	moduleFixtureEnvironment(t)
	binary := parallelFixtureCLI(t)
	dir := moduleRootPartitionFixture(t)
	out := filepath.Join(t.TempDir(), "fragment")
	stem := filepath.Join(t.TempDir(), "cli")
	_, err := captureCommand(context.Background(), 3*time.Minute, ".", binary,
		[]string{"-module", "-module-owner=0", "-module-root-partitions=8", "-module-root-partition=0",
			"-dir", dir, "-out", out, "-shards=32", "-workers=2", "-timeout=2m", "--", "-p=1"}, stem)
	if err != nil {
		t.Fatal(errorsWithActualOutput(err, stem))
	}
	var report struct {
		Schema int    `json:"schema"`
		Status string `json:"status"`
		Part   struct {
			Protocol string `json:"protocol"`
			Index    int    `json:"index"`
			Count    int    `json:"count"`
		} `json:"root_partition"`
		Names  []string      `json:"inventory"`
		Shards []shardResult `json:"shards"`
	}
	data, err := os.ReadFile(filepath.Join(out, "package-0000", "partition.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The partial receipt cannot be accepted as an ordinary complete pass.
	if err := json.Unmarshal(data, &report); err != nil || report.Schema != 2 || report.Status != "completed_owned" ||
		report.Part.Protocol != "actual_go_root_shard_fragment_v1" || report.Part.Index != 0 || report.Part.Count != 8 ||
		len(report.Names) != 36 || len(report.Shards) != 32 {
		t.Fatalf("partial plan lost full inventory/identity: %s (%v)", data, err)
	}
	for index, shard := range report.Shards {
		if shard.Index != index {
			t.Fatalf("global shard index was renumbered: %+v", shard)
		}
		if index%8 == 0 {
			if shard.Status != "passed" || len(shard.Outcomes) == 0 || len(shard.Command) == 0 {
				t.Fatalf("assigned shard was not executed: %+v", shard)
			}
		} else if shard.Status != "not_owned" || len(shard.Outcomes) != 0 || len(shard.Command) != 0 {
			t.Fatalf("foreign shard gained execution or pass: %+v", shard)
		}
	}
	if _, err := os.Lstat(filepath.Join(out, "package-0000", "report.json")); !os.IsNotExist(err) {
		t.Fatalf("partial execution masquerades as schema-1 complete suite: %v", err)
	}
}
