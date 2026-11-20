package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixSchedulingRetainsTwoWholeShardsPerOwner(t *testing.T) {
	parts, err := moduleRootShardParts(32, 16)
	if err != nil || len(parts) != 16 {
		t.Fatal("complete test/coverage root scheduling layout", parts, err)
	}
	seen := make([]int, 32)
	for owner, shards := range parts {
		if len(shards) != 2 || shards[0] != owner || shards[1] != owner+16 {
			t.Fatal("test/coverage must fit one two-worker wave", owner, shards)
		}
		for _, shard := range shards {
			seen[shard]++
		}
	}
	for shard, count := range seen {
		if count != 1 {
			t.Fatal("missing or duplicate complete test/coverage shard", shard, count)
		}
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "test-module-ci.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"root_partitions=16\n", "shards=32\n", "test) timeout=45m ;;",
		"coverage) timeout=45m; flags=(-coverprofile=coverage-root.out) ;;",
		"race) timeout=60m; flags=(-race); root_partitions=32; shards=64 ;;",
		"-shards=$shards -workers=2", "-timeout=$timeout", "GOMAXPROCS=2",
		"-module-root-partitions=$root_partitions", "-module-root-partition=$4",
	} {
		if !strings.Contains(string(source), required) {
			t.Error("execution and completion must retain the exact exhaustive scheduling/resource contract:", required)
		}
	}
}
