package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRaceSchedulingRetainsTwoWholeShardsPerOwner(t *testing.T) {
	parts, err := moduleRootShardParts(64, 32)
	if err != nil || len(parts) != 32 {
		t.Fatal("complete race root scheduling layout", parts, err)
	}
	seen := make([]int, 64)
	for owner, shards := range parts {
		if len(shards) != 2 || shards[0] != owner || shards[1] != owner+32 {
			t.Fatal("race scheduling changed its original two-shard resource boundary", owner, shards)
		}
		for _, shard := range shards {
			seen[shard]++
		}
	}
	for shard, count := range seen {
		if count != 1 {
			t.Fatal("missing or duplicate complete race shard", shard, count)
		}
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "scripts", "test-module-ci.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"race) timeout=60m; flags=(-race); root_partitions=32; shards=64 ;;",
		"-shards=$shards -workers=2", "-timeout=$timeout", "GOMAXPROCS=2",
		"-module-root-partitions=$root_partitions", "-module-root-partition=$4",
	} {
		if !strings.Contains(string(source), required) {
			t.Error("actual execution and complete aggregation must retain the race layout/resource contract:", required)
		}
	}
}
