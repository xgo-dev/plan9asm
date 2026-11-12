package main

import (
	"reflect"
	"testing"
)

func TestModuleRootShardPartsAreExhaustiveAndDisjoint(t *testing.T) {
	for _, shards := range []int{32, 64} {
		counts := []int{1, 3, 8, 16, 32}
		if shards == 64 {
			counts = append(counts, 64)
		}
		for _, count := range counts {
			parts, err := moduleRootShardParts(shards, count)
			if err != nil || len(parts) != count {
				t.Fatalf("%d/%d plan: %v %v", shards, count, parts, err)
			}
			seen := make([]int, shards)
			for part, indices := range parts {
				if len(indices) == 0 {
					t.Fatalf("part %d has no global shard indices", part)
				}
				for _, index := range indices {
					if index < 0 || index >= shards || index%count != part {
						t.Fatalf("part %d obtained foreign shard %d", part, index)
					}
					seen[index]++
				}
			}
			for index, owners := range seen {
				if owners != 1 {
					t.Fatalf("shard %d has %d owners", index, owners)
				}
			}
			if shards == 32 && count == 8 && !reflect.DeepEqual(parts[0], []int{0, 8, 16, 24}) {
				t.Fatalf("CI root part zero changed original shard indices: %v", parts[0])
			}
			if count == 16 {
				want := []int{1, 17}
				if shards == 64 {
					want = append(want, 33, 49)
				}
				if !reflect.DeepEqual(parts[1], want) {
					t.Fatalf("root part changed its complete shard ownership: %v", parts[1])
				}
			}
		}
	}
	for _, invalid := range [][2]int{{0, 1}, {1025, 1}, {32, 0}, {32, -1}, {32, 33}} {
		if _, err := moduleRootShardParts(invalid[0], invalid[1]); err == nil {
			t.Fatalf("invalid scheduling accepted: %v", invalid)
		}
	}
}

func TestModuleRootSchedulingRolesStaySeparate(t *testing.T) {
	base := config{Package: ".", Module: true, ModuleOwner: 0, CIOwner: -1,
		Shards: 32, ModuleRootPartitions: 8, ModuleRootPartition: 0}
	for _, owner := range []int{0, 1, 2, -1} {
		cfg := base
		cfg.ModuleOwner = owner
		if owner != 0 {
			cfg.ModuleRootPartition = -1
		}
		if owner == -1 {
			cfg.ModuleVerify = "original-artifacts"
		}
		if err := validateModuleRootScheduling(cfg); err != nil {
			t.Fatalf("registered module role %d: %v", owner, err)
		}
	}
	for part := 0; part < 8; part++ {
		cfg := base
		cfg.ModuleRootPartition = part
		if err := validateModuleRootScheduling(cfg); err != nil {
			t.Fatalf("root part %d: %v", part, err)
		}
	}
	for _, change := range []func(*config){
		func(c *config) { c.Module = false },
		func(c *config) { c.Package = "foreign/package" },
		func(c *config) { c.ModuleOwner = 1 },
		func(c *config) { c.ModuleOwner = 2 },
		func(c *config) { c.ModuleOwner = -1 },
		func(c *config) { c.ModuleOwner = 3 },
		func(c *config) { c.ModuleRootPartitions = 0 },
		func(c *config) { c.ModuleRootPartitions = 33 },
		func(c *config) { c.ModuleRootPartition = -1 },
		func(c *config) { c.ModuleRootPartition = 8 },
		func(c *config) { c.ModuleVerify = "artifacts" },
		func(c *config) { c.CISelector = "^TestNative$" },
		func(c *config) { c.CIIsolate = "TestNative" },
		func(c *config) { c.CIVerify = "native-artifacts" },
		func(c *config) { c.CIOwner = 0 },
	} {
		cfg := base
		change(&cfg)
		if err := validateModuleRootScheduling(cfg); err == nil {
			t.Fatalf("unregistered/mixed partial role accepted: %+v", cfg)
		}
	}
	legacy := base
	legacy.ModuleRootPartitions, legacy.ModuleRootPartition = 1, -1
	legacy.Module, legacy.ModuleOwner = false, -1
	if err := validateModuleRootScheduling(legacy); err != nil {
		t.Fatalf("default ordinary role changed: %v", err)
	}
}
