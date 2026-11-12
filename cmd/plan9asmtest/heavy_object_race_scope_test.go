package main

import (
	"reflect"
	"testing"
)

func TestHeavyObjectSchedulingInstrumentationIndependent(t *testing.T) {
	names := heavyObjectNames(heavyObjectSourceFamilies(t))
	names = append(names, "TestOrdinaryBefore", "TestOrdinaryAfter")
	for count := 1; count <= 1024; count++ {
		plain, err := partition(names, count)
		if err != nil {
			t.Fatal(err)
		}
		for index, shard := range plain {
			for _, name := range shard {
				if (name == "TestOrdinaryBefore" || name == "TestOrdinaryAfter") && index != independentHashShard(name, count) {
					t.Fatalf("default layout changed ordinary hash: shards=%d root=%s", count, name)
				}
			}
		}
		for _, flags := range [][]string{
			nil,
			{"-cover", "-covermode=atomic"},
			{"-tags=byollvm", "-p=2"}, // Existing Windows build context.
			{"-race=false"},
			{"-race", "-race=false"},
			{"-race=true", "-race=false"},
			{"-race"},
			{"-race=false", "-race=true"},
			{"-tags", "-race"},
			{"-gcflags", "-race"},
			{"-ldflags=-race"},
		} {
			actual, err := partitionForFlags(names, count, flags)
			if err != nil || !reflect.DeepEqual(actual, plain) {
				t.Fatalf("instrumentation flags changed complete ownership: shards=%d flags=%v err=%v", count, flags, err)
			}
		}
	}
}

func TestHeavyObjectRaceScopeExplicitFlagsKeepCompleteBalancedOwners(t *testing.T) {
	names := heavyObjectNames(heavyObjectSourceFamilies(t))
	for count := 1; count <= 1024; count++ {
		var first [][]string
		for _, flags := range [][]string{
			{"-race"},
			{"-race=true"},
			{"-race=false", "-race"},
			{"-race=false", "-race=true"},
			{"-tags", "-race=false", "-race", "-covermode=atomic"},
		} {
			actual, err := partitionForFlags(names, count, flags)
			if err != nil {
				t.Fatal(err)
			}
			if first == nil {
				first = actual
			} else if !reflect.DeepEqual(actual, first) {
				t.Fatalf("equivalent effective race flags changed ownership: %d %v", count, flags)
			}
			seen := make(map[string]bool)
			for _, shard := range actual {
				if len(shard) < len(names)/count || len(shard) > (len(names)+count-1)/count {
					t.Fatalf("complete race family is not balanced: %d %v", count, flags)
				}
				for _, name := range shard {
					if seen[name] {
						t.Fatal("duplicate race object owner", name)
					}
					seen[name] = true
				}
			}
			if len(seen) != len(names) {
				t.Fatal("race layout lost complete roots", count)
			}
		}
	}
}

func TestHeavyObjectRaceScopeRejectsUnvalidatedSelectors(t *testing.T) {
	names := heavyObjectNames(heavyObjectSourceFamilies(t))
	for _, flags := range [][]string{
		{"-race=TRUE"}, {"-race=1"}, {"-race="}, {"--race"},
		{"-run=TestOne"}, {"-tags"}, {"-unknown=-race"},
	} {
		if _, err := partitionForFlags(names, 64, flags); err == nil {
			t.Fatal("invalid/unrecordable selector reached scheduling", flags)
		}
	}
}
