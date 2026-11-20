package main

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestRunPatternCompactsExactInventory(t *testing.T) {
	prefix := "TestGoAMD64FixedLocal" + strings.Repeat("CompleteOriginalSource", 3)
	names := []string{prefix, "Example", "FuzzSeeds", "TestUnicode_世界", "TestUnicode_世代"}
	for index := 0; index < 240; index++ {
		names = append(names, fmt.Sprintf("%sFamily%03d", prefix, index))
	}
	if len(strings.Join(names, "|")) <= 16000 {
		t.Fatal("fixture no longer reproduces the CI argument bound")
	}
	original := append([]string(nil), names...)
	pattern, err := runPattern(names)
	if err != nil || len(pattern) > 16000 {
		t.Fatalf("complete exact inventory did not fit without changing shards: %d bytes, %v", len(pattern), err)
	}
	if !reflect.DeepEqual(names, original) {
		t.Fatal("pattern construction changed the ordered inventory")
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool, len(names))
	for _, name := range names {
		want[name] = true
	}
	// Test every retained root and anchored truncation/extension mutations.
	// A shorter root may itself be selected; membership decides the oracle.
	for _, name := range names {
		for _, candidate := range []string{name, name + "Missing", "Extra" + name, name + "\n", name[:len(name)-1]} {
			if got := matcher.MatchString(candidate); got != want[candidate] {
				t.Fatalf("selector membership for %q: got %v, want %v", candidate, got, want[candidate])
			}
		}
	}
	for _, absent := range []string{"", prefix + "Family240", prefix + "Family999", "TestUnicode_世", "TestUnicode_世界代"} {
		if matcher.MatchString(absent) {
			t.Fatalf("factoring invented a root: %q", absent)
		}
	}
	for left, right := 0, len(names)-1; left < right; left, right = left+1, right-1 {
		names[left], names[right] = names[right], names[left]
	}
	reversed, err := runPattern(names)
	if err != nil || reversed != pattern {
		t.Fatal("oversized inventory factoring is not deterministic", err)
	}
}

func TestRunPatternRetainsSmallSelectorsAndArgumentLimit(t *testing.T) {
	pattern, err := runPattern([]string{"TestB", "TestA", "Example"})
	if err != nil || pattern != "^(TestB|TestA|Example)$" {
		t.Fatal("ordinary selector changed", pattern, err)
	}
	for _, names := range [][]string{nil, {"Test" + strings.Repeat("A", 16001)}} {
		if pattern, err := runPattern(names); err == nil || pattern != "" {
			t.Fatal("empty or irreducibly oversized selector was admitted", len(pattern), err)
		}
	}
}
