package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Independent complete source domains, not names copied from the scheduler.
// Runtime, source-observation, API and object checks remain in their owners.
func heavyObjectSourceFamilies(t *testing.T) map[string]string {
	t.Helper()
	want := make(map[string]string)
	for _, family := range []struct {
		file, prefix string
		targets      []string
		batches      int
	}{
		{"amd64_fixed_local_conversion_test.go", "TestGoAMD64FixedLocalConversionActualObjects", []string{"Linux", "Darwin", "Windows"}, 12},
		{"amd64_fixed_local_packed_matrix_test.go", "TestGoAMD64FixedLocalPackedCompleteFormsActualObjects", []string{"Linux", "Darwin", "Windows"}, 4},
		{"amd64_cmov_fixed_local_test.go", "TestX86CMOVFamilyFixedLocalAUTOActualObjects", []string{"Linux", "Darwin"}, 6},
		{"amd64_fixed_local_data_matrix_go127_test.go", "TestGoAMD64FixedLocalReadonlyData", []string{"Linux", "Darwin", "Windows"}, 0},
		{"amd64_fixed_local_packed_runtime_test.go", "TestGoAMD64FixedLocalPackedWideRuntimeOracle", []string{"", "Module", "GoModule"}, -1},
		{"amd64_fixed_local_packed_native_linux_amd64_test.go", "TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWide", []string{""}, 6},
		{"amd64_fixed_local_conversion_runtime_linux_amd64_test.go", "TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNative", []string{""}, 7},
	} {
		expected := make(map[string]bool)
		for _, target := range family.targets {
			if family.batches > 0 {
				for batch := 0; batch < family.batches; batch++ {
					expected[fmt.Sprintf("%s%sBatch%02d", family.prefix, target, batch)] = true
				}
			} else {
				suffix := "RegisteredConsumers"
				if family.batches == -1 {
					suffix = "CompileOnly"
				}
				expected[family.prefix+target+suffix] = true
			}
		}
		syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", family.file), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := make(map[string]bool)
		for _, declaration := range syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(function.Name.Name, family.prefix) {
				continue
			}
			name := function.Name.Name
			if family.batches == 0 && !strings.HasSuffix(name, "RegisteredConsumers") {
				continue
			}
			if !expected[name] || found[name] || function.Body == nil {
				t.Fatal("unknown, duplicate or incomplete heavy source owner", family.file, name)
			}
			found[name] = true
			want[name] = family.prefix
		}
		if !reflect.DeepEqual(found, expected) {
			t.Fatal("complete heavy source family changed", family.file, found, expected)
		}
	}
	for _, owner := range []struct{ file, name string }{
		{"go_x86_numerical_read_revocation_final_go127_test.go", "TestGoX86NumericalReadRevokeDuringFinalSDKCallback"},
		{"arm64_gp_immediate_runtime_test.go", "TestARM64GPImmediateScratchCompleteObjects"},
	} {
		syntax, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", owner.file), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, declaration := range syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Name.Name == owner.name && function.Body != nil {
				found++
			}
		}
		if found != 1 {
			t.Fatal("missing complete callback or scratch source owner", owner.file, owner.name, found)
		}
		want[owner.name] = owner.name
	}
	if len(want) != 81 {
		t.Fatal("complete independent heavy object denominator changed", len(want))
	}
	return want
}

func heavyObjectNames(families map[string]string) []string {
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func independentHashShard(name string, count int) int {
	hash := sha256.Sum256([]byte(name))
	return int(binary.BigEndian.Uint64(hash[:8]) % uint64(count))
}

func heavyObjectOwners(t *testing.T, names []string, count int) ([][]string, map[string]int) {
	t.Helper()
	shards, err := partitionForFlags(names, count, []string{"-race"})
	if err != nil {
		t.Fatal(err)
	}
	owners := make(map[string]int)
	for index, shard := range shards {
		if !sort.StringsAreSorted(shard) {
			t.Fatal("noncanonical shard order", index)
		}
		for _, name := range shard {
			if _, exists := owners[name]; exists {
				t.Fatal("duplicate complete root owner", name)
			}
			owners[name] = index
		}
	}
	if len(owners) != len(names) {
		t.Fatal("scheduler reduced the complete inventory", count, len(owners), len(names))
	}
	for _, name := range names {
		if _, found := owners[name]; !found {
			t.Fatal("missing complete root", name)
		}
	}
	return shards, owners
}

func TestHeavyObjectSchedulingIndependentClosedSourceFamilies(t *testing.T) {
	heavyObjectSourceFamilies(t)
}

func TestHeavyObjectSchedulingPreventsCrossFamilyBudgetCollision(t *testing.T) {
	families := heavyObjectSourceFamilies(t)
	names := heavyObjectNames(families)
	// The first CI failure completed these four independent owners in 2725.57
	// seconds before exhausting the unchanged 3600-second whole-shard limit.
	// Its reported missing packed-shift root had never started.
	for _, name := range []string{
		"TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch01",
		"TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch00",
		"TestGoAMD64FixedLocalConversionActualObjectsDarwinBatch09",
		"TestGoAMD64FixedLocalReadonlyDataLinuxRegisteredConsumers",
	} {
		if _, found := families[name]; !found || independentHashShard(name, 32) != 5 {
			t.Fatal("independent original hash-collision witness changed", name)
		}
	}
	for _, count := range []int{32, 64} {
		shards, _ := heavyObjectOwners(t, names, count)
		for index, roots := range shards {
			conversion, readonly := 0, 0
			for _, name := range roots {
				if strings.HasPrefix(name, "TestGoAMD64FixedLocalConversionActualObjects") {
					conversion++
				}
				if strings.HasPrefix(name, "TestGoAMD64FixedLocalReadonlyData") {
					readonly++
				}
			}
			if readonly > 0 && conversion > 1 {
				t.Errorf("layout %d shard %d collocates complete readonly and repeated conversions: %v", count, index, roots)
			}
			if len(roots) > (len(names)+count-1)/count {
				t.Errorf("layout %d shard %d accumulates heavy source families: %v", count, index, roots)
			}
		}
	}
}

func TestHeavyObjectSchedulingStableCompleteLayouts(t *testing.T) {
	names := heavyObjectNames(heavyObjectSourceFamilies(t))
	for count := 1; count <= 1024; count++ {
		shards, owners := heavyObjectOwners(t, names, count)
		for index, shard := range shards {
			if len(shard) < len(names)/count || len(shard) > (len(names)+count-1)/count {
				t.Fatalf("complete heavy family imbalance: layout=%d shard=%d count=%d", count, index, len(shard))
			}
		}
		reversed := append([]string(nil), names...)
		for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
			reversed[left], reversed[right] = reversed[right], reversed[left]
		}
		_, reordered := heavyObjectOwners(t, reversed, count)
		if !reflect.DeepEqual(owners, reordered) {
			t.Fatal("heavy ownership depends on input order", count)
		}
		extended := append(append([]string(nil), names...), "TestOrdinaryInsertedBefore", "ExampleOrdinary", "FuzzOrdinary")
		_, extendedOwners := heavyObjectOwners(t, extended, count)
		for _, name := range names {
			_, single := heavyObjectOwners(t, []string{name}, count)
			if owners[name] != extendedOwners[name] || owners[name] != single[name] {
				t.Fatal("heavy ownership depends on unrelated roots or a filtered inventory", count, name)
			}
		}
		for _, name := range extended[len(names):] {
			if extendedOwners[name] != independentHashShard(name, count) {
				t.Fatal("ordinary root lost its original hash role", count, name)
			}
		}
	}
}

func TestHeavyObjectSchedulingOrdinaryNeighborNamesKeepHashOwnership(t *testing.T) {
	for _, count := range []int{1, 7, 32, 64, 1024} {
		for _, name := range []string{
			"TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch12",
			"TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch000",
			"TestX86CMOVFamilyFixedLocalAUTOActualObjectsWindowsBatch00",
			"TestGoAMD64FixedLocalReadonlyDataLinuxRegisteredConsumersExtra",
			"TestGoAMD64FixedLocalPackedWideRuntimeOracleUnknownCompileOnly",
			"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWide",
			"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch06",
			"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch000",
			"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNativeBatch07",
			"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNativeBatch000",
			"TestGoX86NumericalReadRevokeDuringFinalSDKCallbackExtra",
			"TestARM64GPImmediateScratchCompleteObjectsExtra",
		} {
			_, owners := heavyObjectOwners(t, []string{name}, count)
			if owners[name] != independentHashShard(name, count) {
				t.Fatal("a neighboring spelling borrowed another complete family's scheduling role", count, name)
			}
		}
	}
}
