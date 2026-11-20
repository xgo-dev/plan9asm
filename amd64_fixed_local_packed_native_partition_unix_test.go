//go:build unix

package plan9asm

import (
	"go/ast"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

func TestFixedLocalPackedNativeBatchSelectionPreservesCompleteSourceUnion(t *testing.T) {
	helper := fixedLocalLeaseFunctions(t, "amd64_fixed_local_packed_runtime_test.go")["fixedLocalPackedRuntimeAPIs"]
	if helper == nil {
		t.Fatal("missing complete packed source consumer")
	}
	var selection, original token.Pos
	consumesSelected := false
	ast.Inspect(helper.Body, func(node ast.Node) bool {
		if loop, ok := node.(*ast.RangeStmt); ok {
			if indices, ok := loop.X.(*ast.Ident); ok && indices.Name == "indices" {
				consumesSelected = true
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fixedLocalLeaseCallName(call) {
		case "fixedLocalPackedBatchSelection":
			selection = call.Pos()
		case "fixedLocalPackedRunOriginal":
			original = call.Pos()
			fixedLocalLeaseRequireArguments(t, call, "t", "execution", "assembly", "declarations", "goOracle", "execute")
		}
		return true
	})
	if selection == 0 || original <= selection || !consumesSelected {
		t.Fatal("invalid ownership must fail before running the unchanged whole original, and only selected complete batches may execute")
	}
	for _, all := range []bool{false, true} {
		batches := fixedLocalPackedLeaseBatches(t, all, "x86_64-unknown-linux-gnu")
		indices, err := fixedLocalPackedBatchSelection(len(batches))
		if err != nil || len(indices) != len(batches) {
			t.Fatal("default compile-only/SSE source selection changed", err)
		}
		var assembly, declarations, rows, prototypes strings.Builder
		for index, batch := range batches {
			selected, err := fixedLocalPackedBatchSelection(len(batches), index)
			if err != nil || !reflect.DeepEqual(selected, []int{index}) || indices[index] != index {
				t.Fatal("one required owner must retain exactly its complete original source batch", index, selected, err)
			}
			assembly.WriteString(batch.assembly)
			declarations.WriteString(batch.declarations)
			rows.WriteString(batch.rows)
			prototypes.WriteString(batch.prototypes)
		}
		original, decls, cases := fixedLocalPackedRuntimeProgram(all)
		_, oracle := fixedLocalPackedRuntimeOracles(cases, "x86_64-unknown-linux-gnu")
		if assembly.String() != original || declarations.String() != decls ||
			!strings.Contains(oracle, rows.String()) || !strings.Contains(oracle, prototypes.String()) {
			t.Fatal("independent source owners cropped, renamed or duplicated the original whole program")
		}
	}
}

func TestFixedLocalPackedNativeBatchSelectionRejectsInvalidOwners(t *testing.T) {
	for _, selected := range [][]int{{-1}, {6}, {0, 0}, {0, 1}, {5, 4}} {
		if _, err := fixedLocalPackedBatchSelection(6, selected...); err == nil {
			t.Error("invalid or repeated source selection became an executable owner", selected)
		}
	}
	for _, total := range []int{-1, 0} {
		if _, err := fixedLocalPackedBatchSelection(total); err == nil {
			t.Error("empty source inventory became a successful owner", total)
		}
	}
}
