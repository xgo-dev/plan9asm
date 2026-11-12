package plan9asm

import (
	"go/ast"
	"os"
	"strings"
	"testing"
)

var x86PackedMoveRuntimeRows = []struct {
	op   string
	bits int
}{
	{"VMOVAPS", 32}, {"VMOVAPD", 64}, {"VMOVUPS", 32}, {"VMOVUPD", 64},
	{"VMOVDQA32", 32}, {"VMOVDQA64", 64}, {"VMOVDQU8", 8}, {"VMOVDQU16", 16}, {"VMOVDQU32", 32}, {"VMOVDQU64", 64},
}

// Test-only ISA partition. An aligned register copy stays portable; only its
// original physical memory instruction requires the native counterpart.
func x86PackedMoveRuntimeNativeRow(op string, memory bool) bool {
	if !memory {
		return false
	}
	switch op {
	case "VMOVDQA", "VMOVAPS", "VMOVAPD", "VMOVDQA32", "VMOVDQA64":
		return true
	}
	return false
}

func TestX86PackedMoveRuntimePartitionIsComplete(t *testing.T) {
	frameFunctions := fixedLocalLeaseFunctions(t, "amd64_lower_packed_move_frame_test.go")
	for name, execute := range map[string]string{
		"TestX86PackedMoveFrameSlotsObjects": "false", "TestX86PackedMoveFrameSlotsRuntime": "true",
	} {
		function := frameFunctions[name]
		if function == nil || fixedLocalLeaseCalls(function.Body)["x86PackedMoveFrameSlots"] != 1 {
			t.Fatal("missing original frame objects or native runtime owner", name)
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && fixedLocalLeaseCallName(call) == "x86PackedMoveFrameSlots" {
				if len(call.Args) != 2 || !fixedLocalLeaseIdent(call.Args[1], execute) {
					t.Error("frame object compilation changed its role or weakened native execution", name)
				}
			}
			return true
		})
	}
	// These are the exact historical rows, independent of the implementation
	// registry. Every old row must have one owner, never an execution skip.
	oldRows := map[string]int{"VMOVAPS": 32, "VMOVAPD": 64, "VMOVUPS": 32, "VMOVUPD": 64, "VMOVDQA32": 32, "VMOVDQA64": 64, "VMOVDQU8": 8, "VMOVDQU16": 16, "VMOVDQU32": 32, "VMOVDQU64": 64}
	var masked, views, frame [2]int
	seen := make(map[string]bool)
	for _, row := range x86PackedMoveRuntimeRows {
		name := row.op
		if seen[name] || oldRows[name] != row.bits {
			t.Fatal("unknown or duplicate historical runtime row", row)
		}
		seen[name] = true
		aligned := name == "VMOVAPS" || name == "VMOVAPD" || name == "VMOVDQA32" || name == "VMOVDQA64"
		if aligned {
			frame[1]++ // Actual-Go accepted; virtual FP must report Context.
		} else {
			frame[0]++ // Numeric portable FP oracle.
		}
		for width := 0; width < 3; width++ {
			owner := 0
			if x86PackedMoveRuntimeNativeRow(name, true) {
				owner = 1
			}
			if (owner == 1) != aligned {
				t.Fatal("incorrect historical masked-memory owner", name, width)
			}
			masked[owner]++
			for form := 0; form < 6; form++ {
				owner = 0
				if x86PackedMoveRuntimeNativeRow(name, form < 3) {
					owner = 1
				}
				if (owner == 1) != (aligned && form < 3) {
					t.Fatal("incorrect historical view owner", name, width, form)
				}
				views[owner]++
			}
		}
	}
	if len(seen) != len(oldRows) || masked != [2]int{18, 12} || views != [2]int{144, 36} || frame != [2]int{6, 4} {
		t.Fatal("lost old rows", masked, views, frame)
	}
	for file, roots := range map[string][]string{
		"amd64_lower_packed_move_memory_test.go": {"TestX86PackedMoveMaskedMemoryRuntime", "TestX86PackedMoveRegisterViewsRuntime"},
		"amd64_packed_vector_move_aligned_runtime_linux_amd64_test.go": {
			"TestCrossLinuxRuntimeMatrixX86PackedMoveAlignedMaskedMemory", "TestCrossLinuxRuntimeMatrixX86PackedMoveAlignedRegisterViews", "TestCrossLinuxRuntimeMatrixX86PackedMoveAlignedOriginalGo"},
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "t.Skip") {
			t.Fatal("runtime partition silently skips rows", file)
		}
		for _, root := range roots {
			if !strings.Contains(string(source), "func "+root+"(t *testing.T)") {
				t.Fatal("missing required runtime counterpart", root)
			}
		}
	}
	t.Log("historical memory rows: portable=18 native=12; alias rows: portable=144 native=36; FP rows: portable=6 explicit Context=4; all native roots are required cross-runtime tests")
}
