//go:build amd64

package amd64conformance

import "testing"

func x87OracleFixed8() uint64
func x87OracleFixed9() uint64
func x87OracleDynBranch78(x uint64) uint64
func x87OracleDynBranch78Swapped(x uint64) uint64

// TestAMD64X87StackOverflowNativeOracle records real amd64 hardware execution
// for the Round 14 P1 x87 stack-overflow cases:
//   - fixed 8 pushes -> 0x00
//   - fixed 9 pushes -> 0x41 (SF|IE)
//   - dynamic branch 7/8 + 1 (x != 0 pushes 8th) -> x=0: 0x00, x=1: 0x41
//   - swapped dynamic branch 7/8 + 1 (x == 0 pushes 8th) -> x=0: 0x41, x=1: 0x00
func TestAMD64X87StackOverflowNativeOracle(t *testing.T) {
	if got := x87OracleFixed8(); got != 0x00 {
		t.Fatalf("x87OracleFixed8() = %#x, want 0x0", got)
	}
	if got := x87OracleFixed9(); got != 0x41 {
		t.Fatalf("x87OracleFixed9() = %#x, want 0x41 (SF|IE)", got)
	}
	if got := x87OracleDynBranch78(0); got != 0x00 {
		t.Fatalf("x87OracleDynBranch78(0) = %#x, want 0x0", got)
	}
	if got := x87OracleDynBranch78(1); got != 0x41 {
		t.Fatalf("x87OracleDynBranch78(1) = %#x, want 0x41 (SF|IE)", got)
	}
	if got := x87OracleDynBranch78Swapped(0); got != 0x41 {
		t.Fatalf("x87OracleDynBranch78Swapped(0) = %#x, want 0x41 (SF|IE)", got)
	}
	if got := x87OracleDynBranch78Swapped(1); got != 0x00 {
		t.Fatalf("x87OracleDynBranch78Swapped(1) = %#x, want 0x0", got)
	}
}
