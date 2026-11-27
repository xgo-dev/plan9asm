//go:build amd64

package amd64conformance

import "testing"

func x87OracleFixed8() uint64
func x87OracleFixed9() uint64
func x87OracleDynBranch78(x uint64) uint64
func x87OracleDynBranch78Swapped(x uint64) uint64
func x87OracleInlineFinit() uint64
func x87OracleCallReset() uint64
func x87OracleCallNop() uint64
func x87OracleCallResetEmptyTop() uint64
func x87OracleCallNopEmptyTop() uint64

// TestAMD64X87StackOverflowNativeOracle records real amd64 hardware execution
// for:
//   - Round 14 P1 x87 stack-overflow cases: fixed-8 (0x0), fixed-9 (0x41),
//     dynamic 7/8+1 in both branch polarities (0x0 / 0x41);
//   - Round 16 P1 cross-CALL x87 TOP divergence: CALL reset and inline FINIT
//     both produce M7=0x8000000000000000 (empty-stack TOP=0x3800), whereas
//     CALL nop preserves TOP=7 and produces M7=123 (empty-stack TOP=0x3000).
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
	if got := x87OracleInlineFinit(); got != 0x8000000000000000 {
		t.Fatalf("x87OracleInlineFinit() = %#x, want 0x8000000000000000", got)
	}
	if got := x87OracleCallReset(); got != 0x8000000000000000 {
		t.Fatalf("x87OracleCallReset() = %#x, want 0x8000000000000000", got)
	}
	if got := x87OracleCallNop(); got != 123 {
		t.Fatalf("x87OracleCallNop() = %#x, want 123", got)
	}
	if got := x87OracleCallResetEmptyTop(); got != 0x3800 {
		t.Fatalf("x87OracleCallResetEmptyTop() = %#x, want 0x3800", got)
	}
	if got := x87OracleCallNopEmptyTop(); got != 0x3000 {
		t.Fatalf("x87OracleCallNopEmptyTop() = %#x, want 0x3000", got)
	}
}
