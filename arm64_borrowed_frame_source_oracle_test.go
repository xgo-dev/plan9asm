package plan9asm

import "testing"

// This is the original borrowed-frame source, not a translated C tail call.
// Its helper consumes the outgoing slots correctly but has no source-level
// epilogue for the caller's 48-byte Go frame. Restore real SP/LR/FP in the
// NOFRAME observation trampoline so the native witness safely returns to Go.
func TestCrossLinuxRuntimeMatrixARM64BorrowedFrameSourceSPOracle(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	const trampoline = `TEXT ·Measure(SB),516,$0-16
MOVD out+0(FP),R0
MOVD RSP,R19
MOVD R30,R23
MOVD R29,R24
SUB $16,RSP
MOVD R0,8(RSP)
CALL caller(SB)
SUB R19,RSP,R0
ADD $16,R0
MOVD R19,RSP
MOVD R24,R29
MOVD R23,R30
MOVD R0,ret+8(FP)
RET
`
	runARM64LocalRegisterGoOracle(t, trampoline+arm64BorrowedTailOriginalSource, `package main
func Measure(*uint64) int64
func main() {
  for _,initial:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    out:=initial
    if delta:=Measure(&out); delta!=-48 { panic(delta) }
    if out!=7 { panic("original borrowed argument slots changed") }
  }
}
`, len(runner) != 0)
	t.Log("native Go original borrowed helper writes 7 but returns with SP delta -48; trampoline restores actual caller SP/LR/FP")
}
