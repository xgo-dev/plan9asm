package plan9asm

import "fmt"

// A non-temporal hint does not make the instruction's native access optional.
// Reuse the aligned packed-move emitter, including original faults, exact
// width, segment address spaces and encoding-aware register writeback.
func (c *amd64Ctx) lowerNonTemporalVectorMove(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86NonTemporalVectorProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: non-temporal vector access needs its actual x86 target", ErrProbeNeedsContext)
	}
	if form.trap {
		return c.lowerSyscall("UD2", Instr{Op: "UD2"})
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		(ins.x86Encoded || ins.x86SourceRaw != nil) && ins.x86NumericalRead == nil && ins.x86SDKLiteral == nil {
		return true, false, fmt.Errorf("%w: non-temporal vector access needs its actual x86 target/encoding", ErrProbeNeedsContext)
	}
	if !form.move.ordinaryMemory(ins, c.goarch) &&
		!x86CallerMemoryCertified(ins, form.move.memory) && !c.fixedLocalMemoryCertified(ins, form.move.memory) {
		return true, false, fmt.Errorf("%w: non-temporal vector access needs native backing, not logical FP/AUTO bytes", ErrProbeNeedsContext)
	}
	if err := x86Mode32VectorRegisterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	native := ins
	native.Op = Op(form.spec.native) // Local spelling adapter; never mutate original source identity.
	return true, false, c.lowerNativeAlignedVectorMemory(native, form.move, !form.spec.vector)
}
