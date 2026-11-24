package plan9asm

import "fmt"

// Logical AUTO bytes are relative to the immutable frame. A relative stack
// plan projects its dynamic bytes and fixed AUTO bytes into one object.
// Independently bound native/caller storage has its own address projection.
func (c *amd64Ctx) prepareLogicalAUTOStorage() error {
	fn := c.fpScalarSource
	if !c.fpScalarChecked || c.fpScalarCheckErr != nil || c.sourceStack != nil || c.fixedLocal != nil ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil ||
		fn.x86ContinuationFlow != nil || fn.x86BoolCalls != nil {
		return nil
	}
	if c.relativeStack != nil && c.relativeStack.extent != 0 {
		c.logicalAUTOExtent = c.relativeStack.extent
		return nil
	}
	if c.relativeStack == nil && x86Mode32FixedFrameCandidate(fn, c.goarch) {
		// The paired transfer mapped named AUTO and physical addresses into
		// the same frame. Preserve that projection in the emitter.
		if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
			return fmt.Errorf("%w: 386 fixed TEXT frame requires a matching pointer width", ErrProbeNeedsContext)
		}
		c.logicalAUTOExtent = int(fn.FrameSize)
		c.physicalSPWithAUTO = true
		return nil
	}
	if _, scopedControl := x86X87ScopedControlScratchExtent(fn, c.goarch); scopedControl {
		if c.frameSize != 0 {
			return fmt.Errorf("%w: scoped x87 scratch lost its original zero frame", ErrProbeNeedsContext)
		}
		// Keep actual negative SP offsets in the existing bounded private
		// stack object. Do not manufacture positive logical AUTO storage.
		return nil
	}
	stack, err := x86ResultPrivateFlagsSource(fn, c.goarch)
	if err != nil {
		return err
	}
	c.physicalSPWithAUTO = stack != nil
	extent, err := x86ResultAUTOExtentWithPrivateStack(fn, c.goarch, c.physicalSPWithAUTO)
	if err != nil {
		return err
	}
	if extent != 0 && int64(extent) != c.frameSize {
		return fmt.Errorf("%w: logical AUTO emitter lost its original frame extent", ErrProbeNeedsContext)
	}
	c.logicalAUTOExtent = extent
	return nil
}

func (c *amd64Ctx) logicalAUTOAddress(mem MemRef) (string, bool, error) {
	pointer, logical, err := c.logicalAUTOPointer(mem)
	if !logical || err != nil {
		return "", logical, err
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", address, pointer)
	return "%" + address, true, nil
}

func (c *amd64Ctx) logicalAUTOPointer(mem MemRef) (string, bool, error) {
	if c.logicalAUTOExtent == 0 || mem.Base != SP {
		return "", false, nil
	}
	if c.physicalSPWithAUTO && mem.Off >= 0 && mem.Sym == "" && mem.OffRaw == "" &&
		mem.Index == "" && mem.IndexExt == "" && mem.Segment == "" && mem.Scale == 0 {
		return "", false, nil // The reaching physical stack pointer owns this operand.
	}
	if _, static := x86SBMemoryAddressRole(Operand{Kind: OpMem, Mem: mem}, c.goarch); static {
		return "", false, nil
	}
	offset, valid := x86ResultAUTOOffset(Operand{Kind: OpMem, Mem: mem}, 1, c.logicalAUTOExtent)
	if !valid || c.logicalAUTOBase == "" {
		return "", true, fmt.Errorf("%w: logical AUTO address no longer matches its complete source", ErrProbeNeedsContext)
	}
	if offset == 0 {
		return c.logicalAUTOBase, true, nil
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", pointer, c.logicalAUTOBase, offset)
	return "%" + pointer, true, nil
}
