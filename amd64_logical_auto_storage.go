package plan9asm

import "fmt"

// Ordinary logical AUTO bytes use immutable entry SP plus the frame extent,
// not addresses below the mutable physical/private SP. Private PUSH storage
// must not overwrite them. This consumes an existing complete source proof;
// independently bound native/caller storage keeps its own address projection.
func (c *amd64Ctx) prepareLogicalAUTOStorage() error {
	fn := c.fpScalarSource
	if !c.fpScalarChecked || c.fpScalarCheckErr != nil || c.sourceStack != nil || c.fixedLocal != nil ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil ||
		fn.x86ContinuationFlow != nil || fn.x86BoolCalls != nil {
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
	c.privateFlagsStack = stack != nil
	extent, err := x86ResultAUTOExtentWithPrivateStack(fn, c.goarch, c.privateFlagsStack)
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
	if c.logicalAUTOExtent == 0 || mem.Base != SP {
		return "", false, nil
	}
	if c.privateFlagsStack && mem.Off >= 0 && mem.Sym == "" && mem.OffRaw == "" &&
		mem.Index == "" && mem.IndexExt == "" && mem.Segment == "" && mem.Scale == 0 {
		return "", false, nil // Reaching PUSH depth, rather than the immutable AUTO base, owns this access.
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
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", address, c.logicalAUTOBase, offset)
	return "%" + address, true, nil
}
