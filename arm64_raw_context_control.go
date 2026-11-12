package plan9asm

import "reflect"

// The coarse general CFG intentionally merges helper inputs. For a checked
// raw zero-frame source, that can mix incoming pointers with disjoint private
// scratch. Reuse the independent call-context interpreter instead of granting
// alias permission to its mixed store. Nothing is published from a failed or
// partial proof, and ordinary/raw-native functions retain the coarse path.
func (c *arm64Ctx) rawZeroContextControlPlan(outer string) *arm64LocalControlPlan {
	if !c.unexposedCallFrame || c.sourceGoFrame.present ||
		!arm64CallFrameFreshEntry(c.sig) || c.sig.ARM64ClosureABI != nil {
		return nil
	}
	if c.sig.ARM64GoRegisterABI != nil && arm64ValidateGoRegisterABI(c.sig) != nil {
		return nil
	}
	if !reflect.DeepEqual(c.blocks, arm64SplitBlocks(c.normalizedSource)) {
		return nil
	}
	plan := &arm64LocalControlPlan{
		before:      make(map[[2]int]arm64ControlValue),
		stackBefore: make(map[[2]int]arm64ControlValue),
		linkBefore:  make(map[[2]int]arm64ControlValue),
		reachable:   make([]bool, len(c.blocks)),
		outer:       outer,
	}
	transport := &arm64PrivateFrameTransport{entry: c.sig, resolve: c.resolve, sigs: c.sigs}
	if !arm64RawZeroFrameProof(c.normalizedSource, transport, plan) {
		return nil
	}
	return plan
}

func (plan *arm64LocalControlPlan) recordRawZeroReturn(block, instruction int, state *arm64ControlState, entryLink string) {
	point := [2]int{block, instruction}
	link := arm64ControlFromMap(make(map[string]bool))
	for _, token := range arm64ControlKeys(arm64ControlRead(state.regs, "R30")) {
		if token == entryLink {
			token = "label:" + plan.outer
		}
		link = arm64ControlSetToken(link, token, true)
	}
	plan.before[point] = arm64ControlUnion(plan.before[point], link)
	plan.linkBefore[point] = arm64ControlUnion(plan.linkBefore[point], link)
	plan.stackBefore[point] = arm64ControlUnion(plan.stackBefore[point], arm64ControlRead(state.regs, SP))
}
