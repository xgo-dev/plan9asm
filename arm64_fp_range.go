package plan9asm

import (
	"fmt"
	"reflect"
)

type arm64FPFramePart struct {
	slot   FrameSlot
	offset int64
	size   int64
}

// fpFrameParts validates an exact byte range before emitting any accesses.
// Frame fields have independent allocas: their ABI offsets describe byte
// adjacency, not the physical adjacency of the LLVM allocations.
func (c *arm64Ctx) fpFrameParts(off, size int64) ([]arm64FPFramePart, error) {
	const maxOffset = int64(1<<63 - 1)
	if off < 0 || size <= 0 || size > 16 || off > maxOffset-size {
		return nil, fmt.Errorf("arm64: invalid FP frame range +%d(FP), size %d", off, size)
	}
	// Generated Go argument/result layouts start at zero and advance by
	// nonnegative field sizes. Reject malformed slot extents before any signed
	// subtraction or end-offset arithmetic can wrap and appear in-range.
	for _, slots := range [][]FrameSlot{c.sig.Frame.Params, c.fpResults} {
		for _, slot := range slots {
			slotSize := frameTypeSize(slot.Type, 8)
			if slot.Offset < 0 || slot.Offset > maxOffset-slotSize {
				return nil, fmt.Errorf("arm64: invalid FP frame slot +%d(FP), size %d", slot.Offset, slotSize)
			}
		}
	}
	var parts []arm64FPFramePart
	for cursor := off; cursor < off+size; {
		var found *FrameSlot
		for _, slots := range [][]FrameSlot{c.sig.Frame.Params, c.fpResults} {
			for _, slot := range slots {
				slotSize := frameTypeSize(slot.Type, 8)
				if cursor < slot.Offset || cursor >= slot.Offset+slotSize {
					continue
				}
				if slotSize > 8 {
					return nil, fmt.Errorf("arm64: FP frame range +%d(FP)..+%d(FP) contains unsupported slot type %q", off, off+size, slot.Type)
				}
				if found != nil {
					return nil, fmt.Errorf("arm64: FP frame range +%d(FP)..+%d(FP) contains overlapping slots at +%d(FP)", off, off+size, cursor)
				}
				candidate := slot
				found = &candidate
			}
		}
		if found == nil {
			return nil, fmt.Errorf("arm64: FP frame range +%d(FP)..+%d(FP) has no slot at +%d(FP)", off, off+size, cursor)
		}
		bytes := frameTypeSize(found.Type, 8) - (cursor - found.Offset)
		if remaining := off + size - cursor; bytes > remaining {
			bytes = remaining
		}
		for _, slots := range [][]FrameSlot{c.sig.Frame.Params, c.fpResults} {
			for _, slot := range slots {
				if slot.Offset > cursor && slot.Offset < cursor+bytes {
					return nil, fmt.Errorf("arm64: FP frame range +%d(FP)..+%d(FP) contains overlapping slots at +%d(FP)", off, off+size, slot.Offset)
				}
			}
		}
		parts = append(parts, arm64FPFramePart{slot: *found, offset: cursor, size: bytes})
		cursor += bytes
	}
	return parts, nil
}

func arm64FPRangeType(size int64) string {
	if size <= 8 {
		return "i64"
	}
	return "i128"
}

// loadFPFrameBits packs scalar fragments in ARM64's little-endian byte order.
// Sub-word and cross-field accesses read only declared frame bytes; padding or
// missing neighboring slots remain errors, unless a complete typed source
// bit-use certificate proves a parameter/result gap cannot be observed.
func (c *arm64Ctx) loadFPFrameBits(off, size int64) (string, error) {
	parts, err := c.fpFrameParts(off, size)
	if err != nil {
		read, certified := c.fpPaddingReads[[2]int{c.currentBlock, c.currentInstruction}]
		decl := c.sig.arm64FPReadDeclaration
		if !certified || !decl.matches(c.sig) || read.offset != off || read.bytes != size ||
			read.declared <= 0 || read.declared >= size || c.currentBlock < 0 || c.currentInstruction < 0 ||
			c.currentBlock >= len(c.blocks) || c.currentInstruction >= len(c.blocks[c.currentBlock].instrs) ||
			!reflect.DeepEqual(read.instruction, c.blocks[c.currentBlock].instrs[c.currentInstruction]) {
			return "", err
		}
		want, candidate := arm64FPPaddingCandidate(c.blocks[c.currentBlock].instrs[c.currentInstruction], decl)
		if !candidate || !reflect.DeepEqual(read, want) {
			return "", err
		}
		// Zero is only an explicit representative of the unobservable bits.
		// The original source still performs its real native-width MOV and
		// implicit scratch effects; no padding slot/address/write is created.
		parts, err = c.fpFrameParts(off, read.declared)
		if err != nil {
			return "", err
		}
	}
	ty := arm64FPRangeType(size)
	packed := "0"
	for _, part := range parts {
		value, err := c.evalFPValue64(Operand{Kind: OpFP, FPOffset: part.slot.Offset})
		if err != nil {
			return "", err
		}
		if shift := (part.offset - part.slot.Offset) * 8; shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shifted, value, shift)
			value = "%" + shifted
		}
		if part.size < 8 {
			masked := c.newTmp()
			mask := ^uint64(0) >> uint(64-part.size*8)
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, value, mask)
			value = "%" + masked
		}
		if ty == "i128" {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", wide, value)
			value = "%" + wide
		}
		if shift := (part.offset - off) * 8; shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", shifted, ty, value, shift)
			value = "%" + shifted
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", merged, ty, packed, value)
		packed = "%" + merged
	}
	return packed, nil
}

// storeFPFrameBits preserves every scalar bit outside the exact write span,
// including writes beginning in the upper word or spanning separate allocas.
func (c *arm64Ctx) storeFPFrameBits(off, size int64, value string) error {
	parts, err := c.fpFrameParts(off, size)
	if err != nil {
		return err
	}
	ty := arm64FPRangeType(size)
	for _, part := range parts {
		fragment := value
		if shift := (part.offset - off) * 8; shift != 0 {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", shifted, ty, fragment, shift)
			fragment = "%" + shifted
		}
		if ty == "i128" {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i128 %s to i64\n", narrow, fragment)
			fragment = "%" + narrow
		}
		if part.size != frameTypeSize(part.slot.Type, 8) {
			mask := ^uint64(0) >> uint(64-part.size*8)
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, fragment, mask)
			fragment = "%" + masked
			shift := (part.offset - part.slot.Offset) * 8
			if shift != 0 {
				shifted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %d\n", shifted, fragment, shift)
				fragment = "%" + shifted
			}
			previous, err := c.evalFPValue64(Operand{Kind: OpFP, FPOffset: part.slot.Offset})
			if err != nil {
				return err
			}
			kept := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", kept, previous, ^(mask << uint(shift)))
			merged := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %s\n", merged, kept, fragment)
			fragment = "%" + merged
		}
		if err := c.storeFPResult64(part.slot.Offset, fragment); err != nil {
			return err
		}
	}
	return nil
}
