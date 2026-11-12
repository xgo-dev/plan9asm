package plan9asm

import "fmt"

// Keep defined, preserved and ISA-choice arms separate. Only the paired result
// observer may consume these finite choices; the ordinary typed effect retains
// its stricter availability contract. Nothing restores native entry FLAGS.
func (c *amd64Ctx) emitScalarShiftFlags(stem string, bits int, before, result, count string, double bool) {
	ty := amd64IntegerTypeForBits(bits)
	predicate := func(comparison string, amount int) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s i64 %s, %d\n", name, comparison, count, amount)
		return "%" + name
	}
	nonzero, multiple := predicate("ne", 0), predicate("ugt", 1)
	outside := "false"
	if double && bits == 16 {
		outside = predicate("ugt", bits)
	}
	bit := func(value, index string) string {
		if bits != 64 {
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", truncated, index, ty)
			index = "%" + truncated
		}
		shifted, flag := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shifted, ty, value, index)
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i1\n", flag, ty, shifted)
		return "%" + flag
	}
	write := func(slot, value, choice, old string) {
		if old == "" {
			old = c.loadFlag(slot)
		}
		if choice != "false" {
			value = c.emitScalarShiftArchitecturalChoice(I1, choice, value)
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i1 %s, i1 %s\n", selected, nonzero, value, old)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", selected, slot)
	}
	msb := bit(result, fmt.Sprint(bits-1))
	var cf, overflow string
	if !double && (stem == "ROL" || stem == "ROR") {
		if stem == "ROL" {
			cf = bit(result, "0")
		} else {
			cf = msb
		}
		write(c.flagsCFSlot, cf, "false", "")
		other := cf
		if stem == "ROR" {
			other = bit(result, fmt.Sprint(bits-2))
		}
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", name, msb, other)
		overflow = "%" + name
	} else {
		// Clamp only the bit-index calculation, so count0 and out-of-range
		// B/W counts cannot produce LLVM poison even on an inactive select.
		zero := predicate("eq", 0)
		minimum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 1, i64 %s\n", minimum, zero, count)
		large := predicate("ugt", bits)
		bounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %d, i64 %%%s\n", bounded, large, bits, minimum)
		index := c.newTmp()
		if stem == "SHL" || stem == "SAL" {
			fmt.Fprintf(c.b, "  %%%s = sub i64 %d, %%%s\n", index, bits, bounded)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, 1\n", index, bounded)
		}
		cf = bit(before, "%"+index)
		cfChoice := outside
		if !double && stem != "SAR" && bits < 32 {
			cfChoice = predicate("uge", bits)
		}
		write(c.flagsCFSlot, cf, cfChoice, "")
		oldMSB := bit(before, fmt.Sprint(bits-1))
		if double {
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", name, oldMSB, msb)
			overflow = "%" + name
		} else if stem == "SAR" {
			overflow = "false"
		} else if stem == "SHR" {
			overflow = oldMSB
		} else {
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", name, msb, cf)
			overflow = "%" + name
		}
		zf, sf := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zf, ty, result)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sf, ty, result)
		write(c.flagsZSlot, "%"+zf, outside, "")
		write(c.flagsSltSlot, "%"+sf, outside, "")
		oldPF := c.loadFlag(c.flagsPFSlot)
		c.setParityFlagSized(ty, result)
		write(c.flagsPFSlot, c.loadFlag(c.flagsPFSlot), outside, oldPF)
		// AF is unspecified for every nonzero scalar/double shift. Its
		// zero-count arm still preserves the actual old availability/value.
		write(c.flagsAFSlot, "false", "true", "")
	}
	// The formula is used only at count1; at count0 the outer write preserves
	// old OF, and count>1 selects one frozen finite architectural choice.
	write(c.flagsOFSlot, overflow, multiple, "")
}
