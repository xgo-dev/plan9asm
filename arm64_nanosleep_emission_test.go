package plan9asm

import (
	"strings"
	"testing"
)

func arm64NanosleepEmittedProof(t *testing.T) (*arm64Ctx, int, Instr) {
	t.Helper()
	c := arm64NanosleepProofContext(t)
	c.emitEntryAllocasAndArgInit()
	c.machineAvailability = newARM64MachineAvailability(c)
	if err := c.lowerBlocks(); err != nil {
		t.Fatal("actual nanosleep lowering prerequisite", err)
	}
	if err := c.machineAvailability.validate(); err != nil {
		t.Fatal("complete numerical/byte-defined input prerequisite", err)
	}
	count, start := 0, -1
	var original Instr
	for offset, native := range c.machineAvailability.nativeIR {
		if native.syscall == nil {
			continue
		}
		count++
		if strings.Contains(native.line, "call i64 @syscall(") {
			start, original = offset, native.syscall.source
			c.currentBlock, c.currentInstruction = native.syscall.block, native.syscall.instruction
			c.machineAvailability.current = c.currentBlock
		}
	}
	if count != 2 || start < 0 {
		t.Fatal("actual syscall/errno pair lost its distinct source-bound effects")
	}
	c.machineAvailability.blocks[c.currentBlock].effects = nil
	return c, start, original
}

func TestARM64NanosleepEmittedBorrowIsExactAndNotNeutral(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*arm64Ctx, int)
	}{
		{"unaltered", func(*arm64Ctx, int) {}},
		{"copied-input", func(c *arm64Ctx, _ int) {
			copy := *c.nanosleepInput
			c.nanosleepInput = &copy
		}},
		{"lost-original", func(c *arm64Ctx, _ int) { c.nanosleepOriginal = nil }},
		{"copied-emission", func(c *arm64Ctx, start int) {
			native := c.machineAvailability.nativeIR[start]
			copy := *native.syscall
			native.syscall = &copy
			c.machineAvailability.nativeIR[start] = native
		}},
		{"source-changed", func(c *arm64Ctx, _ int) { c.normalizedSource.Instrs[1].Raw += " changed" }},
		{"target-changed", func(c *arm64Ctx, _ int) { c.targetTriple = "aarch64-unknown-linux-musl" }},
		{"operand-line-changed", func(c *arm64Ctx, start int) {
			native := c.machineAvailability.nativeIR[start]
			native.line = strings.Replace(native.line, "i64 0, i64 0, i64 0, i64 0)", "i64 1, i64 0, i64 0, i64 0)", 1)
			c.machineAvailability.nativeIR[start] = native
		}},
		{"erased-memory-effect", func(c *arm64Ctx, start int) {
			native := c.machineAvailability.nativeIR[start]
			native.store = false
			c.machineAvailability.nativeIR[start] = native
		}},
		{"foreign-call", func(c *arm64Ctx, _ int) {
			c.b.WriteString("  %foreign = call i64 @syscall(i64 101, i64 0, i64 0, i64 0, i64 0, i64 0, i64 0)\n")
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			c, start, original := arm64NanosleepEmittedProof(t)
			change.apply(c, start)
			c.recordMachineOpaqueIR(start, original)
			stores, opaque := 0, 0
			for _, effect := range c.machineAvailability.blocks[c.currentBlock].effects {
				if effect.store {
					stores++
				}
				if effect.opaque {
					opaque++
				}
			}
			if change.name == "unaltered" {
				if stores != 2 || opaque != 0 {
					t.Fatalf("typed syscall bridge erased real effects: stores=%d opaque=%d", stores, opaque)
				}
			} else if opaque == 0 {
				t.Fatal("stale/copied/changed borrow was accepted as an actual emission")
			}
		})
	}
}
