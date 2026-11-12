package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64BarrierPreservesUnknownSourceScratch(t *testing.T) {
	instructions := []string{"SB"}
	for _, op := range []string{"DMB", "DSB", "ISB"} {
		for immediate := 0; immediate < 16; immediate++ {
			instructions = append(instructions, fmt.Sprintf("%s $%d", op, immediate))
		}
	}
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			ins := arm64ImmediateTestInstruction(t, instruction)
			var ir strings.Builder
			flow := &arm64MachineAvailability{
				blocks: []arm64MachineBlock{{name: "entry", effects: []arm64MachineEffect{
					{register: "R27", unavailable: true, source: "original source memory expansion"},
				}}},
				source: instruction, sourceScratch: true,
			}
			ctx := &arm64Ctx{b: &ir, machineAvailability: flow}
			ok, terminated, err := ctx.lowerARM64Barrier(ins.Op, ins)
			if !ok || terminated || err != nil {
				t.Fatalf("barrier lowerer = (%v, %v, %v)", ok, terminated, err)
			}
			ctx.recordMachineOpaqueIR(0, ins)
			if err := flow.validateSourceScratch(); err != nil {
				t.Fatalf("barrier observed a GP scratch it does not read: %v", err)
			}
			if !strings.Contains(ir.String(), "~{memory}") || len(flow.blocks[0].effects) != 1 {
				t.Fatalf("barrier lost its memory clobber or manufactured register effects: %s", ir.String())
			}
			// Neutral does not make the original scratch known or permit a
			// second, unproved native effect in the same source instruction.
			flow.blocks[0].effects = append(flow.blocks[0].effects, arm64MachineEffect{
				register: "R27", width: 64, source: "subsequent real R27 read",
			})
			if err := flow.validateSourceScratch(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("barrier made R27 available: %v", err)
			}
			flow.blocks[0].effects = flow.blocks[0].effects[:1]
			fmt.Fprintln(&ir, `  call void asm sideeffect "nop", ""()`)
			ctx.recordMachineOpaqueIR(0, ins)
			if err := flow.validateSourceScratch(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("validated barrier excused a second opaque callout: %v", err)
			}
		})
	}
}

func TestARM64BarrierRejectsFloatingConstantClass(t *testing.T) {
	for _, op := range []string{"DMB", "DSB", "ISB"} {
		for _, literal := range []string{"0.0", "-0.0", "1.5", "-1.5"} {
			instruction := fmt.Sprintf("%s $%s", op, literal)
			t.Run(instruction, func(t *testing.T) {
				requireARM64GoAssemblerResult(t, "TEXT invalid(SB),516,$0-0\n"+instruction+"\nRET\n", false)
				ins := arm64ImmediateTestInstruction(t, instruction)
				var ir strings.Builder
				ctx := &arm64Ctx{b: &ir}
				ok, _, err := ctx.lowerARM64Barrier(ins.Op, ins)
				if !ok || err == nil || ir.Len() != 0 {
					t.Fatalf("Go-invalid floating barrier = (%v, %v), emitted %q", ok, err, ir.String())
				}
			})
		}
	}
}
