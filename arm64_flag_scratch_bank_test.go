package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func arm64FlagScratchBankFixture() (*arm64Ctx, *arm64MachineAvailability) {
	flow := &arm64MachineAvailability{
		blocks: []arm64MachineBlock{{name: "entry"}},
		source: "unmodeled native callout", sourceScratch: true,
	}
	return &arm64Ctx{
		b: &strings.Builder{}, machineAvailability: flow,
		flagsNSlot: "%nzcv_N", flagsZSlot: "%nzcv_Z", flagsCSlot: "%nzcv_C", flagsVSlot: "%nzcv_V",
		flagsKnown: arm64FlagAll, flagsWritten: true,
	}, flow
}

func TestARM64FlagScratchBankDoesNotInventOriginalGPScratch(t *testing.T) {
	ctx, flow := arm64FlagScratchBankFixture()
	fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
	ctx.recordMachineOpaqueIR(0, Instr{})
	if ctx.flagsKnown != 0 || ctx.flagsWritten || len(flow.blocks[0].effects) != 5 {
		t.Fatalf("native callout did not revoke four flags before its opaque effect: %+v", flow.blocks[0].effects)
	}
	if err := flow.validateSourceScratch(); err != nil {
		t.Fatalf("virtual NZCV became a missing original Go GP scratch: %v", err)
	}
}

func TestARM64FlagScratchBankRetainsPhysicalGPScratch(t *testing.T) {
	for _, register := range []Reg{"R27", "R1"} {
		t.Run(string(register), func(t *testing.T) {
			ctx, flow := arm64FlagScratchBankFixture()
			ctx.recordMachineUnavailable(register)
			fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
			ctx.recordMachineOpaqueIR(0, Instr{})
			if err := flow.validateSourceScratch(); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "native effects can observe an unbound original Go memory scratch") {
				t.Fatalf("native callout manufactured physical %s scratch: %v", register, err)
			}
		})
	}
}

func TestARM64FlagScratchBankRetainsOrderedFlagRejection(t *testing.T) {
	for _, flag := range []struct {
		condition string
		mask      uint8
	}{
		{"MI", 0x8}, {"EQ", 0x4}, {"CS", 0x2}, {"VS", 0x1},
	} {
		t.Run(flag.condition, func(t *testing.T) {
			ctx, flow := arm64FlagScratchBankFixture()
			ctx.flagFlow = &arm64FlagFlow{blocks: []arm64FlagFlowBlock{{name: "entry"}}}
			ctx.setFlagsSub("10", "4", "6")
			start := ctx.b.Len()
			fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
			ctx.recordMachineOpaqueIR(start, Instr{})
			if _, err := ctx.condValue(flag.condition); err != nil {
				t.Fatal(err)
			}
			if err := flow.validateSourceScratch(); err != nil {
				t.Fatalf("virtual flag read entered original GP scratch analysis: %v", err)
			}
			witness := fmt.Sprintf("condition %s has unknown NZCV bits %#x", flag.condition, flag.mask)
			if err := ctx.flagFlow.validate(); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), witness) {
				t.Fatalf("native callout manufactured ordered %s flag bits: %v", flag.condition, err)
			}
		})
	}
}

func TestARM64FlagScratchBankTagsActualReadWriteAndUnavailable(t *testing.T) {
	ctx, flow := arm64FlagScratchBankFixture()
	for _, flag := range []struct {
		slot string
		mask arm64FlagMask
	}{
		{ctx.flagsNSlot, arm64FlagN}, {ctx.flagsZSlot, arm64FlagZ},
		{ctx.flagsCSlot, arm64FlagC}, {ctx.flagsVSlot, arm64FlagV},
	} {
		ctx.storeFlag(flag.slot, "true")
		ctx.recordMachineRegister(Reg(flag.slot), 1, false)
		ctx.recordMachineUnavailable(Reg(flag.slot))
		for _, effect := range flow.blocks[0].effects[len(flow.blocks[0].effects)-3:] {
			if effect.nzcv != flag.mask || effect.width != 1 || effect.register != flag.slot {
				t.Fatalf("actual flag hook lost its typed bank: %+v", effect)
			}
		}
	}
	ctx.recordMachineUnavailable("R27")
	ctx.recordMachineRegister("R1", 64, false)
	ctx.recordMachineRegister("R1", 64, true)
	for _, effect := range flow.blocks[0].effects[len(flow.blocks[0].effects)-3:] {
		if effect.nzcv != 0 || effect.width != 64 {
			t.Fatalf("physical GP effect acquired a virtual flag bank: %+v", effect)
		}
	}
	ctx.regSlot = map[Reg]string{"R27": "%r27", "R1": "%r1"}
	if err := ctx.lowerMachineRegisterCopy("R27", "R1"); err != nil {
		t.Fatal(err)
	}
	copy := flow.blocks[0].effects[len(flow.blocks[0].effects)-1]
	if copy.nzcv != 0 || copy.copyFrom != "R27" || copy.register != "R1" || copy.width != 64 {
		t.Fatalf("validated physical GP copy acquired a virtual flag bank: %+v", copy)
	}
}

func TestARM64FlagScratchBankRetainsMachineDefinedness(t *testing.T) {
	for _, slot := range []string{"%nzcv_N", "%nzcv_Z", "%nzcv_C", "%nzcv_V"} {
		t.Run(slot, func(t *testing.T) {
			ctx, flow := arm64FlagScratchBankFixture()
			flow.used, flow.entry = true, &ARM64GoRegisterABI{}
			ctx.invalidateARM64Flags(arm64FlagAll)
			ctx.recordMachineRegister(Reg(slot), 1, false)
			if err := flow.validateSourceScratch(); err != nil {
				t.Fatalf("virtual flag entered physical GP scratch analysis: %v", err)
			}
			witness := slot + " read (1 bits) is not supplied"
			if err := flow.validate(); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), witness) {
				t.Fatalf("virtual flag bank bypassed machine must-defined analysis: %v", err)
			}
		})
	}
}
