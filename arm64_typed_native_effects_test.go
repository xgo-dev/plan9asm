package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var arm64TypedNativeTargets = []string{
	"aarch64-unknown-linux-gnu",
	"aarch64-unknown-linux-musl",
	"aarch64-apple-darwin",
	"aarch64-pc-windows-msvc",
}

func arm64TypedNativeOptions(t *testing.T, target string) Options {
	t.Helper()
	sig := FuncSig{Name: "NativeEffects", Args: []LLVMType{I64}, Ret: I64}
	var err error
	sig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(sig)
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Goarch: "arm64", TargetTriple: target,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") },
		Sigs:       map[string]FuncSig{"NativeEffects": sig},
	}
}

func arm64TypedNativeSource(body string) string {
	return "TEXT ·NativeEffects<ABIInternal>(SB),4,$0\n" + body + "\nRET\n"
}

func arm64TypedNativeGoObject(t *testing.T, source string) {
	t.Helper()
	if goToolchainAtLeast(runtime.Version(), 1, 27) {
		requireARM64GoABIInternalObject(t, source)
	}
}

func TestARM64TypedNativeEffectsCompletePrefetchFamily(t *testing.T) {
	// Reuse the complete existing Go PRFM grammar fixture, but give every
	// consumed GP register a real reaching value at the typed entry.
	lines := strings.Split(arm64PrefetchForms, "\n")
	var body strings.Builder
	for i := 1; i < 30; i++ {
		if i != 18 && i != 28 {
			fmt.Fprintf(&body, "MOVD R0,R%d\n", i)
		}
	}
	for _, line := range lines {
		if strings.Contains(line, "PRFM ") {
			fmt.Fprintln(&body, line)
		}
	}
	for _, hint := range []string{"PLDKEEP", "PSTKEEP", "PLDSTRM", "PSTSTRM"} {
		fmt.Fprintf(&body, "RPRFM (R0),R1,%s\n", hint)
	}
	for hint := 0; hint < 64; hint++ {
		fmt.Fprintf(&body, "RPRFM (RSP),R2,$%d\n", hint)
	}
	for hint := 0; hint < 32; hint++ {
		fmt.Fprintf(&body, "PRFM (R30),$%d\n", hint)
	}
	source := arm64TypedNativeSource(body.String())
	arm64TypedNativeGoObject(t, source)
	arm64TypedNativeAllAPIsAndObjects(t, source, 58, 68)
}

func TestARM64TypedNativeEffectsDCZIDNamedAndRaw(t *testing.T) {
	var body strings.Builder
	// Go's physical platform register R18 is deliberately not made an
	// ordinary typed GP result by this system-register proof.
	for i := 0; i < 30; i++ {
		if i != 18 && i != 27 && i != 28 {
			fmt.Fprintf(&body, "MRS DCZID_EL0,R%d\n", i)
		}
	}
	fmt.Fprintln(&body, "MRS DCZID_EL0,ZR")
	fmt.Fprintln(&body, "MRS DCZID_EL0,R27")
	fmt.Fprintln(&body, "MOVD R30,R27")
	fmt.Fprintln(&body, "MRS DCZID_EL0,R30")
	fmt.Fprintln(&body, "MOVD R27,R30")
	spec := arm64GoSystemRegisters["DCZID_EL0"]
	for reg := uint32(0); reg < 32; reg++ {
		if reg == 18 || reg == 28 {
			continue
		}
		saved := 27
		if reg == 27 {
			saved = 25
		}
		fmt.Fprintf(&body, "MOVD R30,R%d\nWORD $0x%08x\nMOVD R%d,R30\n",
			saved, uint32(0xd5300000)|uint32(spec.encoding)<<5|reg, saved)
	}
	source := arm64TypedNativeSource(body.String())
	arm64TypedNativeGoObject(t, source)
	arm64TypedNativeAllAPIsAndObjects(t, source, 0, 0)
}

func arm64TypedNativeAllAPIsAndObjects(t *testing.T, source string, prfm, rprfm int) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			opt := arm64TypedNativeOptions(t, target)
			text, err := Translate(file, opt)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(text, `asm sideeffect "prfm #`) != prfm ||
				strings.Count(text, `asm sideeffect "rprfm #`) != rprfm {
				t.Fatal("typed proof changed the actual prefetch instruction inventory")
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, opt)
			if err != nil {
				t.Fatal(err)
			}
			ir := module.String()
			module.Dispose()
			compileLLVMToObject(t, llc, target, "typed-native.ll", "typed-native.o", ir)
			pkg := mustGoPackage(t, "test/nativeeffects", "package nativeeffects\nfunc NativeEffects(uint64) uint64\n")
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
			})
			if err != nil {
				t.Fatal(err)
			}
			bound.Module.Dispose()
		})
	}
}

func TestARM64TypedNativeEffectsUnknownStateRemainsContext(t *testing.T) {
	spec := arm64GoSystemRegisters["DCZID_EL0"]
	for _, body := range []string{
		"PRFM (R9),PLDL1KEEP",
		"RPRFM (R0),R9,PLDKEEP",
		"MRS DCZID_EL0,R30",
		"MRS DCZID_EL0,R18_PLATFORM",
		"MRS DCZID_EL0,g",
		"MRS DCZID_EL0,R9\nB (R9)",
		"MRS NZCV,R0",
		// RNG defines its result and NZCV, but not an unrelated GP input.
		"MRS RNDR,R0\nADD R9,R0,R0",
		"MRS SCTLR_EL1,R0",
		"MSR R0,TPIDR_EL0",
		"WORD $0xd5300000",
		"WORD $0xd51bd040", // MSR R0,TPIDR_EL0 stays outside this typed role.
		fmt.Sprintf("WORD $0x%08x", uint32(0xd5300000)|uint32(spec.encoding)<<5|18),
		fmt.Sprintf("WORD $0x%08x", uint32(0xd5300000)|uint32(spec.encoding)<<5|28),
	} {
		t.Run(strings.ReplaceAll(body, "\n", "_"), func(t *testing.T) {
			source := arm64TypedNativeSource(body)
			arm64TypedNativeGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				opt := arm64TypedNativeOptions(t, target)
				_, err := Translate(file, opt)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: unknown state accepted: %v", target, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: module accepted unknown state: %v", target, err)
				}
				pkg := mustGoPackage(t, "test/nativeeffects", "package nativeeffects\nfunc NativeEffects(uint64) uint64\n")
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
				})
				if bound != nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s: Go binding accepted unknown state: %v", target, err)
				}
			}
		})
	}
}

func TestARM64TypedNativeEffectsMRSRejectsNonGPDestinations(t *testing.T) {
	for _, instruction := range []string{
		"MRS DCZID_EL0,RSP", "MRS DCZID_EL0,F0", "MRS DCZID_EL0,V0",
		"MRS DCZID_EL0,(R0)", "MRS.W DCZID_EL0,R0", "MRS.P DCZID_EL0,R0",
		"MRS DCZID_EL0,$1", "MRS R0,R1", "MRS DCZID_EL0",
	} {
		source := "TEXT bad(SB),4,$0\n" + instruction + "\nRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
			t.Errorf("MRS accepted an instruction outside the Go form table: %s", instruction)
		}
	}
}

func TestARM64TypedNativeEffectsProofIsBoundToExactEmission(t *testing.T) {
	var ir strings.Builder
	flow := &arm64MachineAvailability{
		blocks: []arm64MachineBlock{{name: "entry"}}, source: "PRFM (R0),PLDL1KEEP",
	}
	ctx := &arm64Ctx{
		b: &ir, machineAvailability: flow, flagsKnown: arm64FlagAll, flagsWritten: true,
		flagsNSlot: "flags_N", flagsZSlot: "flags_Z", flagsCSlot: "flags_C", flagsVSlot: "flags_V",
	}
	opaqueCount := func() int {
		count := 0
		for _, effect := range flow.blocks[0].effects {
			if effect.opaque {
				count++
			}
		}
		return count
	}
	ctx.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q()\n", "nop", "")
	ctx.recordMachineOpaqueIR(0, Instr{})
	if len(flow.blocks[0].effects) != 0 || ctx.flagsKnown != arm64FlagAll || !ctx.flagsWritten {
		t.Fatal("exact validated native emission remained opaque")
	}
	start := ir.Len()
	fmt.Fprint(&ir, "  call void asm sideeffect \"nop\", \"\"()\n")
	ctx.recordMachineOpaqueIR(start, Instr{})
	if opaqueCount() != 1 || ctx.flagsKnown != 0 || ctx.flagsWritten {
		t.Fatal("identical unproven native IR borrowed a different emission's proof")
	}
	unavailable := make(map[string]int)
	for _, effect := range flow.blocks[0].effects {
		if !effect.unavailable {
			continue
		}
		if effect.width != 1 {
			t.Fatalf("native flag invalidation widened %s to %d bits", effect.register, effect.width)
		}
		unavailable[effect.register]++
	}
	if len(unavailable) != 4 {
		t.Fatalf("native callout did not separately revoke all four flags: %v", unavailable)
	}
	for _, slot := range []string{ctx.flagsNSlot, ctx.flagsZSlot, ctx.flagsCSlot, ctx.flagsVSlot} {
		if unavailable[slot] != 1 {
			t.Fatalf("native callout did not revoke %s exactly once: %v", slot, unavailable)
		}
	}
	start = ir.Len()
	ctx.emitMachineNeutralNativeIR("  call void asm sideeffect %q, %q()\n", "nop", "")
	fmt.Fprint(&ir, "  call void @unknown()\n")
	ctx.recordMachineOpaqueIR(start, Instr{})
	if opaqueCount() != 2 {
		t.Fatal("one proven line excused a second unknown callout")
	}
}
