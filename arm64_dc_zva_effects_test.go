package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64DCZVAControlIsAnUnknownExtentStore(t *testing.T) {
	file, err := Parse(ArchARM64, arm64TypedNativeSource("DC ZVA,R0"))
	if err != nil {
		t.Fatal(err)
	}
	state := arm64ControlState{
		regs: map[Reg]arm64ControlValue{
			"R0": arm64ControlFromMap(map[string]bool{"label:data": true}), "R30": arm64ControlFromMap(map[string]bool{"label:caller": true}),
		},
		memory: map[string]arm64ControlValue{
			"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true}), "sp:4096": arm64ControlFromMap(map[string]bool{"label:far": true}),
			"fp:8": arm64ControlFromMap(map[string]bool{"fpa:24": true}),
		},
	}
	before := state.clone()
	ins := file.Funcs[0].Instrs[1]
	state.transfer(ins, "DC", false, nil)
	if !reflect.DeepEqual(state.regs, before.regs) {
		t.Fatal("DC ZVA reads its address; it must not define a GP destination")
	}
	for key, value := range state.memory {
		if !arm64ControlHas(value, "") {
			t.Errorf("unknown hardware granule left %s falsely known: %v", key, value)
		}
		for _, token := range arm64ControlKeys(before.memory[key]) {
			if !arm64ControlHas(value, token) {
				t.Errorf("possible old contents/aliases were discarded at %s: %v", key, value)
			}
		}
	}
	raw := before.clone()
	raw.transfer(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0xd50b7420}}}, OpWORD, false, nil)
	if !reflect.DeepEqual(raw, &state) {
		t.Fatal("raw and named ZVA continuation memory/GP effects diverged")
	}
}

func TestARM64DCZVACompleteGoOperationTable(t *testing.T) {
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return // Newest table comparison is versioned; the objects still run below.
	}
	source, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`SPOP_([A-Z0-9]+):\s*\{\s*([0-9]+),\s*7,\s*([0-9]+),\s*([0-9]+),\s*true\s*\}`)
	want := make(map[arm64CacheOperation]arm64SystemFields)
	for _, match := range row.FindAllStringSubmatch(string(source), -1) {
		op1, _ := strconv.Atoi(match[2])
		cm, _ := strconv.Atoi(match[3])
		op2, _ := strconv.Atoi(match[4])
		want[arm64CacheOperation(match[1])] = arm64SystemFields{uint8(op1), uint8(cm), uint8(op2)}
	}
	if len(want) != 28 || !reflect.DeepEqual(want, arm64CacheOperations) {
		t.Fatalf("DC must mirror all actual Go cn=7 rows, got %d: %v", len(want), want)
	}
}

func TestARM64DCZVACompleteGrammarObjects(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64CacheMaintenanceForms, true)
	file, err := Parse(ArchARM64, arm64CacheMaintenanceForms)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, Options{
				Goarch: "arm64", TargetTriple: target,
				Sigs: map[string]FuncSig{"cachemaintenanceforms": {Name: "cachemaintenanceforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, target, "dc-family.ll", "dc-family.o", module.String())
		})
	}
}

func TestARM64DCZVAOtherCacheOperationsRemainContext(t *testing.T) {
	var operations []string
	for operation := range arm64CacheOperations {
		if operation != "ZVA" {
			operations = append(operations, string(operation))
		}
	}
	sort.Strings(operations)
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			source := arm64TypedNativeSource("DC " + operation + ",R0")
			arm64TypedNativeGoObject(t, source)
			arm64DCZVARequireContextAllAPIs(t, source)
		})
	}
}

func TestARM64DCZVASymbolAddressesNeedNativeExtentContract(t *testing.T) {
	for _, address := range []string{
		"MOVD $payload<>(SB)", "MOVD $payload<>+1(SB)", "MOVD $payload<>+4096(SB)", "MOVD $external(SB)",
		"MOVWU $payload<>(SB)",
	} {
		t.Run(address, func(t *testing.T) {
			source := arm64TypedNativeSource(address+",R0\nDC ZVA,R0") +
				"DATA payload<>+0(SB)/8,$7\nGLOBL payload<>(SB),16,$8\n"
			// A real Go relocation is valid grammar, not proof that the
			// separately materialized LLVM object's hardware zero granule
			// has the same extent/alignment/neighbours as the Go symbol.
			arm64TypedNativeGoObject(t, source)
			arm64DCZVARequireContextAllAPIs(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			if !errors.Is(validateARM64DCZVASource(fn, file.Data), ErrProbeNeedsContext) {
				t.Fatal("original source gate lost SB address-of")
			}
			fn, err = normalizeARM64RawPCRelative(fn)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(validateARM64DCZVAAddressSources(arm64SourceGoFrame(fn), fn.FrameSize, arm64SplitBlocks(fn), file.Data), ErrProbeNeedsContext) {
				t.Fatal("normalized CFG gate lost SB address-of")
			}
		})
	}
}

func TestARM64DCZVAUnprovenPrivateAddressSourcesRemainContext(t *testing.T) {
	for name, source := range map[string]string{
		"frame":           "TEXT ·NativeEffects<ABIInternal>(SB),4,$32\nDC ZVA,R0\nRET\n",
		"saved-LR":        "TEXT ·NativeEffects<ABIInternal>(SB),4,$32\nBL helper\nDC ZVA,R0\nRET\nhelper:\nB (R30)\n",
		"SP":              arm64TypedNativeSource("MOVD RSP,R2\nDC ZVA,R0"),
		"masked-SP":       arm64TypedNativeSource("MOVD RSP,R0\nAND $-64,R0\nDC ZVA,R0"),
		"FP-pointer-slot": arm64TypedNativeSource("MOVD $ret+8(FP),R2\nADD $1,R2\nDC ZVA,R2"),
		"FP-data":         arm64TypedNativeSource("MOVD arg+0(FP),R2\nDC ZVA,R0"),
		"ADR":             arm64TypedNativeSource("ADR here,R2\nDC ZVA,R0\nhere:"),
		"unreachable-SP":  arm64TypedNativeSource("B clear\ndead:\nMOVD RSP,R2\nclear:\nDC ZVA,R0"),
		"raw-SP":          arm64TypedNativeSource("WORD $0x910003e2\nDC ZVA,R0"),
		"DWORD":           arm64TypedNativeSource("DWORD $0x910003e2\nDC ZVA,R0"),
		"LR-data":         arm64TypedNativeSource("MOVD R30,R2\nDC ZVA,R0"),
		"unknown-input":   arm64TypedNativeSource("DC ZVA,R9"),
		"platform-input":  arm64TypedNativeSource("MOVD R0,R18_PLATFORM\nDC ZVA,R18_PLATFORM"),
		"g-input":         arm64TypedNativeSource("MOVD R0,g\nDC ZVA,g"),
	} {
		t.Run(name, func(t *testing.T) {
			arm64TypedNativeGoObject(t, source)
			arm64DCZVARequireContextAllAPIs(t, source)
		})
	}
}

func arm64DCZVARequireContextAllAPIs(t *testing.T, source string) {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "test/nativeeffects", "package nativeeffects\nfunc NativeEffects(uint64) uint64\n")
	for _, target := range arm64TypedNativeTargets {
		opt := arm64TypedNativeOptions(t, target)
		_, err := Translate(file, opt)
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: Translate requires Context, got %v", target, err)
		}
		ctx := llvm.NewContext()
		module, err := TranslateModuleInContext(ctx, file, opt)
		if err == nil {
			module.Dispose()
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: Module requires Context, got %v", target, err)
		}
		bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target, ResolveSym: opt.ResolveSym,
		})
		if bound != nil {
			bound.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s: Go binding requires Context, got %v", target, err)
		}
	}
}

func TestARM64DCZVAValidatedAddressReads(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 30; i++ {
		if i == 18 || i == 28 {
			continue
		}
		if i != 0 {
			fmt.Fprintf(&body, "MOVD R0,R%d\n", i)
		}
		fmt.Fprintf(&body, "DC ZVA,R%d\n", i)
	}
	fmt.Fprintln(&body, "DC ZVA,ZR")
	// Keep the register-address grammar distinct from caller-return proof.
	// This compile-only function does not touch memory at runtime.
	source := arm64TypedNativeSource(body.String())
	arm64TypedNativeGoObject(t, source)
	arm64TypedNativeAllAPIsAndObjects(t, source, 0, 0)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	// Control-only R30 consumption is legal, unlike exposing its LLVM/native
	// code address as ordinary data. A raw RET word has no Go epilogue.
	file.Funcs[0].Instrs[len(file.Funcs[0].Instrs)-1] = Instr{
		Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0xd65f03c0}}, Raw: "WORD $0xd65f03c0",
	}
	if _, err := Translate(file, arm64TypedNativeOptions(t, arm64TypedNativeTargets[0])); err != nil {
		t.Fatalf("raw caller RET was mistaken for a private address observer: %v", err)
	}
}

func TestARM64DCZVARawAddressReadsAndSharedEffects(t *testing.T) {
	fields := arm64CacheOperations["ZVA"]
	base := uint32(0xd5080000) | uint32(fields.op1)<<16 | 7<<12 |
		uint32(fields.cm)<<8 | uint32(fields.op2)<<5
	var body strings.Builder
	for i := uint32(0); i < 32; i++ {
		word := base | i
		form, ok := decodeARM64RawDCZVA(word)
		if !ok || form.fields != fields || form.operation != "ZVA" {
			t.Fatalf("raw ZVA rejected complete Rt=%d: %#x", i, word)
		}
		effects, ok := arm64RawContinuationEffectsForWord(word)
		if !ok || !effects.stores || effects.gpWrites != 0 || effects.readsSP ||
			effects.gpReads != arm64RawGPBit(int(i)) {
			t.Fatalf("raw ZVA Rt=%d has incorrect bank/store effects: %+v", i, effects)
		}
		if i == 18 || i == 28 || i == 30 {
			// Hidden platform/g state and entry LR as data are not an
			// ordinary typed external pointer contract.
			arm64DCZVARequireContextAllAPIs(t, arm64TypedNativeSource(fmt.Sprintf("WORD $0x%08x", word)))
			continue
		}
		if i != 0 && i != 31 {
			fmt.Fprintf(&body, "MOVD R0,R%d\n", i)
		}
		fmt.Fprintf(&body, "WORD $0x%08x\n", word)
	}
	source := arm64TypedNativeSource(body.String())
	arm64TypedNativeGoObject(t, source)
	arm64TypedNativeAllAPIsAndObjects(t, source, 0, 0)
	for bit := uint(5); bit < 32; bit++ {
		if _, ok := decodeARM64RawDCZVA(base ^ (1 << bit)); ok {
			t.Errorf("raw ZVA decoder ignored fixed bit %d", bit)
		}
	}
}

func TestARM64DCZVAStoreProofIsNotNeutralAndIsEmissionBound(t *testing.T) {
	var ir strings.Builder
	flow := &arm64MachineAvailability{
		blocks: []arm64MachineBlock{{name: "entry"}}, source: "DC ZVA,ZR",
	}
	ctx := &arm64Ctx{
		b: &ir, machineAvailability: flow, flagsKnown: arm64FlagAll, flagsWritten: true,
		flagsNSlot: "flags_N", flagsZSlot: "flags_Z", flagsCSlot: "flags_C", flagsVSlot: "flags_V",
	}
	ctx.emitMachineStoreNativeIR("  call void asm sideeffect %q, %q()\n", "sys #3, c7, c4, #1, xzr", "~{memory}")
	ctx.recordMachineOpaqueIR(0, Instr{})
	if len(flow.blocks[0].effects) != 1 || !flow.blocks[0].effects[0].store || flow.blocks[0].effects[0].opaque ||
		ctx.flagsKnown != arm64FlagAll || !ctx.flagsWritten {
		t.Fatal("validated ZVA emission must retain an explicit data-store effect")
	}

	checkEffects := func(wantStores, wantOpaque, wantUnavailable int) {
		t.Helper()
		stores, opaque := 0, 0
		unavailable := make(map[string]int)
		for _, effect := range flow.blocks[0].effects {
			switch {
			case effect.store && !effect.opaque && !effect.unavailable:
				stores++
			case effect.opaque && !effect.store && !effect.unavailable:
				opaque++
			case effect.unavailable && !effect.store && !effect.opaque && effect.width == 1:
				unavailable[effect.register]++
			default:
				t.Fatalf("unexpected native store effect: %+v", effect)
			}
		}
		if stores != wantStores || opaque != wantOpaque || len(unavailable) != 4 ||
			ctx.flagsKnown != 0 || ctx.flagsWritten {
			t.Fatalf("native store effects: stores=%d opaque=%d unavailable=%v known=%#x written=%v",
				stores, opaque, unavailable, ctx.flagsKnown, ctx.flagsWritten)
		}
		for _, slot := range []string{ctx.flagsNSlot, ctx.flagsZSlot, ctx.flagsCSlot, ctx.flagsVSlot} {
			if unavailable[slot] != wantUnavailable {
				t.Fatalf("native store revoked %s %d times, want %d", slot, unavailable[slot], wantUnavailable)
			}
		}
	}

	start := ir.Len()
	fmt.Fprint(&ir, "  call void asm sideeffect \"sys #3, c7, c4, #1, xzr\", \"~{memory}\"()\n")
	ctx.recordMachineOpaqueIR(start, Instr{})
	if _, proven := flow.nativeIR[start]; proven {
		t.Fatal("unproven identical native store borrowed an earlier exact-emission proof")
	}
	checkEffects(1, 1, 1)

	start = ir.Len()
	ctx.emitMachineStoreNativeIR("  call void asm sideeffect %q, %q()\n", "sys #3, c7, c4, #1, xzr", "~{memory}")
	fmt.Fprint(&ir, "  call void @unknown()\n")
	ctx.recordMachineOpaqueIR(start, Instr{})
	checkEffects(2, 2, 2)
}
