package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Both invocations of this exact raw helper are valid: one points at the
// incoming output, the other at a disjoint slice of the fresh private frame.
// A context-insensitive join cannot use external+SP as an exact memory cell.
func arm64RawContextFixture(t *testing.T) string {
	t.Helper()
	source := `TEXT rawContext(SB),516,$0-16
MOVD in+0(FP),R4
MOVD out+8(FP),R1
WORD $0xa9bc7bfd
WORD $0x3dc00080
MOVD R1,R0
WORD $0x94000000
WORD $0x910043e0
WORD $0x94000000
WORD $0x3dc007e1
WORD $0x3d800421
WORD $0xa8c47bfd
WORD $0xd65f03c0
helper:
WORD $0x3d800000
WORD $0xd65f03c0
`
	return arm64RawContextResolveCalls(t, source)
}

func arm64RawContextResolveCalls(t *testing.T, source string) string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	var calls []int64
	offset, helper := int64(0), int64(-1)
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == OpLABEL && ins.Args[0].Sym == "helper" {
			helper = offset
		}
		if ins.Op == OpWORD && ins.Args[0].Imm == 0x94000000 {
			calls = append(calls, offset)
		}
		width, known := arm64RawKnownSourceWidth(file.Funcs[0], ins)
		if !known {
			t.Fatalf("fixture source width is unknown: %s", ins.Raw)
		}
		offset += width
	}
	if helper < 0 || len(calls) != 2 {
		t.Fatal("missing raw helper layout")
	}
	for _, call := range calls {
		word := uint32(0x94000000) | uint32((helper-call)/4)&0x03ffffff
		source = strings.Replace(source, "WORD $0x94000000", fmt.Sprintf("WORD $%#x", word), 1)
	}
	return source
}

func TestARM64RawContextLocalAndExternalHelperPointer(t *testing.T) {
	source := arm64RawContextFixture(t)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := arm64RawZeroFrameSig()
	sig.Name = "rawContext"
	if !arm64CallFrameUnexposedTyped(file.Funcs[0], sig, nil, nil) {
		t.Fatal("valid raw helper contexts did not restore the independent whole-source caller proof")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "raw-context.ll", "raw-context.o", ir)
	}
}

func arm64RawContextLowerer(t *testing.T, source string, sig FuncSig) *arm64Ctx {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	fn, _, err := prepareARM64RawPCRelative(file.Funcs[0])
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	return newARM64Ctx(&output, fn, sig, nil, nil, false)
}

func TestARM64RawContextControlRequiresCompleteBoundSource(t *testing.T) {
	source := arm64RawContextFixture(t)
	sig := arm64RawZeroFrameSig()
	sig.Name = "rawContext"
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"full_overlap", "WORD $0x910043e0", "WORD $0x910003e0"},
		{"one_byte_overlap", "WORD $0x910043e0", "WORD $0x91003fe0"},
		{"escape_to_external", "helper:\n", "helper:\nMOVD R0,(R1)\n"},
		{"escape_to_global", "helper:\n", "helper:\nMOVD R0,escaped(SB)\n"},
		{"escape_alias", "helper:\n", "helper:\nMOVD R0,R9\nMOVD R9,(R1)\n"},
		{"bad_lr", "helper:\n", "helper:\nMOVD R1,R30\n"},
		{"bad_g", "helper:\n", "helper:\nMOVD $0,g\n"},
		{"bad_os", "helper:\n", "helper:\nWORD $0xd2800012\n"},
		{"bad_bp", "helper:\n", "helper:\nMOVD $0,R29\n"},
		{"unbalanced_sp", "helper:\n", "helper:\nWORD $0xd10043ff\n"},
		{"native_blr", "helper:\n", "helper:\nWORD $0xd63f0200\n"},
		{"self_bl", "helper:\n", "helper:\nWORD $0x94000000\n"},
		{"unknown_word", "helper:\n", "helper:\nWORD $0xffffffff\n"},
		{"ordinary_unproved_call", "WORD $0x94000007", "BL helper"},
		{"external_call", "helper:\n", "helper:\nBL external(SB)\n"},
		{"conditional_sp_mismatch", "helper:\n", "helper:\nCBZ R2,join\nWORD $0xd10043ff\njoin:\n"},
		{"conditional_lr_mismatch", "helper:\n", "helper:\nCBZ R2,join\nMOVD R1,R30\njoin:\n"},
		{"conditional_g_mismatch", "helper:\n", "helper:\nCBZ R2,join\nMOVD $0,g\njoin:\n"},
		{"mixed_pointer_store", "helper:\n", "helper:\nCBZ R2,join\nMOVD R1,R0\njoin:\n"},
		{"conditional_pointer_escape", "helper:\n", "helper:\nCBZ R2,join\nMOVD R0,(R1)\njoin:\n"},
		{"dead_unsafe_component", "helper:\n", "dead:\nWORD $0xffffffff\nWORD $0xd65f03c0\nhelper:\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.Replace(source, tc.old, tc.replacement, 1)
			if tc.name == "dead_unsafe_component" {
				changed = source + "dead:\nWORD $0xffffffff\nWORD $0xd65f03c0\n"
			}
			if tc.name == "bad_bp" {
				changed = strings.Replace(changed, "WORD $0xa8c47bfd", "WORD $0xa8c47be4", 1)
			}
			if changed == source {
				t.Fatalf("negative did not change fixture: %s", tc.old)
			}
			c := arm64RawContextLowerer(t, changed, sig)
			// Even a caller-supplied true bool must not publish a partial plan
			// from an independently failing normalized whole-source proof.
			c.unexposedCallFrame = true
			if c.rawZeroContextControlPlan("outer") != nil {
				t.Fatal("unsafe/partial raw source published a continuation certificate")
			}
		})
	}
	for _, mutate := range []func(*arm64Ctx){
		func(c *arm64Ctx) { c.unexposedCallFrame = false },
		func(c *arm64Ctx) { c.sourceGoFrame.present = true },
		func(c *arm64Ctx) { c.sig.ArgRegs = []Reg{SP, "R1"} },
		func(c *arm64Ctx) { c.sig.Frame.Params = nil },
		func(c *arm64Ctx) { c.sig.Ret = I64 },
		func(c *arm64Ctx) { c.normalizedSource.Instrs = c.normalizedSource.Instrs[1:] },
		func(c *arm64Ctx) { c.blocks = c.blocks[1:] },
	} {
		c := arm64RawContextLowerer(t, source, sig)
		mutate(c)
		if c.rawZeroContextControlPlan("outer") != nil {
			t.Fatal("missing original/typed/fresh/normalized binding published a certificate")
		}
	}
	// A user label must not collide with the independent caller sentinel.
	c := arm64RawContextLowerer(t, strings.Replace(source, "helper:", "__entry_lr:", 1), sig)
	if c.rawZeroContextControlPlan("outer") == nil {
		t.Fatal("legitimate helper label collided with synthetic entry-LR identity")
	}
	// A helper CFG is permitted only when both paths independently restore
	// the same exact continuation and stack; this is not a straight-line rule.
	branched := strings.Replace(source, "helper:\nWORD $0x3d800000\n", `helper:
CBZ R2,other
WORD $0x3d800000
B joined
other:
WORD $0x3d800000
joined:
`, 1)
	c = arm64RawContextLowerer(t, branched, sig)
	if c.rawZeroContextControlPlan("outer") == nil {
		t.Fatal("same-source helper with matching branch contexts lost its complete proof")
	}
}
