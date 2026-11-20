package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RawPrivateMemoryCase struct {
	name, store, load string
	width, count      int
	signBits          int // 0 unsigned, 32 sign-extend to W, 64 sign-extend to X
	floating          bool
}

func arm64RawPrivateMemoryCases() []arm64RawPrivateMemoryCase {
	var cases []arm64RawPrivateMemoryCase
	for _, shape := range []struct {
		name, store, load string
		width, count      int
		signBits          int
		floating          bool
	}{
		{name: "byte", store: "strb w4", load: "ldrb w9", width: 1, count: 1},
		{name: "signed_byte_x", store: "strb w4", load: "ldrsb x9", width: 1, count: 1, signBits: 64},
		{name: "signed_byte_w", store: "strb w4", load: "ldrsb w9", width: 1, count: 1, signBits: 32},
		{name: "half", store: "strh w4", load: "ldrh w9", width: 2, count: 1},
		{name: "signed_half_x", store: "strh w4", load: "ldrsh x9", width: 2, count: 1, signBits: 64},
		{name: "signed_half_w", store: "strh w4", load: "ldrsh w9", width: 2, count: 1, signBits: 32},
		{name: "word", store: "str w4", load: "ldr w9", width: 4, count: 1},
		{name: "signed_word", store: "str w4", load: "ldrsw x9", width: 4, count: 1, signBits: 64},
		{name: "double", store: "str x4", load: "ldr x9", width: 8, count: 1},
		{name: "fp_s", store: "str s0", load: "ldr s2", width: 4, count: 1, floating: true},
		{name: "fp_d", store: "str d0", load: "ldr d2", width: 8, count: 1, floating: true},
		{name: "fp_q", store: "str q0", load: "ldr q2", width: 16, count: 1, floating: true},
		{name: "pair_x", store: "stp x4,x5", load: "ldp x9,x10", width: 8, count: 2},
		{name: "pair_w", store: "stp w4,w5", load: "ldp w9,w10", width: 4, count: 2},
		{name: "pair_sw", store: "stp w4,w5", load: "ldpsw x9,x10", width: 4, count: 2, signBits: 64},
		{name: "fp_pair_s", store: "stp s0,s1", load: "ldp s2,s3", width: 4, count: 2, floating: true},
		{name: "fp_pair_d", store: "stp d0,d1", load: "ldp d2,d3", width: 8, count: 2, floating: true},
		{name: "fp_pair_q", store: "stp q0,q1", load: "ldp q2,q3", width: 16, count: 2, floating: true},
	} {
		for _, mode := range []string{"offset", "pre_post", "post_pre", "unscaled"} {
			if mode == "unscaled" && shape.count != 1 {
				continue // Pair encodings have no unscaled-address sibling.
			}
			store, load := shape.store+",[sp,#16]", shape.load+",[sp,#16]"
			if mode == "pre_post" {
				store, load = shape.store+",[sp,#-32]!", shape.load+",[sp],#32"
			}
			if mode == "post_pre" {
				store, load = shape.store+",[sp],#32", shape.load+",[sp,#-32]!"
			}
			if mode == "unscaled" {
				store = strings.Replace(shape.store, "str", "stur", 1) + ",[sp,#9]"
				load = strings.Replace(shape.load, "ldr", "ldur", 1) + ",[sp,#9]"
			}
			cases = append(cases, arm64RawPrivateMemoryCase{
				name: "rawFrame_" + shape.name + "_" + mode, store: store, load: load,
				width: shape.width, count: shape.count, signBits: shape.signBits, floating: shape.floating,
			})
		}
	}
	return cases
}

// LLVM MC independently assembles each native memory spelling. Actual Go then
// assembles every raw WORD and its framed source epilogue. Each recovered form
// still goes through the regular width/sign/register-aware semantic lowerer.
func arm64RawPrivateFamilyFixture(t *testing.T) (*File, map[string]FuncSig, string, []arm64RawPrivateMemoryCase) {
	t.Helper()
	cases := arm64RawPrivateMemoryCases()
	var lines []string
	for _, tc := range cases {
		lines = append(lines, tc.store, tc.load)
	}
	words := assembleARM64LLVMWords(t, lines, "")
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, tc := range cases {
		prep := "MOVD (R0),R4\nMOVD 8(R0),R5\n"
		outputs := "MOVD R9,(R1)\n"
		if tc.count == 2 {
			outputs += "MOVD R10,8(R1)\n"
		}
		if tc.floating {
			prep = "FMOVQ (R0),F0\nFMOVQ 16(R0),F1\n"
			op := map[int]string{4: "FMOVS", 8: "FMOVD", 16: "FMOVQ"}[tc.width]
			outputs = op + " F2,(R1)\n"
			if tc.count == 2 {
				outputs += fmt.Sprintf("%s F3,%d(R1)\n", op, tc.width)
			}
		}
		// Keep tested stores below, rather than on top of, the original
		// R28/R27 spill. In particular a post-index store at SP must not
		// corrupt the real Go g register when the spill is later restored.
		body := "WORD $0xd10103ff\n" + prep +
			fmt.Sprintf("WORD $%#08x\nWORD $%#08x\n", words[2*index], words[2*index+1]) +
			outputs + "WORD $0x910103ff\n"
		// Do not overwrite the observed output with the fixture's pointer copy.
		fixture := arm64RawPrivateFrameFixture(tc.name, body)
		fixture = strings.Replace(fixture, "MOVD R0,(R1)\nWORD $0xa9457bfd", "WORD $0xa9457bfd", 1)
		source.WriteString(fixture)
		sigs[tc.name] = arm64RawPrivateFrameSignature(tc.name)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		if !arm64CallFrameUnexposed(fn) {
			for _, ins := range fn.Instrs {
				t.Logf("source %s -> decoded %s", ins.Raw, arm64ControlDecode(ins).Raw)
			}
			t.Fatalf("typed raw store/read lost its bounded private-frame proof: %s", fn.Sym)
		}
	}
	return file, sigs, source.String(), cases
}

func TestARM64RawPrivateFrameMemoryFamilyObjects(t *testing.T) {
	file, sigs, _, cases := arm64RawPrivateFamilyFixture(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw_frame_family.ll", "raw_frame_family.o", ir)
		})
	}
	t.Logf("actual Go + LLVM22 objects: %d raw scalar/GP-pair/FP-pair width/sign/offset/writeback variants", len(cases))
}

func TestARM64RawLDPSWPreservesCompletePairAddressGrammar(t *testing.T) {
	for _, tc := range []struct{ native, plan9 string }{
		{"ldpsw x9,x10,[sp,#16]", "LDPSW"},
		{"ldpsw x9,x10,[sp,#-32]!", "LDPSW.W"},
		{"ldpsw x9,x10,[sp],#32", "LDPSW.P"},
	} {
		word := assembleARM64LLVMWords(t, []string{tc.native}, "")[0]
		ins, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
		if err != nil {
			t.Fatal(err)
		}
		if ins.Op != Op(tc.plan9) || len(ins.Args) != 2 || ins.Args[1].Kind != OpRegList ||
			len(ins.Args[1].RegList) != 2 || ins.Args[1].RegList[0] != "R9" || ins.Args[1].RegList[1] != "R10" {
			t.Fatalf("LDPSW width/order/writeback changed: %s: %+v", tc.native, ins)
		}
	}
}

func TestARM64RawPrivateFrameMemoryGrammarRejectsUncertainEffects(t *testing.T) {
	for _, tc := range []struct {
		native      string
		mask, value uint32
	}{
		// LLVM rejects constrained-unpredictable source spellings. Change only
		// their encoded Rn or Rt2 field from a legal independent MC object.
		{native: "ldr x9,[x11],#8", mask: 31 << 5, value: 9 << 5},
		{native: "ldp x9,x10,[x11],#16", mask: 31 << 5, value: 9 << 5},
		{native: "str x9,[x11,#-8]!", mask: 31 << 5, value: 9 << 5},
		{native: "stp x9,x10,[x11,#-16]!", mask: 31 << 5, value: 9 << 5},
		{native: "ldp x9,x10,[sp,#16]", mask: 31 << 10, value: 9 << 10},
		{native: "ldp d0,d1,[sp,#16]", mask: 31 << 10},
		{native: "ldnp x9,x10,[sp,#16]"}, // No Go named non-temporal pair optab.
		{native: "stnp x9,x10,[sp,#16]"},
		{native: "ldr x9,[sp,x0]"},
		{native: "str x9,[sp,x0]"},
	} {
		word := assembleARM64LLVMWords(t, []string{tc.native}, "")[0]
		word = word&^tc.mask | tc.value
		source := arm64RawPrivateFrameFixture("rawUncertainMemory", fmt.Sprintf("ADD $16,RSP,R9\nWORD $%#08x\nMOVD $0,R9", word))
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if arm64CallFrameUnexposed(file.Funcs[0]) {
			t.Fatalf("unproven raw memory grammar acquired a private frame: %s masked %#08x", tc.native, word)
		}
	}
}
