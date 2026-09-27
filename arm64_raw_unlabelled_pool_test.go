package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64RawPoolControlFlowIR(t *testing.T, triple string) string {
	words := assembleARM64LLVMWords(t, []string{
		"adr x9, #52", "cbz x3, #32", "ldr w1, [x9]",
		"add x4, x3, x3, lsl #2", "sub x3, x3, #1", "cbnz x3, #-12",
		"mov x9, xzr", "str w1, [x0]", "ret",
		"ldr w1, [x9, #4]", "mov x9, xzr", "str w1, [x0]", "ret",
	}, "")
	words = append(words, 0x11223344, 0xaabbccdd)
	var source strings.Builder
	source.WriteString("TEXT branchpool(SB),$0-16\nMOVD out+0(FP),R0\nMOVD count+8(FP),R3\n")
	for _, word := range words {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"branchpool": {Name: "branchpool", Args: []LLVMType{Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "private constant [8 x i8]") {
		t.Fatal("missing proven data pool")
	}
	return ir
}

const arm64RawPoolControlFlowMain = `
#include <stdint.h>
extern void branchpool(uint32_t *, uint64_t);
int main(void) {
  for (unsigned count = 0; count < 5; count++) {
    uint32_t got = 0;
    branchpool(&got, count);
    if (got != (count ? 0x11223344U : 0xaabbccddU)) return 1;
  }
  return 0;
}
`

func TestARM64RawPoolControlFlowLLVM(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolControlFlowIR(t, triple)
			compileLLVMToObject(t, llc, triple, "branchpool.ll", "branchpool.o", ir)
			native := runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" ||
				runtime.GOOS == "linux" && triple == "aarch64-unknown-linux-gnu"
			if runtime.GOARCH == "arm64" && native {
				compileAndRunRuntimeTestForTarget(t, llc, clang, "branchpool", triple, ir, arm64RawPoolControlFlowMain, nil)
			}
		})
	}
}

func TestARM64RawPoolAddressAcrossControlFlow(t *testing.T) {
	lines := []string{
		"adr x9, #48", "cbz x3, #28",
		"ldr w1, [x9]", "add x4, x4, x5, lsl #2", "sub x3, x3, #1", "cbnz x3, #-12",
		"mov x9, xzr", "ret",
		"ldr w1, [x9, #4]", "ldr w2, [x0, x4, lsl #2]", "mov x9, xzr", "ret",
	}
	for _, test := range []struct {
		name, old, replacement string
		want                   bool
	}{
		{name: "loop-and-diamond", want: true},
		{"escape-one-edge", "mov x9, xzr", "str x9, [x0]", false},
		{"shifted-address", "add x4, x4, x5, lsl #2", "add x4, x4, x9, lsl #2", false},
		{"indexed-address", "ldr w2, [x0, x4, lsl #2]", "ldr w2, [x0, x9, lsl #2]", false},
		{"call-with-live-address", "add x4, x4, x5, lsl #2", "blr x5", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			asm := strings.Join(lines, "\n")
			if test.old != "" {
				asm = strings.Replace(asm, test.old, test.replacement, 1)
			}
			words := assembleARM64LLVMWords(t, strings.Split(asm, "\n"), "")
			var instructions []Instr
			for _, word := range words {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			}
			if got := arm64RawAddressOnlyLoaded(instructions, 0, len(instructions)); got != test.want {
				t.Fatalf("load-only proof = %v, want %v", got, test.want)
			}
		})
	}
}

const arm64RawUnlabelledPoolSource = `TEXT rawpool(SB),$0-8
MOVD out+0(FP),R0
WORD $0x10000109 // ADR X9, +32
WORD $0x1000010a // ADR X10, +32
WORD $0xb9400521 // LDR W1, [X9, #4]
WORD $0xb85fc142 // LDUR W2, [X10, #-4]
WORD $0x29000801 // STP W1, W2, [X0]
WORD $0xaa1f03e9 // MOV X9, XZR
WORD $0x9100800a // ADD X10, X0, #32 overwrites the pool pointer.
WORD $0xd65f03c0 // RET
WORD $0x11223344
WORD $0xaabbccdd
WORD $0x17b4a14d // Data that resembles a branch must not be decoded.
RET
`

func TestARM64RawUnlabelledPoolAliases(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUnlabelledPoolSource, true)
	file, err := Parse(ArchARM64, arm64RawUnlabelledPoolSource)
	if err != nil {
		t.Fatal(err)
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawpool": {Name: "rawpool", Args: []LLVMType{Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(ir, "private constant [12 x i8]") != 1 {
				t.Fatalf("pool aliases must share one contiguous global:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "rawpool.ll", "rawpool.o", ir)
			native := runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" ||
				runtime.GOOS == "linux" && triple == "aarch64-unknown-linux-gnu"
			if runtime.GOARCH == "arm64" && native {
				compileAndRunRuntimeTestForTarget(t, llc, clang, "rawpool", triple, ir, `
#include <stdint.h>
extern void rawpool(uint32_t *);
int main(void) {
  uint32_t result[2] = {0};
  rawpool(result);
  return result[0] != 0xaabbccdd || result[1] != 0x11223344;
}
`, nil)
			}
		})
	}
}

func TestARM64RawUnlabelledPoolRejectsCodeAndEscapedAddresses(t *testing.T) {
	for _, change := range [][2]string{
		{"0x10000109", "0x14000008"}, // Executable branch into the apparent pool.
		{"0xaa1f03e9", "0xf9000009"}, // Escape the address with STR X9, [X0].
		{"0xd65f03c0", "0xd503201f"}, // Fall through into the words.
	} {
		source := strings.Replace(arm64RawUnlabelledPoolSource, change[0], change[1], 1)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = prepareARM64RawPCRelative(file.Funcs[0])
		if err == nil {
			t.Errorf("unsafe pool %v was accepted", change)
		}
	}
}

func arm64RawVoidPoolIR(t *testing.T, triple string) string {
	t.Helper()
	source := strings.ReplaceAll(arm64RawUnlabelledPoolSource, "rawpool", "voidpool")
	source = strings.Replace(source, "0xaa1f03e9", "0xd503201f", 1)
	source = strings.Replace(source, "0x9100800a", "0xd503201f", 1)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "voidpool", Args: []LLVMType{Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"voidpool": sig}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "private constant [12 x i8]") {
		t.Fatal("missing proven data pool in a void function")
	}
	return ir
}

const arm64RawVoidPoolMain = `
#include <stdint.h>
extern void voidpool(uint32_t *);
int main(void) {
  uint32_t result[2] = {0};
  voidpool(result);
  return result[0] != 0xaabbccdd || result[1] != 0x11223344;
}
`

func TestARM64RawPoolExplicitVoidSignature(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawVoidPoolIR(t, triple)
			compileLLVMToObject(t, llc, triple, "voidpool.ll", "voidpool.o", ir)
			native := runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" ||
				runtime.GOOS == "linux" && triple == "aarch64-unknown-linux-gnu"
			if runtime.GOARCH == "arm64" && native {
				compileAndRunRuntimeTestForTarget(t, llc, clang, "voidpool", triple, ir, arm64RawVoidPoolMain, nil)
			}
		})
	}
}

func TestARM64RawPoolVoidReturnDoesNotHideEscapes(t *testing.T) {
	for _, test := range []struct {
		name   string
		ret    LLVMType
		custom bool
		frame  bool
		old    string
		word   string
	}{
		{name: "unknown-signature", ret: Void},
		{name: "register-result", ret: I64, frame: true},
		{name: "custom-register-ABI", ret: Void, custom: true, frame: true},
		{name: "stored-address", ret: Void, frame: true, old: "0xd503201f", word: "0xf9000009"},
		{name: "indirect-call", ret: Void, frame: true, old: "0xd503201f", word: "0xd63f00a0"},
		{name: "return-through-address", ret: Void, frame: true, old: "0xd65f03c0", word: "0xd65f0120"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.Replace(arm64RawUnlabelledPoolSource, "0xaa1f03e9", "0xd503201f", 1)
			if test.old != "" {
				source = strings.Replace(source, test.old, test.word, 1)
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := FuncSig{Name: "rawpool", Args: []LLVMType{Ptr}, Ret: test.ret}
			if test.frame {
				sig.Frame.Params = []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}
			}
			if test.custom {
				sig.ArgRegs = []Reg{"R0"}
			}
			if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawpool": sig}}); err == nil {
				t.Fatal("accepted an unproven or escaping pool address")
			}
		})
	}
	words := assembleARM64LLVMWords(t, []string{"adr x19, #12", "ldr x1, [x19]", "ret"}, "")
	var instructions []Instr
	for _, word := range words {
		instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
	}
	if arm64RawAddressOnlyLoadedWithExit(instructions, 0, len(instructions), (1<<18)-1) {
		t.Fatal("callee-preserved register must not become a terminal scratch kill")
	}
}

func TestARM64RawPoolLoadKillsAndPostIndexEffects(t *testing.T) {
	for _, test := range []struct {
		instruction string
		want        bool
	}{
		{"ldr x9, [x0]", true}, {"ldr w9, [x0]", true},
		{"ldrb w9, [x0]", true}, {"ldrh w9, [x0]", true},
		{"ldrsb x9, [x0]", true}, {"ldrsb w9, [x0]", true},
		{"ldrsh x9, [x0]", true}, {"ldrsh w9, [x0]", true}, {"ldrsw x9, [x0]", true},
		{"ldur x9, [x0]", true}, {"ldur w9, [x0]", true},
		{"ldurb w9, [x0]", true}, {"ldurh w9, [x0]", true},
		{"ldursb x9, [x0]", true}, {"ldursb w9, [x0]", true},
		{"ldursh x9, [x0]", true}, {"ldursh w9, [x0]", true}, {"ldursw x9, [x0]", true},
		{"csel x9, x0, x1, eq", true}, {"csinc x9, x0, x1, eq", true},
		{"csinv x9, x0, x1, eq", true}, {"csneg x9, x0, x1, eq", true},
		{"ldr x9, [x9]", true},
		{"ld1 {v0.16b}, [x0], x1\nmov x9, xzr", true},
		{"ld1 {v0.16b}, [x0], x9\nmov x9, xzr", false},
		{"ld1 {v0.16b}, [x9], x0\nmov x9, xzr", false},
		{"csel x9, x0, x9, eq", false}, {"csinc x9, x9, x1, eq", false},
		{"str x9, [x0]\nmov x9, xzr", false},
		{"ldp x9, x10, [x0]", true}, {"ldp x10, x9, [x0]", true},
		{"ldp w9, w10, [x0]", true}, {"ldp w10, w9, [x0]", true},
		{"ldnp x9, x10, [x0]", true}, {"ldnp x10, x9, [x0]", true},
		{"ldnp w9, w10, [x0]", true}, {"ldnp w10, w9, [x0]", true},
		{"ldpsw x9, x10, [x0]", true}, {"ldpsw x10, x9, [x0]", true},
		{"ldp x9, x10, [x0, #16]!", true}, {"ldp x10, x9, [x0], #16", true},
		{"ldp x9, x10, [x9]", true},
		{"ldp x0, x1, [x9], #16", false},
		{"ldp d9, d10, [x0]", false}, {"ldp q9, q10, [x0]", false},
		{"stp x9, x10, [x0]\nmov x9, xzr", false},
		{"stp x10, x9, [x0]\nmov x9, xzr", false},
		{"ldxr x0, [x9]\nmov x9, xzr", false}, // The exclusive monitor would retain the address.
		{"lsl x9, x0, #3", true}, {"lsl w9, w0, w1", true},
		{"lsr w9, w0, #3", true}, {"lsr x9, x0, x1", true},
		{"asr x9, x0, #3", true}, {"asr w9, w0, w1", true},
		{"ror w9, w0, #3", true}, {"ror x9, x0, x1", true},
		{"lsl x9, x9, #3", false}, {"lsr w9, w0, w9", false},
		{"fmov w9, s0", true}, {"fmov x9, d0", true},
		{"fmov d0, x9\nmov x9, xzr", false},
		{"ptrue p15.b\nmov x9, xzr", true},
		{"ptrue p0.h, vl4\nmov x9, xzr", true},
		{"ptrue p7.s\nmov x9, xzr", true},
		{"ptrue p8.d\nmov x9, xzr", true},
		{"orr z31.d, z30.d, z29.d\nmov x9, xzr", true},
		{"and z31.h, p7/m, z31.h, z30.h\nmov x9, xzr", true},
		{"eor z31.s, z31.s, #1\nmov x9, xzr", true},
		{"bic z31.d, z30.d, z29.d\nmov x9, xzr", true},
		{"add z31.b, z30.b, z29.b\nmov x9, xzr", true},
		{"add z31.h, p7/m, z31.h, z30.h\nmov x9, xzr", true},
		{"add z31.s, z31.s, #12\nmov x9, xzr", true},
		{"dup z31.d, x9\nmov x9, xzr", false},
		{"ld1b { z31.b }, p0/z, [x9]\nmov x9, xzr", false}, // Not a proven scalar load effect.
		{"add x9, x9, #0\nmov x9, xzr", true},
		{"sub x9, x9, #0, lsl #12\nmov x9, xzr", true},
		{"add w9, w9, #0\nmov x9, xzr", false},  // Truncates the address.
		{"adds x9, x9, #0\nmov x9, xzr", false}, // Exposes address bits through flags.
		{"add x9, x9, #40\nmov x9, xzr", false}, // Requires an offset/range proof.
		{"sub x9, x9, #40\nmov x9, xzr", false},
		{"index z31.s, #1, #1\nmov x9, xzr", true},
		{"index z31.d, x9, #1\nmov x9, xzr", false},
		{"index z31.d, #1, x9\nmov x9, xzr", false},
		{"cmpne p3.s, p0/z, z17.s, #0\nmov x9, xzr", true},
		{"cmpeq p15.d, p7/z, z31.d, z30.d\nmov x9, xzr", true},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			lines := []string{"adr x9, #64", "ldr w1, [x9]"}
			lines = append(lines, strings.Split(test.instruction, "\n")...)
			lines = append(lines, "ret")
			var instructions []Instr
			for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			}
			if got := arm64RawAddressOnlyLoaded(instructions, 0, len(instructions)); got != test.want {
				t.Fatalf("load-only proof=%v, want %v", got, test.want)
			}
		})
	}
}

func arm64RawPoolRegisterEffectsIR(t *testing.T, triple string) string {
	t.Helper()
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, test := range []struct {
		name    string
		effects []string
	}{
		{"pool_pair_first", []string{"ptrue p15.b", "ldp x19, x20, [x1]"}},
		{"pool_pair_second", []string{"ldp x20, x19, [x1]"}},
		{"pool_shift", []string{"lsl x19, x1, #3"}},
		{"pool_carry", []string{"adds x5, xzr, xzr", "adcs x19, x1, xzr"}},
		{"pool_float", []string{"fmov d0, x1", "fmov x19, d0"}},
		{"pool_umov", []string{"dup v0.4s, w2", "umov w19, v0.s[3]", "str w19, [x0, #4]"}},
		{"pool_smov", []string{"movi v0.16b, #128", "smov x19, v0.b[15]", "str w19, [x0, #4]"}},
		{"pool_sve", []string{
			"mov x3, #1", "ptrue p0.s", "dup z0.s, w2",
			"zip1 z0.s, z0.s, z0.s",
			"compact z1.s, p0, z0.s", "cnt z1.s, p0/m, z1.s",
			"addvl x5, x1, #2", "addpl x5, x5, #-8", "str z1, [x5]", "ldr z1, [x5]",
			"movprfx z2, z1", "asrd z2.s, p0/m, z2.s, #1",
			"dup z3.s, #1", "add z2.s, z2.s, z3.s",
			"whilelo p1.s, xzr, x3", "ands p1.b, p0/z, p1.b, p1.b", "cntp x4, p0, p1.s",
			"st1w {z2.s}, p1, [x0, x4, lsl #2]", "cntp x19, p0, p1.s",
		}},
	} {
		// R19 is deliberately outside every terminal-clobber mask: these
		// functions need an actual overwrite, not just a void return contract.
		lines := []string{fmt.Sprintf("adr x19, #%d", (4+len(test.effects))*4), "ldr w2, [x19]", "str w2, [x0]"}
		lines = append(lines, test.effects...)
		lines = append(lines, "ret")
		fmt.Fprintf(&source, "TEXT %s(SB),$0-16\nMOVD out+0(FP),R0\nMOVD restore+8(FP),R1\n", test.name)
		for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		source.WriteString("WORD $0x17b4a14d\nRET\n")
		sigs[test.name] = FuncSig{Name: test.name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}}}
	}
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64RawPoolRegisterEffectsLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolRegisterEffectsIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_effects.ll", "pool_effects.o", ir)
		})
	}
}

const arm64RawPoolRegisterEffectsMain = `
#include <stdint.h>
extern void pool_pair_first(uint32_t *, const uint64_t *);
extern void pool_pair_second(uint32_t *, const uint64_t *);
extern void pool_shift(uint32_t *, const uint64_t *);
extern void pool_float(uint32_t *, const uint64_t *);
extern void pool_sve(uint32_t *, const uint64_t *);
extern void pool_carry(uint32_t *, const uint64_t *);
extern void pool_umov(uint32_t *, const uint64_t *);
extern void pool_smov(uint32_t *, const uint64_t *);
int main(void) {
  uint64_t restore[512] = {0x123456789abcdef0ULL, 0xfedcba9876543210ULL};
  uint32_t result[13] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
  pool_pair_first(result + 1, restore);
  pool_pair_second(result + 2, restore);
  pool_shift(result + 3, restore);
  pool_float(result + 4, restore);
  pool_sve(result + 5, restore);
  pool_carry(result + 7, restore);
  pool_umov(result + 8, restore);
  pool_smov(result + 10, restore);
  for (unsigned i = 1; i < 6; i++) if (result[i] != 0x17b4a14d) return 1;
  unsigned count = 0;
  for (uint32_t value = 0x17b4a14d; value; value >>= 1) count += value & 1;
  return result[0] != 1 || result[6] != count / 2 + 1 || result[7] != 0x17b4a14d ||
         result[8] != 0x17b4a14d || result[9] != 0x17b4a14d ||
         result[10] != 0x17b4a14d || result[11] != 0xffffff80 || result[12] != 2;
}
`

func arm64RawPoolResultIR(t *testing.T, triple string) string {
	t.Helper()
	file, err := Parse(ArchARM64, `
TEXT pool_result(SB),$0-16
MOVD unused+0(FP), R1
	WORD $0x10000089 // ADR X9, #16
	WORD $0xf9400120 // LDR X0, [X9]
	WORD $0x91000129 // ADD X9, X9, #0: still the same non-result pointer.
WORD $0xd65f03c0 // RET: X0 is observable, X9 is not.
WORD $0x17b4a14d
WORD $0x11223344
RET
`)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "pool_result", Args: []LLVMType{Ptr}, Ret: I64, Frame: FrameLayout{
		Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
		Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
	}}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{"pool_result": sig}})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64RawPoolExplicitResultContract(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolResultIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_result.ll", "pool_result.o", ir)
		})
	}
}

func TestARM64RawPoolResultRegistersRemainObservable(t *testing.T) {
	const scratch = (1 << 18) - 1
	for _, test := range []struct {
		name    string
		ret     LLVMType
		results []FrameSlot
		want    uint32
	}{
		{"integer", I64, []FrameSlot{{Type: I64, Index: 0}}, scratch &^ 1},
		{"pointer", Ptr, []FrameSlot{{Type: Ptr, Index: 0}}, scratch &^ 1},
		{"float-frame-fallback", "double", []FrameSlot{{Type: "double", Index: 3}}, scratch &^ (1 << 3)},
		{"aggregate", "{ i64, double, ptr }", []FrameSlot{{Type: I64, Index: 0}, {Type: "double", Index: 1}, {Type: Ptr, Index: 2}}, scratch &^ 7},
		{"high-frame-fallback", I64, []FrameSlot{{Type: I64, Index: 9}}, scratch &^ (1 | 1<<9)},
		{"missing-result-contract", I64, nil, 0},
		{"unknown-result-type", "i128", []FrameSlot{{Type: "i128", Index: 0}}, 0},
		{"inconsistent-void", Void, []FrameSlot{{Type: Ptr, Index: 0}}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			sig := FuncSig{Ret: test.ret, Args: []LLVMType{Ptr}, Frame: FrameLayout{
				Params: []FrameSlot{{Type: Ptr, Index: 0, Field: -1}}, Results: test.results,
			}}
			mask := arm64RawPoolReturnClobbers(Func{ArgSize: 16}, sig)
			if mask != test.want {
				t.Fatalf("terminal-clobber mask=%#x, want %#x", mask, test.want)
			}
			for _, reg := range []int{0, 1, 2, 3, 9, 17, 19} {
				lines := []string{fmt.Sprintf("adr x%d, #12", reg), fmt.Sprintf("ldr d0, [x%d]", reg), "ret"}
				var instructions []Instr
				for _, word := range assembleARM64LLVMWords(t, lines, "") {
					instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
				}
				if got := arm64RawAddressOnlyLoadedWithExit(instructions, 0, len(instructions), mask); got != (test.want&(1<<reg) != 0) {
					t.Fatalf("incorrect pool proof for R%d result contract", reg)
				}
			}
		})
	}
}

const arm64RawPoolResultMain = `
#include <stdint.h>
extern uint64_t pool_result(void *);
int main(void) {
  return pool_result(0) != UINT64_C(0x1122334417b4a14d);
}
`
