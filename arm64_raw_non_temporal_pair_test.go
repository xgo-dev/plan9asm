package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawNonTemporalPairLLVMObjects(t *testing.T) {
	var asm []string
	for _, view := range []struct {
		register  string
		byteWidth int
	}{
		{"w", 4}, {"x", 8}, {"s", 4}, {"d", 8}, {"q", 16},
	} {
		for _, op := range []string{"ldnp", "stnp"} {
			for _, scale := range []int{-64, 0, 63} {
				asm = append(asm, fmt.Sprintf("%s %s1, %s2, [x10, #%d]",
					op, view.register, view.register, scale*view.byteWidth))
			}
		}
	}
	asm = append(asm, "ldnp wzr, w12, [sp, #204]", "stnp xzr, xzr, [x0, #-8]")
	words := assembleARM64LLVMWords(t, asm, "")
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM 22 llc and llvm-objdump are required")
	}
	var source strings.Builder
	source.WriteString("TEXT pairs(SB),4,$0-0\n")
	for index, word := range words {
		instruction := Instr{Op: OpWORD, Raw: fmt.Sprintf("WORD $%#08x", word),
			Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		if err := ProbeInstruction(ArchARM64, "arm64", instruction); err != nil {
			t.Errorf("%s (%#08x): %v", asm[index], word, err)
		}
		fmt.Fprintln(&source, instruction.Raw)
	}
	if t.Failed() {
		return
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"pairs": {Name: "pairs", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			object := compileLLVMToObject(t, llc, triple, "pair.ll", "pair.o", ir)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, objdump, "-d", object))
			if err != nil {
				t.Fatalf("inspect translated instructions: %v\n%s", err, output)
			}
			if loads, stores := strings.Count(string(output), "\tldnp\t"), strings.Count(string(output), "\tstnp\t"); loads != 16 || stores != 16 {
				t.Fatalf("objects need every original pair instruction, got %d loads and %d stores\n%s", loads, stores, output)
			}
		})
	}
}

func TestARM64RawNonTemporalPairWidthsAndEffects(t *testing.T) {
	for _, word := range []uint32{
		0x68400941, // reserved GP size
		0xe8400941, // reserved GP size
		0xec400941, // reserved SIMD size
		0x28400541, // duplicate GP load destination
		0x2c400541, // duplicate SIMD load destination
		0xa9400941, // ordinary offset LDP
		0xa8c00941, // post-index LDP
	} {
		if form, ok := decodeARM64RawNonTemporalPair(word); ok {
			t.Fatalf("%#08x outside defined non-temporal pairs: %+v", word, form)
		}
	}
	for _, test := range []struct {
		word   uint32
		width  int
		offset int64
		effect arm64RawContinuationEffects
	}{
		{0x28600941, 4, -256, arm64RawContinuationEffects{gpReads: 1 << 10, gpWrites: 1<<1 | 1<<2}},
		{0xa81f8941, 8, 504, arm64RawContinuationEffects{gpReads: 1<<10 | 1<<1 | 1<<2, stores: true}},
		{0xac600941, 16, -1024, arm64RawContinuationEffects{gpReads: 1 << 10}},
		{0x2859b3ff, 4, 204, arm64RawContinuationEffects{gpWrites: 1 << 12, readsSP: true}},
	} {
		form, ok := decodeARM64RawNonTemporalPair(test.word)
		effect, known := arm64RawContinuationEffectsForWord(test.word)
		if !ok || !known || form.view.bytes != test.width || form.offset != test.offset || effect != test.effect {
			t.Fatalf("%#08x: form=%+v, effects=%+v, known=%t", test.word, form, effect, known)
		}
	}
	file, err := Parse(ArchARM64, "TEXT pair(SB),4,$0-0\nWORD $0x28400941\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"pair": {Name: "pair", Ret: Void}}})
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("foreign target emitted native pair: IR=%t, err=%v", ir != "", err)
	}
}

func TestARM64RawNonTemporalPairPrivateFrameAndContinuation(t *testing.T) {
	words := assembleARM64LLVMWords(t, []string{
		"stnp x9, x10, [sp, #16]",
		"ldnp x2, x3, [sp, #16]",
		"stnp w9, w10, [sp, #16]",
		"ldnp w2, w3, [sp, #16]",
	}, "")
	state := arm64ControlState{
		regs: map[Reg]arm64ControlValue{
			"R9":  arm64ControlFromMap(map[string]bool{"label:first": true}),
			"R10": arm64ControlFromMap(map[string]bool{"label:second": true}),
			SP:    arm64ControlFromMap(map[string]bool{"sp:0": true}),
		},
		memory: make(map[string]arm64ControlValue),
	}
	var source strings.Builder
	source.WriteString("TEXT pair(SB),4,$32-0\n")
	for i, word := range words {
		ins := Instr{Op: OpWORD, Raw: fmt.Sprintf("WORD $%#08x", word),
			Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		decoded := arm64ControlDecode(ins)
		state.transfer(decoded, arm64ControlOp(decoded), false, nil)
		if i == 1 {
			for reg, label := range map[Reg]string{"R2": "label:first", "R3": "label:second"} {
				value := state.regs[reg]
				if arm64ControlCount(value) != 1 || !arm64ControlHas(value, label) {
					t.Fatalf("full pair lost %s in %s: %v", label, reg, value)
				}
			}
		}
		fmt.Fprintln(&source, ins.Raw)
	}
	for _, reg := range []Reg{"R2", "R3"} {
		if value := state.regs[reg]; !arm64ControlHas(value, "") {
			t.Fatalf("narrow pair invented an exact control identity in %s: %v", reg, value)
		}
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	if !arm64RawPrivateFrameUnexposed(file.Funcs[0]) {
		t.Fatal("pair accesses within the declared private frame did not retain the source proof")
	}
}

func TestARM64RawNonTemporalPairPreservesNZCV(t *testing.T) {
	const source = `TEXT pair(SB),4,$0-0
CMP R0, R0
WORD $0xa8400941 // LDNP x1, x2, [x10]
CSET EQ, R4
WORD $0xa8000941 // STNP x1, x2, [x10]
CSET EQ, R5
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
		Sigs: map[string]FuncSig{"pair": {Name: "pair", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "pair-nzcv.ll", "pair-nzcv.o", ir)
}

func TestARM64RawNonTemporalPairNativeRuntime(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("covered by the required Linux/QEMU runtime counterpart")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang is required")
	}
	runARM64RawNonTemporalPairs(t, testTargetTriple(runtime.GOOS, runtime.GOARCH), []string{clang}, nil)
}

func TestCrossLinuxRuntimeMatrixARM64RawNonTemporalPairs(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime owner requires Linux/amd64")
	}
	runARM64RawNonTemporalPairs(t, "aarch64-unknown-linux-gnu",
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func runARM64RawNonTemporalPairs(t *testing.T, triple string, compiler, runPrefix []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	var source, driver strings.Builder
	driver.WriteString("#include <string.h>\n#include <stdio.h>\n")
	sigs := make(map[string]FuncSig)
	var calls []string
	for _, view := range []struct {
		reg, snapshot, clobber string
		width                  int
	}{
		{"w", "x", "x", 4},
		{"x", "x", "x", 8},
		{"s", "q", "v", 4},
		{"d", "q", "v", 8},
		{"q", "q", "v", 16},
	} {
		name := "pair_" + view.reg
		load := fmt.Sprintf("ldnp %s1, %s2, [x10, #%d]", view.reg, view.reg, -64*view.width)
		store := fmt.Sprintf("stnp %s1, %s2, [x11, #%d]", view.reg, view.reg, 63*view.width)
		words := assembleARM64LLVMWords(t, []string{load, store}, "")
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVD input+0(FP), R10\nMOVD output+8(FP), R11\nMOVD observed+16(FP), R12\n", name)
		// Poison the previous upper bits so the snapshot detects a partial
		// write where W-register and scalar SIMD loads must zero-extend.
		if view.snapshot == "x" {
			source.WriteString("MOVD $-1, R1\nMOVD $-1, R2\n")
		} else {
			source.WriteString("VMOVI $255, V1.B16\nVMOVI $255, V2.B16\n")
		}
		fmt.Fprintf(&source, "WORD $%#08x\nWORD $%#08x\n", words[0], words[1])
		if view.snapshot == "x" {
			source.WriteString("STP (R1, R2), (R12)\n")
		} else {
			source.WriteString("VST1 [V1.B16, V2.B16], (R12)\n")
		}
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Type: Ptr, Field: -1},
				{Type: Ptr, Offset: 8, Index: 1, Field: -1},
				{Type: Ptr, Offset: 16, Index: 2, Field: -1},
			}}}
		fmt.Fprintf(&driver, "extern void %s(void *, void *, void *);\n", name)
		fmt.Fprintf(&driver, `static int verify_%s(void *in) {
  _Alignas(16) unsigned char want[2400], got[2400], wantRegs[32], gotRegs[32];
  memset(want, 0x5e, sizeof(want));
  memset(got, 0x5e, sizeof(got));
  memset(wantRegs, 0x76, sizeof(wantRegs));
  memset(gotRegs, 0x76, sizeof(gotRegs));
  __asm__ volatile("ldnp %[1]s1, %[1]s2, [%%0, #%[2]d]\n"
                   "stnp %[1]s1, %[1]s2, [%%1, #%[3]d]\n"
                   "stp %[4]s1, %[4]s2, [%%2]"
                   :: "r"(in), "r"(want + 1200), "r"(wantRegs)
                   : "%[5]s1", "%[5]s2", "memory");
  %[6]s(in, got + 1200, gotRegs);
  if (memcmp(want, got, sizeof(want)) || memcmp(wantRegs, gotRegs, sizeof(wantRegs))) {
    fputs("pair %[1]s: wrong memory or register bytes\n", stderr);
    return 1;
  }
  return 0;
}
`, view.reg, -64*view.width, 63*view.width, view.snapshot, view.clobber, name)
		calls = append(calls, fmt.Sprintf("      if (verify_%s(input + 1200)) return 1;\n", view.reg))
	}
	driver.WriteString(`int main(void) {
  _Alignas(16) unsigned char input[2400];
  unsigned long state = 17;
  for (unsigned n = 0; n < 32; ++n) {
    for (unsigned i = 0; i < sizeof(input); ++i) {
      state = state * 1664525 + 1013904223;
      input[i] = state >> 19;
    }
`)
	driver.WriteString(strings.Join(calls, ""))
	driver.WriteString("  }\n  return 0;\n}\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, optimization := range []int{0, 2} {
		compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_non_temporal_pair", triple, ir, driver.String(), runPrefix, optimization)
	}
}
