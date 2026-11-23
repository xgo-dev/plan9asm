package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

type arm64UnprivilegedTransferSample struct {
	assembly string
	mnemonic string
	offset   int
	bytes    int
	base     int
	data     int
	store    bool
}

func arm64UnprivilegedTransferSamples(stack bool) []arm64UnprivilegedTransferSample {
	var samples []arm64UnprivilegedTransferSample
	for _, op := range []struct {
		mnemonic, bank string
		bytes          int
	}{
		{"ldtrb", "w", 1}, {"ldtrh", "w", 2}, {"ldtr", "w", 4}, {"ldtr", "x", 8},
		{"ldtrsb", "w", 1}, {"ldtrsb", "x", 1}, {"ldtrsh", "w", 2}, {"ldtrsh", "x", 2},
		{"ldtrsw", "x", 4}, {"sttrb", "w", 1}, {"sttrh", "w", 2}, {"sttr", "w", 4}, {"sttr", "x", 8},
	} {
		for _, offset := range []int{-256, 0, 255} {
			for _, registers := range []struct {
				data, base         int
				dataName, baseName string
			}{{0, 1, "0", "x1"}, {1, 1, "1", "x1"}, {31, 1, "zr", "x1"}, {31, 31, "zr", "sp"}} {
				if registers.base == 31 && !stack {
					continue
				}
				samples = append(samples, arm64UnprivilegedTransferSample{
					assembly: fmt.Sprintf("%s %s%s, [%s, #%d]", op.mnemonic, op.bank, registers.dataName, registers.baseName, offset),
					mnemonic: op.mnemonic, offset: offset, bytes: op.bytes,
					base: registers.base, data: registers.data, store: strings.HasPrefix(op.mnemonic, "st"),
				})
			}
		}
	}
	return samples
}

func assembleARM64UnprivilegedTransfers(t *testing.T, samples []arm64UnprivilegedTransferSample) []uint32 {
	t.Helper()
	lines := make([]string, len(samples))
	for i, sample := range samples {
		lines[i] = sample.assembly
	}
	return assembleARM64LLVMWords(t, lines, "")
}

func TestARM64UnprivilegedTransferLLVMMatrix(t *testing.T) {
	samples := arm64UnprivilegedTransferSamples(true)
	words := assembleARM64UnprivilegedTransfers(t, samples)
	if len(words) != 156 {
		t.Fatalf("got %d encodings, want 156", len(words))
	}
	var source strings.Builder
	source.WriteString("TEXT unprivilegedMatrix(SB),4,$0-0\n")
	expected := make(map[string]int)
	for i, sample := range samples {
		line := fmt.Sprintf("WORD $%#08x", words[i])
		ins := Instr{Op: OpWORD, Raw: line, Args: []Operand{{Kind: OpImm, Imm: int64(words[i])}}}
		form, known := decodeARM64RawUnprivilegedTransfer(words[i])
		if !known || form.op.mnemonic != sample.mnemonic || form.offset != int64(sample.offset) ||
			form.bytes != sample.bytes || form.base != sample.base || form.data != sample.data || form.store != sample.store {
			t.Errorf("%s: typed form %+v, recognized %t", sample.assembly, form, known)
		}
		want := arm64RawContinuationEffects{readsSP: sample.base == 31, stores: sample.store}
		if sample.base != 31 {
			want.gpReads = 1 << sample.base
		}
		if sample.data != 31 {
			if sample.store {
				want.gpReads |= 1 << sample.data
			} else {
				want.gpWrites = 1 << sample.data
			}
		}
		if effect, ok := arm64RawContinuationEffectsForWord(words[i]); !ok || effect != want {
			t.Errorf("%s: effect %+v, want %+v", sample.assembly, effect, want)
		}
		probe := ProbeInstruction(ArchARM64, "arm64", ins)
		if sample.base == 31 {
			if !errors.Is(probe, ErrProbeNeedsContext) || !strings.Contains(probe.Error(), "SP") {
				t.Errorf("%s must require physical SP: %v", sample.assembly, probe)
			}
			continue
		}
		if probe != nil {
			t.Errorf("%s: %v", sample.assembly, probe)
		}
		fmt.Fprintln(&source, line)
		expected[sample.mnemonic]++
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM 22 llc and llvm-objdump are required")
	}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"unprivilegedMatrix": {Name: "unprivilegedMatrix", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			object := compileLLVMToObject(t, llc, triple, "unprivileged.ll", "unprivileged.o", ir)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			code, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, objdump, "-d", object))
			if err != nil {
				t.Fatalf("inspect translated unprivileged instructions: %v\n%s", err, code)
			}
			for mnemonic, count := range expected {
				if got := strings.Count(string(code), "\t"+mnemonic+"\t"); got != count {
					t.Errorf("%s count %d, want %d", mnemonic, got, count)
				}
			}
		})
	}
}

func TestARM64UnprivilegedTransferRejectsAdjacentEncodings(t *testing.T) {
	for word, reason := range map[uint32]string{
		0xb8400020: "LDUR immediate",
		0xb8400420: "post-index LDR",
		0xb8400c20: "pre-index LDR",
		0xbc400820: "reserved SIMD encoding",
		0xb8c00820: "reserved word signed-to-W load",
		0xf8800820: "reserved doubleword signed load",
		0xf8c00820: "reserved doubleword signed load",
	} {
		if form, ok := decodeARM64RawUnprivilegedTransfer(word); ok {
			t.Errorf("%s (%#08x) decoded as %+v", reason, word, form)
		}
	}
}

func TestNativeARM64UnprivilegedTransferEncodings(t *testing.T) {
	samples := arm64UnprivilegedTransferSamples(true)
	words := assembleARM64UnprivilegedTransfers(t, samples)
	var source strings.Builder
	source.WriteString("TEXT transfer(SB),516,$0-0\n")
	for _, word := range words {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	words = append(words, 0xd65f03c0)
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			original := goAssemblerTextBytes(t, source.String(), goos, "arm64")
			opts := NativeOptions{
				GOOS: goos, GOARCH: "arm64", PackagePath: "probe",
				CodeEntries: map[string]string{"transfer": "native_transfer"},
			}
			assembly, _, err := TranslateNativeSource([]byte(source.String()), opts)
			if err != nil {
				t.Fatal(err)
			}
			var instructions []string
			for _, line := range strings.Split(assembly, "\n") {
				if strings.HasPrefix(line, "\t") {
					instructions = append(instructions, strings.TrimSpace(line))
				}
			}
			codeSize := 4 * len(words)
			if len(instructions) != len(words) || len(original) < codeSize || len(original) > (codeSize+15)&^15 {
				t.Fatalf("got %d native instructions and %d Go bytes for %d source words", len(instructions), len(original), len(words))
			}
			// cmd/asm can pad the end of TEXT to its 16-byte alignment.
			for _, padding := range original[codeSize:] {
				if padding != 0 {
					t.Fatalf("unexpected Go TEXT suffix %x", original[codeSize:])
				}
			}
			for i, actual := range assembleARM64LLVMWords(t, instructions, "") {
				if want := binary.LittleEndian.Uint32(original[i*4:]); actual != want || want != words[i] {
					t.Errorf("instruction %d (%s) encoded as %#08x, Go %#08x, input %#08x", i, instructions[i], actual, want, words[i])
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64NativeUnprivilegedStack(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	goos := "linux"
	if strings.Contains(triple, "apple") {
		goos = "darwin"
	}
	const source = `TEXT transfer(SB),516,$0-0
SUB $16, RSP
WORD $0xf8008be0 // sttr x0, [sp, #8]
WORD $0x38009bff // sttrb wzr, [sp, #9]
WORD $0x38808be2 // ldtrsb x2, [sp, #8]
MOVD R2, (R1)
WORD $0xf8408be0 // ldtr x0, [sp, #8]
ADD $16, RSP
RET
`
	const driver = `#include <stdint.h>
extern uint64_t stack_transfer(uint64_t value, int64_t *signed_byte);
int main(void) {
  int64_t signed_byte;
  if (stack_transfer(0x123456789abcde80ULL, &signed_byte) != 0x123456789abc0080ULL || signed_byte != -128)
    return 1;
  if (stack_transfer(0xfedcba987654327fULL, &signed_byte) != 0xfedcba987654007fULL || signed_byte != 127)
    return 2;
  return 0;
}`
	requireARM64GoAssemblerResult(t, source, true)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	mod, err := TranslateNativeModule(ctx, []byte(source), NativeOptions{
		GOOS: goos, GOARCH: "arm64", PackagePath: "probe",
		CodeEntries: map[string]string{"transfer": "stack_transfer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Dispose()
	for _, opt := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", opt), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_native_unprivileged_stack",
				triple, mod.String(), driver, runner, opt)
		})
	}
}

func TestARM64UnprivilegedTransferPreservesContinuationMemoryWidths(t *testing.T) {
	words := assembleARM64LLVMWords(t, []string{
		"sttr x9, [x1, #16]",
		"ldtr x2, [x1, #16]",
		"ldtrsw x3, [x1, #20]",
		"sttrb wzr, [x1, #23]",
		"ldtr x4, [x1, #16]",
	}, "")
	state := arm64ControlState{
		regs: map[Reg]arm64ControlValue{
			"R1": arm64ControlFromMap(map[string]bool{"sp:0": true}),
			"R9": arm64ControlFromMap(map[string]bool{"label:resume": true}),
		},
		memory: make(map[string]arm64ControlValue),
	}
	for _, word := range words {
		ins := Instr{Op: OpWORD, Raw: fmt.Sprintf("WORD $%#08x", word),
			Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
		decoded := arm64ControlDecode(ins)
		state.transfer(decoded, arm64ControlOp(decoded), false, nil)
	}
	if value := state.regs["R2"]; arm64ControlCount(value) != 1 || !arm64ControlHas(value, "label:resume") {
		t.Fatalf("full-width load lost saved continuation: %v", value)
	}
	if value := state.regs["R3"]; !arm64ControlHas(value, "code-derived:") || !arm64ControlHas(value, "") {
		t.Fatalf("partial sign-extending load invented an exact continuation: %v", value)
	}
	if value := state.regs["R4"]; !arm64ControlHas(value, "") {
		t.Fatalf("overlapping byte store preserved an exact continuation: %v", value)
	}
}

func TestCrossLinuxRuntimeMatrixARM64UnprivilegedTransfers(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	samples := arm64UnprivilegedTransferSamples(false)
	words := assembleARM64UnprivilegedTransfers(t, samples)
	var source, driver, checks strings.Builder
	driver.WriteString(`
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void (*transfer_fn)(void *, uint64_t *, uint64_t, uint64_t);
static int check(transfer_fn translate, transfer_fn original, const char *instruction) {
  const uint64_t values[] = {0, UINT64_MAX, 0x8000000080808080ULL, 0x123456789abcdef0ULL};
  for (unsigned row = 0; row < 16; ++row) {
    unsigned char memory[528], initial[528], want_memory[528];
    uint64_t got[2] = {0}, want[2] = {0};
    for (unsigned i = 0; i < sizeof(memory); ++i)
      initial[i] = (unsigned char)(i * 13 + (row & 1 ? 0x80 : 0));
    uint64_t flags = (uint64_t)row << 28;
    uint64_t value = values[(row >> 1) & 3];
    memcpy(memory, initial, sizeof(memory));
    original(memory + 256, want, value, flags);
    memcpy(want_memory, memory, sizeof(memory));
    // Restore the same address so stores of an aliased base remain comparable.
    memcpy(memory, initial, sizeof(memory));
    translate(memory + 256, got, value, flags);
    if (memcmp(got, want, sizeof(got)) || memcmp(memory, want_memory, sizeof(memory))) {
      fprintf(stderr, "%s row %u: data=%llx want %llx NZCV=%llx want %llx, same memory=%d\n",
              instruction, row, (unsigned long long)got[0], (unsigned long long)want[0],
              (unsigned long long)got[1], (unsigned long long)want[1],
              !memcmp(memory, want_memory, sizeof(memory)));
      return 1;
    }
  }
  return 0;
}
`)
	sigs := make(map[string]FuncSig)
	for i, sample := range samples {
		name := fmt.Sprintf("unprivileged%d", i)
		goReg, nativeReg := fmt.Sprintf("R%d", sample.data), fmt.Sprintf("x%d", sample.data)
		if sample.data == 31 {
			goReg, nativeReg = "ZR", "xzr"
		}
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-32
MOVD input+0(FP), R1
MOVD out+8(FP), R2
MOVD value+16(FP), R0
MOVD flags+24(FP), R3
MSR R3, NZCV
WORD $%#08x
MOVD %s, (R2)
MRS NZCV, R3
MOVD R3, 8(R2)
RET
`, name, words[i], goReg)
		sigs[name] = sigWithClassicFrame(name, []LLVMType{Ptr, Ptr, I64, I64}, Void)
		fmt.Fprintf(&driver, `extern void %[1]s(void *, uint64_t *, uint64_t, uint64_t);
static void original%[2]d(void *base, uint64_t *out, uint64_t value, uint64_t flags) {
  uint64_t old, data, status;
  __asm__ volatile("mrs %%0, nzcv\nmsr nzcv, %%5\n"
                   "mov x1, %%3\nmov x0, %%4\n.inst %#[3]x\n"
                   "mov %%1, %[4]s\nmrs %%2, nzcv\nmsr nzcv, %%0"
                  : "=&r"(old), "=&r"(data), "=&r"(status)
                  : "r"(base), "r"(value), "r"(flags)
                  : "x0", "x1", "cc", "memory");
  out[0] = data;
  out[1] = status;
}
`, name, i, words[i], nativeReg)
		fmt.Fprintf(&checks, "  if (check(%s, original%d, %q)) return 1;\n", name, i, sample.assembly)
	}
	driver.WriteString("int main(void) {\n" + checks.String() + "  return 0;\n}\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", opt), func(t *testing.T) {
			input := ir
			if opt == 2 {
				input = armFloatEffectOptimizedIR(t, ir)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_unprivileged",
				triple, input, driver.String(), runner, opt)
		})
	}
}
