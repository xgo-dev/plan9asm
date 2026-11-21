package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64FloatPairwiseStatus(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·pairwise(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	MOVD 32(R0), R2
	MRS FPCR, R10
	MRS FPSR, R11
	MSR R2, FPCR
	MSR ZR, FPSR
	VLD1 (R0), [V0.B16, V1.B16]
	VFADDP V1.S2, V0.S2, V2.S2
	WORD $0x7e30c803 // FMAXNMP S3, V0.2S, result intentionally dead
	WORD $0x7e30c824 // FMAXNMP S4, V1.2S, result intentionally dead
	MRS FPSR, R2
	MSR R11, FPSR
	MSR R10, FPCR
	MOVD R2, (R1)
	ADD $8, R1
	VST1 [V2.B16], (R1)
	RET
`
	const original = `package main
import "fmt"
func pairwise(*[5]uint64, *[3]uint64)
func main() {
	input := [5]uint64{0x338000003f800000, 0, 0x400000007f800001, 0, 1<<22}
	var got [3]uint64
	pairwise(&input, &got)
	want := [3]uint64{0x11, 0x7fc000013f800001, 0}
	if got != want { panic(fmt.Sprintf("got %x want %x", got, want)) }
}
`
	// The minimum Go SDK predates the VFADDP spelling. The independently
	// assembled architectural word executes the identical operand order.
	originalSource := strings.Replace(source, "VFADDP V1.S2, V0.S2, V2.S2", "WORD $0x2e21d402", 1)
	runARM64GoInternalOracle(t, originalSource, original, len(runner) != 0)
	file, err := Parse(ArchARM64, strings.ReplaceAll(source, "·pairwise", "pairwise"))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pairwise": sigWithClassicFrame("pairwise", []LLVMType{Ptr, Ptr}, Void)},
	})
	if err != nil {
		t.Fatal(err)
	}
	const driver = `#include <inttypes.h>
#include <stdio.h>
extern void pairwise(uint64_t *, uint64_t *);
int main(void) {
  uint64_t input[] = {0x338000003f800000, 0, 0x400000007f800001, 0, 1<<22};
  uint64_t got[3] = {0};
  pairwise(input, got);
  if (got[0] == 0x11 && got[1] == 0x7fc000013f800001 && got[2] == 0) return 0;
  fprintf(stderr, "pairwise status/result: %" PRIx64 " %" PRIx64 " %" PRIx64 "\n", got[0], got[1], got[2]);
  return 1;
}
`
	optimized := armFloatEffectOptimizedIR(t, ir)
	for _, opt := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", opt), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_pairwise_status", triple,
				optimized, driver, runner, opt)
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64FloatPairwiseFormats(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	type shape struct {
		bits, lanes int
		scalar      bool
		suffix      string
	}
	shapes := []shape{
		{16, 2, true, "h"}, {32, 2, true, "s"}, {64, 2, true, "d"},
		{16, 4, false, "h"}, {16, 8, false, "h"},
		{32, 2, false, "s"}, {32, 4, false, "s"}, {64, 2, false, "d"},
	}
	ops := []struct {
		mnemonic string
		pair     func(int, int) int
	}{
		{"faddp", func(a, b int) int { return a + b }},
		{"fmaxp", maxTestPairwise},
		{"fminp", minTestPairwise},
		{"fmaxnmp", maxTestPairwise},
		{"fminnmp", minTestPairwise},
	}
	var nativeInstructions []string
	for _, op := range ops {
		for _, size := range shapes {
			if size.scalar {
				nativeInstructions = append(nativeInstructions, op.mnemonic+" "+size.suffix+"0, v0.2"+size.suffix)
			} else {
				layout := fmt.Sprintf(".%d%s", size.lanes, size.suffix)
				nativeInstructions = append(nativeInstructions, op.mnemonic+" v0"+layout+", v0"+layout+", v1"+layout)
			}
		}
	}
	words := assembleARM64LLVMWords(t, nativeInstructions, "+fullfp16")
	var source, original, goMain, cMain strings.Builder
	sigs := map[string]FuncSig{}
	goMain.WriteString("package main\nimport \"fmt\"\n")
	cMain.WriteString("#include <inttypes.h>\n#include <stdio.h>\n")
	const prologue = `	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	MRS FPCR, R10
	MRS FPSR, R11
	MOVD $0x2000000, R2 // default NaN makes the expected bits independent of payload
	MSR R2, FPCR
	MSR ZR, FPSR
	VLD1 (R0), [V0.B16, V1.B16]
`
	const epilogue = `
	MRS FPSR, R2
	MSR R11, FPSR
	MSR R10, FPCR
	MOVD R2, (R1)
	ADD $8, R1
	VST1 [V0.B16], (R1)
	RET
`
	type observation struct {
		name   string
		input  [4]uint64
		output [4]uint64
	}
	var observations []observation
	for fi, word := range words {
		op, size := ops[fi/len(shapes)], shapes[fi%len(shapes)]
		raw := fmt.Sprintf("WORD $%#08x", word)
		forms := []string{raw}
		if !size.scalar && size.bits != 16 {
			layout := strings.ToUpper(size.suffix) + fmt.Sprint(size.lanes)
			forms = append(forms, fmt.Sprintf("V%s V1.%s, V0.%s, V0.%s", strings.ToUpper(op.mnemonic), layout, layout, layout))
		}
		for syntax, ins := range forms {
			name := fmt.Sprintf("observe%d_%d", fi, syntax)
			fmt.Fprintf(&source, "TEXT %s(SB),$0-16\n%s\t%s%s", name, prologue, ins, epilogue)
			fmt.Fprintf(&original, "TEXT ·%s(SB),$0-16\n%s\t%s%s", name, prologue, raw, epilogue)
			sigs[name] = sigWithClassicFrame(name, []LLVMType{Ptr, Ptr}, Void)
			fmt.Fprintf(&goMain, "func %s(*[4]uint64, *[4]uint64)\n", name)
			fmt.Fprintf(&cMain, "extern void %s(uint64_t *, uint64_t *);\n", name)

			values := [2][8]int{{1, 2, 2, 4, 4, 8, 8, 1}, {4, 8, 8, 1, 1, 2, 2, 4}}
			var row observation
			row.name, row.output[3] = name, 0xabcdef1234567890
			for bank, lanes := range values {
				for lane, value := range lanes[:size.lanes] {
					putTestPairwiseLane(row.input[2*bank:], size.bits, lane, testPairwiseFloatBits(size.bits, value))
				}
			}
			resultBanks, resultLanes := 2, size.lanes/2
			if size.scalar {
				resultBanks = 1
			}
			for bank := 0; bank < resultBanks; bank++ {
				for lane := 0; lane < resultLanes; lane++ {
					value := op.pair(values[bank][2*lane], values[bank][2*lane+1])
					putTestPairwiseLane(row.output[1:], size.bits, bank*resultLanes+lane, testPairwiseFloatBits(size.bits, value))
				}
			}
			observations = append(observations, row)
			signalingNaN, defaultNaN := uint64(0x7c01), uint64(0x7e00)
			if size.bits == 32 {
				signalingNaN, defaultNaN = 0x7f800001, 0x7fc00000
			} else if size.bits == 64 {
				signalingNaN, defaultNaN = 0x7ff0000000000001, 0x7ff8000000000000
			}
			putTestPairwiseLane(row.input[:], size.bits, 0, signalingNaN)
			putTestPairwiseLane(row.output[1:], size.bits, 0, defaultNaN)
			row.output[0] = 1
			observations = append(observations, row)
		}
	}
	goMain.WriteString("func main() {\n")
	cMain.WriteString("int main(void) {\n")
	for i, row := range observations {
		in, out := testPairwiseWords(row.input), testPairwiseWords(row.output)
		fmt.Fprintf(&goMain, `{
			input, want := [4]uint64{%s}, [4]uint64{%s}
			got := [4]uint64{0,0,0,want[3]}
			%s(&input, &got)
			if got != want { panic(fmt.Sprintf("row %d got %%x want %%x", got, want)) }
		}
`, in, out, row.name, i)
		fmt.Fprintf(&cMain, `{
			uint64_t input[4] = {%s}, want[4] = {%s}, got[4] = {0,0,0,want[3]};
			%s(input, got);
			for (int j = 0; j < 4; j++) if (got[j] != want[j]) {
				fprintf(stderr,"row %d word %%d got %%" PRIx64 " want %%" PRIx64 "\n", j, got[j], want[j]);
				return 1;
			}
		}
`, in, out, row.name, i)
	}
	goMain.WriteString("}\n")
	cMain.WriteString("return 0;\n}\n")
	runARM64GoInternalOracle(t, original.String(), goMain.String(), len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"unoptimized", ir}, {"optimized", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/backend_O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_pairwise_formats", triple, variant.ir, cMain.String(), runner, level)
				t.Logf("matched original Go for %d finite and signaling-NaN observations", len(observations))
			})
		}
	}
}

func minTestPairwise(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxTestPairwise(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func testPairwiseFloatBits(bits, value int) uint64 {
	switch bits {
	case 16:
		single := math.Float32bits(float32(value))
		return uint64(((single>>23)-112)<<10 | (single&0x7fffff)>>13)
	case 32:
		return uint64(math.Float32bits(float32(value)))
	default:
		return math.Float64bits(float64(value))
	}
}

func putTestPairwiseLane(buffer []uint64, width, lane int, value uint64) {
	offset := width * lane
	word, bit := offset/64, offset%64
	mask := (uint64(1)<<width - 1) << bit
	buffer[word] = buffer[word]&^mask | value<<bit
}

func testPairwiseWords(words [4]uint64) string {
	return fmt.Sprintf("%#x,%#x,%#x,%#x", words[0], words[1], words[2], words[3])
}
