package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These are the unchanged original format directories, not initialized
// programs. In particular, neither the native AX address nor vector inputs
// come from the Void declaration or the emitter's implementation slots.
func x86ImmediateBlendOriginalBareSource(t *testing.T, arch string) string {
	t.Helper()
	if arch == "386" {
		return `
TEXT immediatepackedblendforms386(SB),NOSPLIT,$0-0
	PBLENDW $0, X0, X1
	PBLENDW $255, (AX), X7
	BLENDPS $0, X0, X1
	BLENDPS $255, (AX), X7
	BLENDPD $0, X0, X1
	BLENDPD $255, (AX), X7
	RET
`
	}
	if arch != "amd64" {
		t.Fatal("original immediate blend directory has no such architecture", arch)
	}
	var source strings.Builder
	source.WriteString("TEXT immediatepackedblendforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PBLENDW", "BLENDPS", "BLENDPD"} {
		fmt.Fprintf(&source, "\t%s $0, X0, X1\n", op)
		fmt.Fprintf(&source, "\t%s $255, (AX), X15\n", op)
	}
	for _, op := range []string{"VPBLENDW", "VPBLENDD", "VBLENDPS", "VBLENDPD"} {
		fmt.Fprintf(&source, "\t%s $0, X0, X1, X2\n", op)
		fmt.Fprintf(&source, "\t%s $255, (AX), X1, X15\n", op)
		fmt.Fprintf(&source, "\t%s $1, Y0, Y1, Y2\n", op)
		fmt.Fprintf(&source, "\t%s $254, (AX), Y1, Y15\n", op)
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func x86ImmediateBlendOriginalBareRows(t *testing.T, arch string) (string, []Instr) {
	t.Helper()
	source := x86ImmediateBlendOriginalBareSource(t, arch)
	wantRows, wantHash := 22, "3f692f45ed4ff1cf08ff81919c4fcdf202c915c74016db5d298fea0d805583df"
	if arch == "386" {
		wantRows, wantHash = 6, "fde15efad285edfdc316851fe0e561752175a763cc24b684c52d928b916732a2"
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != wantHash {
		t.Fatal("original complete immediate blend source changed", arch)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != wantRows+2 {
		t.Fatal("original TEXT/row/RET inventory changed", arch, err)
	}
	return source, file.Funcs[0].Instrs[1 : wantRows+1]
}

func TestX86ImmediateBlendOriginalBareSourcesKeepGoObjectsAndContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, _ := x86ImmediateBlendOriginalBareRows(t, target.arch)
			// This helper first captures the actual complete Go object, then
			// requires all three public APIs to retain the missing-input Context.
			x86UnboundVoidFormatSources(t, source, target.arch, target.triple)
		})
	}
}

// Keep every original format in Go and LLVM objects without granting missing
// public inputs. The independently initialized counterpart below covers each
// original instruction through all three APIs and five physical targets.
func x86ImmediateBlendOriginalBareFormatObjects(t *testing.T, arch, triple string) {
	t.Helper()
	source, _ := x86ImmediateBlendOriginalBareRows(t, arch)
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	ir := x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			return c.lowerImmediatePackedBlend(instruction.Op, instruction)
		})
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete original blend format objects require LLVM22")
	}
	optimized := x86DwordProductIROptimize(t, ir)
	for _, pipeline := range []struct{ body, level string }{
		{ir, "-O0"}, {ir, "-O2"}, {optimized, "-O2"},
	} {
		x86PackedStringCompileObject(t, llc, triple, pipeline.body, pipeline.level)
	}
}

func x86ImmediateBlendOriginalRowInitialized(row Instr, index int, arch string) (string, string) {
	word, move, high := 8, "MOVQ", "Y15"
	if arch == "386" {
		word, move, high = 4, "MOVL", "Y7"
	}
	name := fmt.Sprintf("OriginalBlend%d", index)
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s a+%d(FP),AX\n%s b+%d(FP),BX\n",
		name, word*3, move, move, word, move, word*2)
	for _, register := range []string{"Y0", "Y1", "Y2", high} {
		fmt.Fprintf(&source, "VMOVUPS (BX),%s\n", register)
	}
	fmt.Fprintln(&source, row.Raw)
	destination := row.Args[len(row.Args)-1].Reg
	fmt.Fprintf(&source, "VMOVUPS Y%s,(DI)\nRET\n", destination[1:])
	return source.String(), fmt.Sprintf("func %s(out,a,b *[32]byte)\n", name)
}

func TestX86ImmediateBlendEveryOriginalRowHasInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete original-row objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			_, rows := x86ImmediateBlendOriginalBareRows(t, target.arch)
			var source, declarations strings.Builder
			for index, row := range rows {
				body, declaration := x86ImmediateBlendOriginalRowInitialized(row, index, target.arch)
				source.WriteString(body)
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("actual initialized counterpart lost an original blend row", err)
					}
					optimized := x86DwordProductIROptimize(t, ir)
					for _, pipeline := range []struct{ body, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {optimized, "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.body, pipeline.level)
					}
				})
			}
			// Remove only a required native input from otherwise identical
			// initialized programs. A missing address cannot be mistaken for
			// an absent unrelated vector producer or a faulty test declaration.
			for index, row := range rows {
				if row.Args[1].Kind != OpMem {
					continue
				}
				body, declaration := x86ImmediateBlendOriginalRowInitialized(row, index, target.arch)
				word, move := 8, "MOVQ"
				if target.arch == "386" {
					word, move = 4, "MOVL"
				}
				missing := strings.Replace(body, fmt.Sprintf("%s a+%d(FP),AX\n", move, word), "", 1)
				if missing == body {
					t.Fatal("required native input mutation did not apply")
				}
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, missing, declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original memory blend invented its removed address input", row.Raw, api, err)
					}
				}
			}
		})
	}
}
