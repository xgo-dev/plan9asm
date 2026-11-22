package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func packedDataBPFixture(name, instruction string) (string, string) {
	source := fmt.Sprintf(`TEXT ·%s(SB),4,$8-16
MOVQ memory+0(FP),BP
MOVQ out+8(FP),DI
MOVQ $5,DX
VPXORD Z1,Z1,Z1
VPXORD Z2,Z2,Z2
MOVL $-1,AX
KMOVD AX,K1
%s
VMOVUPS Z2,(DI)
RET
`, name, instruction)
	return source, fmt.Sprintf("func %s(memory *[80]byte, out *[64]byte)\n", name)
}

func TestX86PackedDataBPCompleteConflictFunnelObjects(t *testing.T) {
	const address = "-17(BP)(DX*4)"
	var instructions []string
	for _, row := range x86ConflictFunnelRows() {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, form := range []struct{ suffix, mask string }{
				{"", ""}, {"", "K1,"}, {".Z", "K1,"},
				{".BCST", ""}, {".BCST", "K1,"}, {".BCST.Z", "K1,"},
			} {
				if row.bits == 16 && strings.HasPrefix(form.suffix, ".BCST") {
					continue
				}
				instructions = append(instructions, x86ConflictFunnelInstruction(
					row.op+form.suffix, bank, address, form.mask, row.unary, row.variable))
			}
		}
	}
	if len(instructions) != 216 {
		t.Fatalf("unexpected packed memory form count: %d", len(instructions))
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("packed data BP objects require LLVM 22")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // The mode32 BP already uses the ordinary GP route.
		}
		t.Run(target.triple, func(t *testing.T) {
			for start := 0; start < len(instructions); start += 36 {
				end := start + 36
				t.Run(fmt.Sprint(start), func(t *testing.T) {
					var src, decl strings.Builder
					for index, instruction := range instructions[start:end] {
						text, sig := packedDataBPFixture(fmt.Sprint("Value", start+index), instruction)
						src.WriteString(text)
						decl.WriteString(sig)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, src.String())
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, src.String(), decl.String(), target.arch, target.triple, api)
						if err != nil {
							t.Fatalf("%s: %v", api, err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					}
				})
			}
		})
	}
}

func TestX86PackedDataBPRejectsUnprovedEffect(t *testing.T) {
	for _, instruction := range []string{
		"VPSHLDQ.Z $7,-17(BP)(DX*4),Z1,K1,Z2",
		"VPCONFLICTQ.Z -17(BP)(DX*4),K1,Z2",
	} {
		source, declaration := packedDataBPFixture("Value", instruction)
		for _, missing := range []string{"MOVQ memory+0(FP),BP", "MOVQ $5,DX", "KMOVD AX,K1"} {
			t.Run(instruction+"/"+missing, func(t *testing.T) {
				unproved := strings.Replace(source, missing+"\n", "", 1)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, unproved, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s admitted an unproved packed input: %v", api, err)
					}
				}
			})
		}
	}
}
