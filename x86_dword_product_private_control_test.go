package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86DwordProductRawPrivateFlagsDoNotInventInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix := goWordSize(target.arch), "Q"
		if word == 4 {
			suffix = "L"
		}
		for _, name := range []string{"VPMULDQ", "VPMULUDQ"} {
			for _, seed := range []string{"", "XORL AX,AX\n", "XORL AX,AX\nCLD\n"} {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nVPXOR X0,X0,X0\nVPXOR X1,X1,X1\n%s%s"+
					"PUSHF%s\nPOP%s AX\nMOV%s AX,ret+0(FP)\nRET\n", word, seed,
					x86RawNumericalInstruction(t, target.arch, name+" X0,X1,X2"), suffix, suffix, suffix)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uintptr", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("raw product invented missing full-FLAGS inputs", target.triple, name, seed, api, err)
					}
				}
			}
		}
	}
}

func TestX86DwordProductRawPrivateFlagsFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, suffix, move := goWordSize(target.arch), "Q", "MOVQ"
			if word == 4 {
				suffix, move = "L", "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86FixedBinaryValueRows(target.arch,
				[]string{"VPMULDQ", "VPMULUDQ", "VPMULDQ.BCST", "VPMULUDQ.BCST"}) {
				body, declaration := x86FixedBinaryValueFixture(target.arch, row.op, row.bank, row.mode, false)
				instruction := ""
				for _, line := range strings.Split(body, "\n") {
					if strings.HasPrefix(line, "VPMULDQ") || strings.HasPrefix(line, "VPMULUDQ") {
						instruction = line
					}
				}
				if instruction == "" {
					t.Fatal("complete initialized product source lost its operation")
				}
				raw := x86RawNumericalInstruction(t, target.arch, instruction)
				body = strings.Replace(body, fmt.Sprintf("$0-%d", word*2), fmt.Sprintf("$0-%d", word*3), 1)
				for _, live := range []bool{false, true} {
					control := fmt.Sprintf("PUSH%s mask+%d(FP)\nPOPF%s\n", suffix, word, suffix)
					product := raw
					if live {
						product = fmt.Sprintf("PUSH%s mask+%d(FP)\n%sPOP%s DX\n", suffix, word, raw, suffix)
					}
					capture := fmt.Sprintf("PUSHF%s\nPOP%s CX\n%s CX,ret+%d(FP)\n", suffix, suffix, move, word*2)
					initialized := strings.Replace(body, instruction, control+product+capture, 1)
					name := fmt.Sprint("ProductFlags", count)
					source.WriteString(strings.ReplaceAll(initialized, "Value", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + " uintptr\n")
					count++
				}
			}
			want := 72
			if word == 4 {
				want = 24
			}
			if count != want {
				t.Fatal("complete raw product full/broadcast/mask private-control inventory changed", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}
