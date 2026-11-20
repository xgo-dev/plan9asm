package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type amd64DataBPOverwriteCase struct {
	name, before, overwrite, after string
	extraParameter                 bool
}

// Every negative keeps the same initialized pointer producer and numerical
// shift as its positive control. Removing the later native BP access must not
// turn an unsupported overwrite into an accepted dead-value transfer.
func amd64CheckDataBPOverwriteCases(t *testing.T, cases []amd64DataBPOverwriteCase) {
	t.Helper()
	type program struct {
		name, source, declaration string
		overwrite                 bool
	}
	var programs []program
	var originalObjects strings.Builder
	for index, test := range cases {
		for _, useBP := range []bool{false, true} {
			for _, overwrite := range []bool{false, true} {
				symbol := fmt.Sprintf("BPOverwrite%d_%t_%t", index, useBP, overwrite)
				arguments, extra := 8, ""
				if test.extraParameter {
					arguments, extra = 16, ", adjacent uint64"
				}
				var body strings.Builder
				body.WriteString("MOVQ p+0(FP),BP\nMOVL $0x12345678,AX\n")
				body.WriteString(test.before + "\n")
				if overwrite {
					body.WriteString(test.overwrite + "\n")
				}
				body.WriteString(test.after + "\n")
				if useBP {
					body.WriteString("MOVL (BP),AX\n")
				}
				body.WriteString("ROLL $7,AX\n")
				if useBP {
					body.WriteString("MOVL AX,12(BP)\n")
				}
				source := fmt.Sprintf("TEXT ·%s(SB),4,$8-%d\n%sRET\n", symbol, arguments, body.String())
				originalObjects.WriteString(source)
				programs = append(programs, program{
					name:   fmt.Sprintf("%s/use-BP=%t/overwrite=%t", test.name, useBP, overwrite),
					source: source, declaration: fmt.Sprintf("func %s(p *[16]byte%s)\n", symbol, extra),
					overwrite: overwrite,
				})
			}
		}
	}
	// These are all original, legal stock-Go sources, including overlapping
	// unaligned FP writes. A parser/encoder/tool failure is not Context evidence.
	if !t.Run("OriginalGoObjects", func(t *testing.T) {
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", originalObjects.String())
	}) {
		t.Fatal("original Go object prerequisite failed; no overwrite rejection is certified")
	}
	for _, test := range programs {
		t.Run(test.name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, test.source, test.declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if test.overwrite {
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("an overwritten register or FP pointer slot retained its old data-BP authority", err)
						}
					} else if err != nil || ir == "" {
						t.Fatal("the identical initialized pointer source without the overwrite must remain accepted", err)
					}
				})
			}
		})
	}
}

func TestAMD64DataBPRejectsPartialAndNumericRegisterOverwrites(t *testing.T) {
	var cases []amd64DataBPOverwriteCase
	for _, width := range []struct{ suffix, source, destination string }{
		{"B", "AL", "BPB"}, {"W", "AX", "BP"}, {"L", "AX", "BP"}, {"Q", "AX", "BP"},
	} {
		cases = append(cases,
			amd64DataBPOverwriteCase{name: "immediate/" + width.suffix,
				overwrite: fmt.Sprintf("MOV%s $7,%s", width.suffix, width.destination)},
			amd64DataBPOverwriteCase{name: "numeric-register/" + width.suffix,
				overwrite: fmt.Sprintf("MOV%s %s,%s", width.suffix, width.source, width.destination)},
		)
	}
	amd64CheckDataBPOverwriteCases(t, cases)
}

func TestAMD64DataBPRejectsXToBPOverwrites(t *testing.T) {
	var cases []amd64DataBPOverwriteCase
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
		cases = append(cases, amd64DataBPOverwriteCase{
			name: op, before: "PXOR X0,X0", overwrite: op + " X0,BP",
		})
	}
	amd64CheckDataBPOverwriteCases(t, cases)
}

func TestAMD64DataBPRejectsOverwrittenAliasesAndCFGJoins(t *testing.T) {
	var cases []amd64DataBPOverwriteCase
	for _, width := range []struct{ suffix, source, destination string }{
		{"B", "AL", "DL"}, {"W", "AX", "DX"}, {"L", "AX", "DX"}, {"Q", "AX", "DX"},
	} {
		overwrite := fmt.Sprintf("MOV%s %s,%s", width.suffix, width.source, width.destination)
		cases = append(cases,
			amd64DataBPOverwriteCase{name: "alias/" + width.suffix, before: "MOVQ BP,DX",
				overwrite: overwrite, after: "MOVQ DX,BP"},
			amd64DataBPOverwriteCase{name: "reaching-join/" + width.suffix, extraParameter: true,
				before:    "MOVQ BP,DX\nMOVQ adjacent+8(FP),CX\nTESTQ CX,CX\nJE joined",
				overwrite: overwrite, after: "joined:\nMOVQ DX,BP"},
		)
	}
	amd64CheckDataBPOverwriteCases(t, cases)
}

func amd64CheckDataBPFPSlotOverwrites(t *testing.T, suffix string) {
	t.Helper()
	var cases []amd64DataBPOverwriteCase
	for offset := 0; offset < 8; offset++ {
		cases = append(cases, amd64DataBPOverwriteCase{
			name: fmt.Sprintf("MOV%s/offset=%d", suffix, offset), extraParameter: true,
			overwrite: fmt.Sprintf("MOV%s $7,p+%d(FP)", suffix, offset), after: "MOVQ p+0(FP),BP",
		})
	}
	amd64CheckDataBPOverwriteCases(t, cases)
}

func TestAMD64DataBPRejectsByteFPSlotOverwriteBeforeReimport(t *testing.T) {
	amd64CheckDataBPFPSlotOverwrites(t, "B")
}

func TestAMD64DataBPRejectsWordFPSlotOverwriteBeforeReimport(t *testing.T) {
	amd64CheckDataBPFPSlotOverwrites(t, "W")
}

func TestAMD64DataBPRejectsDwordFPSlotOverwriteBeforeReimport(t *testing.T) {
	amd64CheckDataBPFPSlotOverwrites(t, "L")
}

func TestAMD64DataBPRejectsQwordFPSlotOverwriteBeforeReimport(t *testing.T) {
	amd64CheckDataBPFPSlotOverwrites(t, "Q")
}
