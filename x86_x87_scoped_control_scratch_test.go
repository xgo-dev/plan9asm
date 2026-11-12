package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86ScopedRoundingCase struct {
	name, source, declaration string
	mode                      int
}

func x86ScopedRoundingCases() []x86ScopedRoundingCase {
	var rows []x86ScopedRoundingCase
	for mode := 0; mode < 5; mode++ {
		for _, register := range []string{"AX", "BX", "CX", "DX", "SI", "DI", "BP"} {
			for _, cells := range [][2]int{{-2, -4}, {-4, -2}} {
				name := fmt.Sprintf("Round%d", len(rows))
				clear := fmt.Sprintf("ANDW $0xf3ff,%s\n", register)
				selection := mode
				if mode == 4 {
					clear, selection = "", 3
				}
				source := fmt.Sprintf(`TEXT ·%s(SB),4,$0-16
FMOVD input+0(FP),F0
FSTCW %d(SP)
MOVW %d(SP),%s
%sORW $%d,%s
MOVW %s,%d(SP)
FLDCW %d(SP)
FRNDINT
FLDCW %d(SP)
FMOVDP F0,ret+8(FP)
RET
`, name, cells[0], cells[0], register, clear, selection<<10, register,
					register, cells[1], cells[1], cells[0])
				rows = append(rows, x86ScopedRoundingCase{name, source,
					fmt.Sprintf("func %s(input float64) float64\n", name), selection})
			}
		}
	}
	return rows
}

func x86ScopedRoundingBundle(t *testing.T) (string, string) {
	t.Helper()
	var source, declarations strings.Builder
	rows := x86ScopedRoundingCases()
	if len(rows) != 70 {
		t.Fatal("complete scoped-control family inventory changed", len(rows))
	}
	for _, row := range rows {
		source.WriteString(row.source)
		declarations.WriteString(row.declaration)
	}
	return source.String(), declarations.String()
}

func TestX86X87ScopedRoundingCompleteFamilyObjects(t *testing.T) {
	source, declarations := x86ScopedRoundingBundle(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("scoped rounding requires LLVM22 llc")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc", "i686-w64-windows-gnu"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, source)
			for _, mode := range []X87Mode{X87Auto, X87Hardware} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("mode%d/%s", mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declarations, "386", triple, api, mode)
						if err != nil || ir == "" {
							t.Fatal("complete scoped rounding family cannot translate", err)
						}
						x86X87HardwareWordRead(t, ir, 70)
						for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, input, level)
							}
						}
					})
				}
			}
		})
	}
}

func TestX86X87ScopedRoundingScratchSourceBoundaries(t *testing.T) {
	row := x86ScopedRoundingCases()[0]
	for name, source := range map[string]string{
		"read-named-AUTO":        strings.Replace(row.source, "MOVW -2(SP)", "MOVW saved-2(SP)", 1),
		"change-named-AUTO":      strings.Replace(row.source, "FLDCW -4(SP)", "FLDCW temporary-4(SP)", 1),
		"restore-named-AUTO":     strings.Replace(row.source, "FLDCW -2(SP)", "FLDCW saved-2(SP)", 1),
		"overlap-saved":          strings.ReplaceAll(row.source, "-4(SP)", "-2(SP)"),
		"partial-overlap":        strings.ReplaceAll(row.source, "-4(SP)", "-3(SP)"),
		"outside-bound":          strings.ReplaceAll(row.source, "-4(SP)", "-4097(SP)"),
		"second-stack-word":      strings.ReplaceAll(row.source, "-4(SP)", "-6(SP)"),
		"touch-return-address":   strings.ReplaceAll(row.source, "-4(SP)", "-1(SP)"),
		"incoming-SP":            strings.ReplaceAll(row.source, "-4(SP)", "0(SP)"),
		"changed-exception-mask": strings.Replace(row.source, "$0xf3ff", "$0xf3fe", 1),
		"changed-precision":      strings.Replace(row.source, "ORW $0,", "ORW $256,", 1),
		"unknown-RC":             strings.Replace(row.source, "ORW $0,", "ORW $missing,", 1),
		"missing-save":           strings.Replace(row.source, "FSTCW -2(SP)\n", "", 1),
		"partial-save":           strings.Replace(row.source, "FSTCW -2(SP)", "MOVB $127,-2(SP)", 1),
		"overwrite-saved":        strings.Replace(row.source, "FRNDINT\n", "FRNDINT\nMOVW $0,-2(SP)\n", 1),
		"missing-restore":        strings.Replace(row.source, "FLDCW -2(SP)\n", "", 1),
		"wrong-restore":          strings.Replace(row.source, "FLDCW -2(SP)", "FLDCW -4(SP)", 1),
		"early-return":           strings.Replace(row.source, "FRNDINT\n", "FRNDINT\nRET\n", 1),
		"stack-change":           strings.Replace(row.source, "FRNDINT\n", "PUSHL AX\nFRNDINT\nPOPL AX\n", 1),
		"stack-escape":           strings.Replace(row.source, "FRNDINT\n", "LEAL -2(SP),AX\nCALL ·escape(SB)\nFRNDINT\n", 1),
		"dead-extra-access":      row.source + "MOVW -6(SP),AX\n",
		"nonzero-TEXT":           strings.Replace(row.source, "$0-16", "$4-16", 1),
		"split-TEXT":             strings.Replace(row.source, ",4,$0", ",0,$0", 1),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil || len(file.Funcs) != 1 {
				t.Fatal("source boundary must reach the translator, not fail parsing", err)
			}
			if extent, ok := x86X87ScopedControlScratchExtent(file.Funcs[0], "386"); ok || extent != 0 {
				t.Fatal("changed source borrowed private control-word storage", extent)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86X87InitializedWordAPI(t, source, row.declaration, "386", "i686-pc-windows-msvc", api, X87Hardware)
				if err == nil || ir != "" {
					t.Fatal("changed source was published", api, err)
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("unknown-software-control/"+api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, row.source, row.declaration, "386", "i686-pc-windows-msvc", api, X87Software)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatal("private scratch manufactured ambient Software control", err)
			}
		})
	}
}

func TestX86X87ScopedRoundingScratchReplayAndStorageBoundaries(t *testing.T) {
	row := x86ScopedRoundingCases()[0]
	for _, mutation := range []string{"none", "frame", "argument-extent", "symbol", "operand", "literal"} {
		t.Run(mutation, func(t *testing.T) {
			file, err := Parse(ArchAMD64, row.source)
			if err != nil {
				t.Fatal(err)
			}
			function := file.Funcs[0]
			switch mutation {
			case "frame":
				function.FrameSize = 4
			case "argument-extent":
				function.ArgSize = 32
			case "symbol":
				function.Sym = "·Another"
			case "operand":
				function.Instrs[2].Args[0].Mem.Off = -4
			case "literal":
				function.Instrs[2].Raw = "FSTCW -4(SP)"
			}
			extent, recognized := x86X87ScopedControlScratchExtent(function, "386")
			if mutation == "none" {
				if !recognized || extent != 4 {
					t.Fatal("complete unchanged scope lost its private word", extent, recognized)
				}
				if _, err := x86ResultAUTOExtent(function, "386"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("physical scratch manufactured a standalone logical AUTO frame", err)
				}
				resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
				pkg := mustGoPackage(t, "rounding", "package rounding\n"+row.declaration)
				sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				consumer := newX86Ctx(new(strings.Builder), function, sigs[row.name], resolve, nil,
					"386", "i686-pc-windows-msvc", false)
				if err := consumer.scalarFPResultInitialized(); err != nil {
					t.Fatal("complete scope failed its actual typed result proof", err)
				}
				if err := consumer.prepareLogicalAUTOStorage(); err != nil || consumer.logicalAUTOExtent != 0 || consumer.logicalAUTOBase != "" {
					t.Fatal("scoped scratch acquired named AUTO storage", err)
				}
				consumer.frameSize = 4
				if err := consumer.prepareLogicalAUTOStorage(); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed emitter frame reused a source proof", err)
				}
			} else if recognized || extent != 0 {
				t.Fatal("mutated parsed source retained a scratch role", extent, recognized)
			}
		})
	}
}
