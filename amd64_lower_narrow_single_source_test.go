package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86SingleSourceIntegerNarrowCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			last := 31
			if target.goarch == "386" {
				last = 7
			}
			var source strings.Builder
			source.WriteString("TEXT singlesourcenarrowforms(SB),$0-0\n")
			for _, op := range []string{
				"VPMOVDB", "VPMOVDW", "VPMOVQB", "VPMOVQD", "VPMOVQW", "VPMOVWB",
				"VPMOVSDB", "VPMOVSDW", "VPMOVSQB", "VPMOVSQD", "VPMOVSQW", "VPMOVSWB",
				"VPMOVUSDB", "VPMOVUSDW", "VPMOVUSQB", "VPMOVUSQD", "VPMOVUSQW", "VPMOVUSWB",
			} {
				inputBits, outputBits := x86SingleSourceNarrowTestBits(op)
				for _, width := range []struct {
					name  string
					bytes int
				}{
					{name: "X", bytes: 16},
					{name: "Y", bytes: 32},
					{name: "Z", bytes: 64},
				} {
					outputBytes := width.bytes * outputBits / inputBits
					destinationWidth := "X"
					if outputBytes > 16 {
						destinationWidth = "Y"
					}
					fmt.Fprintf(&source, "\t%s %s%d, %s%d\n", op, width.name, last, destinationWidth, last)
					fmt.Fprintf(&source, "\t%s %s%d, K1, %s%d\n", op, width.name, last, destinationWidth, last)
					fmt.Fprintf(&source, "\t%s.Z %s%d, K2, %s%d\n", op, width.name, last, destinationWidth, last)
					fmt.Fprintf(&source, "\t%s %s%d, 8(AX)\n", op, width.name, last)
					fmt.Fprintf(&source, "\t%s %s%d, K3, 16(AX)\n", op, width.name, last)
					fmt.Fprintf(&source, "\t%s.Z %s%d, K4, 24(AX)\n", op, width.name, last)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"singlesourcenarrowforms": {Name: "singlesourcenarrowforms", Ret: Void},
				},
			})
			if ll != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("bare Go formats invented initialized entry registers or memory", err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			// Preserve every original operand and all 324 Go-encoded shapes as
			// isolated emitter units. Initialized public objects and executable
			// numerical/fault owners are independent of these format objects.
			units, signatures := x86SingleSourceNarrowingFormatUnits(file)
			if len(units.Funcs) != 324 {
				t.Fatal("an original Go format disappeared", len(units.Funcs))
			}
			x86SingleSourceNarrowingFormatObjects(t, llc, units, signatures, target.goarch, target.triple)
		})
	}
}

func x86SingleSourceNarrowingFormatUnits(file *File) (*File, map[string]FuncSig) {
	units := *file
	units.Funcs = nil
	signatures := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == OpTEXT || ins.Op == OpRET {
				continue
			}
			name := fmt.Sprint("NarrowFormat", len(units.Funcs))
			units.Funcs = append(units.Funcs, Func{Sym: name, Instrs: []Instr{{Op: OpTEXT}, ins, {Op: OpRET}}})
			signatures[name] = FuncSig{Name: name, Ret: Void}
		}
	}
	return &units, signatures
}

func x86SingleSourceNarrowingFormatObjects(t *testing.T, llc string, units *File, signatures map[string]FuncSig, arch, triple string) {
	t.Helper()
	for start := 0; start < len(units.Funcs); start += 64 {
		end := start + 64
		if end > len(units.Funcs) {
			end = len(units.Funcs)
		}
		batch := *units
		batch.Funcs = units.Funcs[start:end]
		ir := x86SingleInstructionFormatObjectUnits(t, &batch, signatures, arch, triple,
			func(c *amd64Ctx, ins Instr) (bool, bool, error) { return c.lowerSingleSourceIntegerNarrow(ins.Op, ins) })
		for _, level := range []string{"-O0", "-O2"} {
			x86PackedStringCompileObject(t, llc, triple, ir, level)
		}
	}
}

func x86SingleSourceNarrowTestBits(op string) (inputBits, outputBits int) {
	pair := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(op, "VPMOV"), "US"), "S")
	bits := func(letter byte) int {
		switch letter {
		case 'B':
			return 8
		case 'W':
			return 16
		case 'D':
			return 32
		case 'Q':
			return 64
		default:
			panic("bad narrow element letter")
		}
	}
	return bits(pair[0]), bits(pair[1])
}

func TestTranslateX86SingleSourceIntegerNarrowRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPMOVSDB 8(AX), X0",
		"VPMOVSDB X0, Y0",
		"VPMOVSDW Z0, X0",
		"VPMOVSDB X0, K0, X1",
		"VPMOVSDB.Z X0, X1",
		"VPMOVSDB.BCST X0, X1",
		"VPMOVSDB X0, K1, K2, X1",
		"VPMOVSDB X0, AX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvpmovdb/_yvpmovdw tables", instruction)
			}
		})
	}
}
