package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A private object unit proves Go operand/emitter formats, not initialized
// public inputs, storage or native execution. Preserve the entire original
// actual Go object and all three public Context results before using it.
func x86UnboundBlendMinposFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("original blend/minimum formats lost their physical source", err)
	}
	return x86InstructionFormatObjectUnit(t, normalized, signatures, arch, triple, 0,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			if known, terminated, err := c.lowerVariableBlend(ins.Op, ins); known {
				return known, terminated, err
			}
			return c.lowerPackedUnsignedWordMinimumPosition(ins.Op, ins)
		})
}

func x86UnboundBlendMinposProbeObject(t *testing.T, file *File, arch, triple string) string {
	t.Helper()
	var source strings.Builder
	for _, fn := range file.Funcs {
		text, valid := x86RawReplaySourceText(fn)
		if !valid {
			t.Fatal("original raw blend/minimum format source is absent")
		}
		source.WriteString(text)
	}
	return x86UnboundBlendMinposFormatObject(t, source.String(), arch, triple)
}

// Go's 386 frontend rejects every named four-operand VEX blend. Preserve
// that original whole-source rejection with a real diagnostic, not an
// assembler panic, missing tool, timeout or resource failure. Only the six
// legal legacy rows enter mode32 named format objects; actual low-bank VEX
// bytes have their separate complete encoder and initialized object owners.
func x86BlendMinposOriginal386NamedFormats(t *testing.T, source, triple string) string {
	t.Helper()
	goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source, "", false)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("original 386 source changed its complete parser role", err)
	}
	name := strings.TrimPrefix(file.Funcs[0].Sym, "·")
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, "func "+name+"()", "386", triple, api)
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("Go-rejected named source invented initialized public inputs", api, err)
		}
	}
	var legal strings.Builder
	legacy, rejected := 0, 0
	for _, line := range strings.Split(source, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if spec, known := amd64VariableBlendSpecs[Op(fields[0])]; known {
			if spec.vector {
				goAssemblerOracleOutput(t, "386", "TEXT ·Rejected(SB),4,$0-0\n"+line+"\nRET\n", "", false)
				rejected++
				continue
			}
			legacy++
		} else if fields[0] != "TEXT" && fields[0] != "RET" {
			t.Fatal("original named format directory contains an unrelated source operation", line)
		}
		fmt.Fprintln(&legal, line)
	}
	if legacy != 6 || rejected != 12 {
		t.Fatal("original 386 named format classification changed", legacy, rejected)
	}
	t.Log("original 386 named source: 6 legal legacy formats, 12 Go-rejected VEX four-operand rows; physical low-bank VEX has separate complete owners")
	return x86UnboundBlendMinposFormatObject(t, legal.String(), "386", triple)
}
