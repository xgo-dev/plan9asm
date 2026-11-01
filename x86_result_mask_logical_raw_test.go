package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86MaskLogicalRawOperation(t *testing.T, op string) string {
	t.Helper()
	for _, row := range x86RawKLogicalRows() {
		if string(row.name) != op {
			continue
		}
		destination := 3
		if strings.Contains(op, "TEST") {
			destination = 7
		}
		var source strings.Builder
		for _, value := range encodeX86RawKLogical(row, 0, 7, destination) {
			fmt.Fprintf(&source, "BYTE $%#02x\n", value)
		}
		return source.String()
	}
	t.Fatal("raw oracle has no complete mask encoding", op)
	return ""
}

func x86MaskLogicalRawFixture(t *testing.T, source string) string {
	t.Helper()
	for _, row := range x86MaskLogicalOracle() {
		instruction := row.op + " " + row.operands + "\n"
		if strings.Count(source, instruction) != 1 {
			t.Fatal("raw fixture lost exact original operation", row.op)
		}
		source = strings.Replace(source, instruction, x86MaskLogicalRawOperation(t, row.op), 1)
	}
	return source
}

func TestX86MaskLogicalRawUnknownVoidInputs(t *testing.T) {
	for _, row := range x86MaskLogicalOracle() {
		t.Run(row.op, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$0\n" + x86MaskLogicalRawOperation(t, row.op) + "RET\n"
			for _, target := range x86RawReturnTargets {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("raw source invented incoming mask values", target.triple, api, err)
					}
				}
			}
		})
	}
}

func TestX86MaskLogicalRawCannotBorrowOtherSourceRoles(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0\n"+x86MaskLogicalRawOperation(t, "KANDW")+"RET\n")
	if err != nil {
		t.Fatal(err)
	}
	file, err = normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var original Instr
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == "KANDW" {
			original = ins
		}
	}
	if original.x86SourceRaw == nil {
		t.Fatal("actual raw decoder did not retain the source")
	}
	for _, mutate := range []struct {
		name  string
		apply func(*Instr)
	}{
		{"opcode", func(ins *Instr) { ins.Op = "KORW" }},
		{"operand", func(ins *Instr) { ins.Args[0].Reg = "K2" }},
		{"physical", func(ins *Instr) { ins.x86Encoded = true }},
		{"address-size", func(ins *Instr) { ins.x86AddressBits = 32 }},
		{"unbound-address", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
		{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			state := x86ResultState{flags: x86ByteFlagAF}
			state.masks[0], state.masks[7] = true, true
			control := state.clone()
			if !x86ScalarFPResultTransfer(original, &control, nil, 0, "amd64") {
				t.Fatal("actual decoded register-only control rejected")
			}
			changed := original
			changed.Args = append([]Operand(nil), original.Args...)
			mutate.apply(&changed)
			before := state.clone()
			if x86ScalarFPResultTransfer(changed, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, before) {
				t.Fatal("changed or foreign raw role acquired mask numerical state")
			}
		})
	}
}

func TestX86MaskLogicalRawPrivateStateFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word := "Q"
			if target.arch == "386" {
				word = "L"
			}
			var source, declarations strings.Builder
			for _, row := range x86MaskLogicalOracle() {
				fmt.Fprintf(&declarations, "func %s(a,b uint64) uint32\n", row.op)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-20\nKMOVQ a+0(FP),K0\nKMOVQ b+8(FP),K7\n", row.op)
				// Seed status, DF and ID independently, and keep a live private
				// stack value across the raw operation. No source SP is exposed.
				fmt.Fprintf(&source, "PUSH%s $0x200cd7\nPOPF%s\nPUSH%s $42\n", word, word, word)
				source.WriteString(x86MaskLogicalRawOperation(t, row.op))
				fmt.Fprintf(&source, "POP%s CX\nPUSHF%s\nPOP%s AX\nMOVL AX,ret+16(FP)\nRET\n", word, word, word)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("raw mask operation lost independent DF/ID or private storage", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}
