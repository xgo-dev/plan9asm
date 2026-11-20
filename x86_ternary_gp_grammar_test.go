package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86YmlYrlYrlCompleteIndependentGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	table := regexp.MustCompile(`(?s)var _yandnl = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(text)
	if len(table) != 2 || strings.Join(strings.Fields(table[1]), "") != "{zcase:Zvex_rm_v_r,zoffset:2,args:argList{Yml,Yrl,Yrl}}," {
		t.Fatal("complete Go encoder operand classes, zcase or offset changed")
	}
	rows := regexp.MustCompile(`(?s)\{as: A((?:ANDN|PDEP|PEXT)[LQ]), ytab: _yandnl, prefix: Pavx, op: opBytes\{\s*([^,]+), (0x[0-9A-Fa-f]+),\s*\}\}`).FindAllStringSubmatch(text, -1)
	if len(rows) != 6 || len(x86TernaryGPSpecs) != len(rows) {
		t.Fatal("complete six-member grammar differs from Go", len(rows))
	}
	for _, row := range rows {
		spec, ok := x86TernaryGPSpecs[Op(row[1])]
		bits, prefix, operation, opcode := 32, 0, x86TernaryANDN, "0xF2"
		attributes := "avxEscape|vex128|"
		if strings.HasPrefix(row[1], "PDEP") {
			prefix, operation, opcode = 3, x86TernaryPDEP, "0xF5"
			attributes += "vexF2|"
		} else if strings.HasPrefix(row[1], "PEXT") {
			prefix, operation, opcode = 2, x86TernaryPEXT, "0xF5"
			attributes += "vexF3|"
		}
		attributes += "vex0F38|vexW0"
		if strings.HasSuffix(row[1], "Q") {
			bits = 64
			attributes = strings.Replace(attributes, "vexW0", "vexW1", 1)
		}
		if !ok || spec.bits != bits || spec.operation != operation || spec.prefix != prefix ||
			strings.Join(strings.Fields(row[2]), "") != attributes || row[3] != opcode {
			t.Fatal("typed spec or complete physical encoding differs from Go", row, spec)
		}
	}
}

func TestX86YmlYrlYrlRejectsBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			ins := x86YMMReadSource(t, name+" AX,BX,CX")
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"dispatch", func(i *Instr) { i.Op = "MOVL" }},
				{"arity", func(i *Instr) { i.Args = i.Args[:2] }},
				{"first", func(i *Instr) { i.Args[0].Reg = "X0" }},
				{"second", func(i *Instr) { i.Args[1].Reg = "X0" }},
				{"destination", func(i *Instr) { i.Args[2].Reg = "X0" }},
				{"immediate", func(i *Instr) { i.Args[0] = Operand{Kind: OpImm, Imm: 1} }},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", arch, name, control.name), func(t *testing.T) {
					bad := ins
					bad.Args = append([]Operand(nil), ins.Args...)
					control.change(&bad)
					var ir strings.Builder
					consumer := &amd64Ctx{b: &ir, goarch: arch}
					lower := consumer.lowerParallelBitDepositExtract
					if strings.HasPrefix(name, "ANDN") {
						lower = consumer.lowerANDN
					}
					known, terminated, err := lower(Op(name), bad)
					if !known || terminated || err == nil || ir.Len() != 0 {
						t.Fatal("invalid source emitted before the complete grammar rejected it", known, err, ir.String())
					}
				})
			}
		}
	}
}
