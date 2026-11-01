package plan9asm

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86MOVBECompleteIndependentGoRowsAndAliases(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	table := regexp.MustCompile(`(?s)var ymovbe = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(text)
	if len(table) != 2 || strings.Join(strings.Fields(table[1]), "") !=
		"{Zlitm_r,3,argList{Ym,Yrl}},{Zlitr_m,3,argList{Yrl,Ym}}," {
		t.Fatal("complete Go MOVBE directions, zcases or offsets changed")
	}
	rows := regexp.MustCompile(`\{A(MOVBE[WLQ]), ymovbe, (P\w+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(text, -1)
	if len(rows) != 3 {
		t.Fatal("complete canonical Go MOVBE directory changed", len(rows))
	}
	for _, row := range rows {
		bits, prefix, opcodes := 16, "Pq", "0x38,0xf0,0,0x38,0xf1,0"
		switch row[1] {
		case "MOVBEL":
			bits, prefix = 32, "Pm"
		case "MOVBEQ":
			bits, prefix, opcodes = 64, "Pw", "0x0f,0x38,0xf0,0,0x0f,0x38,0xf1,0"
		}
		if x86MOVBEWidths[Op(row[1])] != bits || row[2] != prefix ||
			strings.Join(strings.Fields(row[3]), "") != opcodes {
			t.Fatal("typed MOVBE width or complete physical encoding differs from Go", row)
		}
	}
	data, err = os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	aliases := regexp.MustCompile(`instructions\["(MOVBE\w+)"\] = x86\.A(MOVBE[WLQ])`).FindAllStringSubmatch(string(data), -1)
	if len(aliases) != 3 || len(x86MOVBEWidths) != len(rows)+len(aliases) {
		t.Fatal("complete Go frontend MOVBE aliases missing from typed directory", len(aliases), len(x86MOVBEWidths))
	}
	for _, alias := range aliases {
		if x86MOVBEWidths[Op(alias[1])] != x86MOVBEWidths[Op(alias[2])] {
			t.Fatal("Go frontend alias has a different typed width", alias)
		}
	}
}

func TestX86MOVBERejectsBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"MOVBEW", "MOVBEWW", "MOVBEL", "MOVBELL", "MOVBEQ", "MOVBEQQ"} {
			for _, direction := range []string{"(AX),BX", "BX,(AX)"} {
				ins := x86YMMReadSource(t, name+" "+direction)
				for _, control := range []struct {
					name   string
					change func(*Instr)
				}{
					{"dispatch", func(i *Instr) { i.Op = "MOVL" }},
					{"arity", func(i *Instr) { i.Args = i.Args[:1] }},
					{"first", func(i *Instr) { i.Args[0] = Operand{Kind: OpImm, Imm: 1} }},
					{"second", func(i *Instr) { i.Args[1] = Operand{Kind: OpReg, Reg: "X0"} }},
					{"suffix", func(i *Instr) { i.Op += ".Z" }},
				} {
					t.Run(arch+"/"+name+"/"+direction+"/"+control.name, func(t *testing.T) {
						bad := ins
						bad.Args = append([]Operand(nil), ins.Args...)
						control.change(&bad)
						var ir strings.Builder
						consumer := &amd64Ctx{b: &ir, goarch: arch}
						known, terminated, err := consumer.lowerMOVBE(Op(name), bad)
						if !known || terminated || err == nil || ir.Len() != 0 || consumer.tmp != 0 {
							t.Fatal("invalid MOVBE emitted before full grammar rejection", known, err, ir.String())
						}
					})
				}
			}
		}
	}
}
