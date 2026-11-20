package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86MOVNTICompleteIndependentGoEncoderRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	table := regexp.MustCompile(`(?s)var yrl_ml = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(text)
	if len(table) != 2 || strings.Join(strings.Fields(table[1]), "") !=
		"{Zr_m,1,argList{Yrl,Yml}}," {
		t.Fatal("complete Go MOVNTI grammar, zcase or encoding offset changed")
	}
	rows := regexp.MustCompile(`\{A(MOVNTI[\w]*), yrl_ml, (P\w+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(text, -1)
	if len(rows) != 2 {
		t.Fatal("complete Go scalar non-temporal family changed", rows)
	}
	if len(x86MOVNTIWidths) != len(rows) {
		t.Fatal("typed scalar non-temporal directory is not the complete independent Go family")
	}
	for _, row := range rows {
		prefix, encoding, bits := "Pm", "0xc3", 32
		if row[1] == "MOVNTIQ" {
			prefix, encoding, bits = "Pw", "0x0f,0xc3", 64
		} else if row[1] != "MOVNTIL" {
			t.Fatal("unmodeled Go scalar non-temporal member", row[1])
		}
		if row[2] != prefix || strings.Join(strings.Fields(row[3]), "") != encoding || x86MOVNTIWidths[Op(row[1])] != bits {
			t.Fatal("complete Go MOVNTI physical encoding changed", row)
		}
	}
}

func TestX86MOVNTICompleteGoRegisterAndAddressClasses(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			registers := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}
			if arch == "amd64" {
				registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
			}
			destinations := append([]string(nil), registers...)
			destinations = append(destinations,
				"(AX)", "-1(AX)(CX*2)", "128(BX)(SI*8)", "tmp-4(SP)",
				"ret+0(FP)", "·cell(SB)", "17", "8(AX)(GS)", "8(AX)(FS)")
			var source strings.Builder
			source.WriteString("DATA ·cell+0(SB)/8,$0\nGLOBL ·cell(SB),$8\n")
			count := 0
			for _, name := range []string{"MOVNTIL", "MOVNTIQ"} {
				if arch == "386" && name == "MOVNTIQ" {
					continue
				}
				for _, register := range registers {
					for _, destination := range destinations {
						text := name + " " + register + "," + destination
						ins := x86YMMReadSource(t, text)
						form, known, err := x86MOVNTIProperties(ins.Op, ins, arch)
						if !known || err != nil || form.trap != (ins.Args[1].Kind == OpReg) || !reflect.DeepEqual(form.source, ins.Args[0]) {
							t.Fatal("complete Go Yrl/Yml row lost source shape or trap priority", text, err)
						}
						fmt.Fprintf(&source, "TEXT ·Format%d(SB),4,$0-8\n%s\nRET\n", count, text)
						count++
					}
				}
			}
			want := 136
			if arch == "amd64" {
				want = 800
			}
			if count != want {
				t.Fatal("independent complete scalar non-temporal source/address inventory changed", count)
			}
			requireX86GoAssemblerResult(t, arch, source.String(), true)
		})
	}
}

func TestX86MOVNTIRejectsCompleteGrammarBeforeIR(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range []string{"MOVNTIL", "MOVNTIQ"} {
			if arch == "386" && name == "MOVNTIQ" {
				continue // The original Go-mode rejection matrix retains this axis.
			}
			original := x86YMMReadSource(t, name+" AX,(BX)")
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"dispatch", func(i *Instr) { i.Op = "MOVL" }},
				{"suffix", func(i *Instr) { i.Op += ".Z" }},
				{"arity", func(i *Instr) { i.Args = i.Args[:1] }},
				{"immediate-source", func(i *Instr) { i.Args[0] = Operand{Kind: OpImm, Imm: 1} }},
				{"vector-source", func(i *Instr) { i.Args[0] = Operand{Kind: OpReg, Reg: "X0"} }},
				{"vector-destination", func(i *Instr) { i.Args[1] = Operand{Kind: OpReg, Reg: "X0"} }},
				{"address-immediate", func(i *Instr) { i.Args[1] = Operand{Kind: OpSym, Sym: "$16(BX)"} }},
			} {
				t.Run(arch+"/"+name+"/"+control.name, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					control.change(&ins)
					var ir strings.Builder
					ctx := &amd64Ctx{b: &ir, goarch: arch}
					known, terminated, err := ctx.lowerMOVNTI(Op(name), ins)
					if !known || terminated || err == nil || ir.Len() != 0 || ctx.tmp != 0 {
						t.Fatal("incomplete MOVNTI grammar emitted before rejection", known, terminated, err, ir.String())
					}
				})
			}
		}
	}
}

func TestX86MOVNTIRegisterDestinationFaultsBeforeInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range []string{"MOVNTIL", "MOVNTIQ"} {
			if arch == "386" && name == "MOVNTIQ" {
				continue
			}
			t.Run(arch+"/"+name, func(t *testing.T) {
				// Go's Yml compatibility closure admits mod=3, but MOVNTI has
				// no ISA register destination. No source byte or memory input
				// may be read before this unconditional architectural #UD.
				ins := x86YMMReadSource(t, name+" AX,BX")
				var ir strings.Builder
				ctx := &amd64Ctx{b: &ir, goarch: arch}
				known, terminated, err := ctx.lowerMOVNTI(ins.Op, ins)
				if !known || !terminated || err != nil || ctx.tmp != 0 ||
					ir.String() != "  call void asm sideeffect \"ud2\", \"~{memory}\"()\n  unreachable\n" {
					t.Fatal("register MOVNTI did not fault before inputs", known, terminated, err, ir.String())
				}
			})
		}
	}
}

func TestX86MOVNTILogicalStorageDoesNotSupplyNativeBacking(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, source := range []string{
			"TEXT ·Value(SB),4,$0-4\nMOVL $1,AX\nMOVNTIL AX,ret+0(FP)\nRET\n",
			"TEXT ·Value(SB),4,$16-4\nMOVL $1,AX\nMOVNTIL AX,tmp-4(SP)\nMOVL $1,ret+0(FP)\nRET\n",
		} {
			t.Run(target.triple+"/"+strings.Split(source, "\n")[0], func(t *testing.T) {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("logical numerical bytes impersonated MOVNTI native storage", api, err)
					}
				}
			})
		}
	}
}
