package plan9asm

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestX86ImplicitDivideTypedFamilyCompleteGoBanksAndAddresses(t *testing.T) {
	if len(x86ImplicitDivideSpecs) != len(x86ImplicitDivideOracle) {
		t.Fatal("typed implicit division directory differs from the independent complete family")
	}
	for _, arch := range []string{"386", "amd64"} {
		var witnesses strings.Builder
		witnesses.WriteString("DATA ·cell+0(SB)/8,$3\nGLOBL ·cell(SB),$8\n")
		count := 0
		for _, row := range x86ImplicitDivideOracle {
			spec, known := x86ImplicitDivideSpecs[Op(row.name)]
			if !known || spec.bits != row.bits || spec.signed != row.signed {
				t.Fatal("typed implicit division width/sign differs from independent Go rows", row.name)
			}
			if arch == "386" && row.bits == 64 {
				continue
			}
			for _, register := range strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15 AL AH BL BH CL CH DL DH BPB SIB DIB R8B R15B X0 Y0 Z0 K1 M0 FS TLS R16") {
				t.Run(arch+"/"+row.name+"/"+register, func(t *testing.T) {
					valid := strings.Contains(" AX CX DX BX SP BP SI DI ", " "+register+" ") ||
						arch == "amd64" && regexp.MustCompile(`^R(?:[89]|1[0-5])$`).MatchString(register)
					if row.bits == 8 {
						valid = valid && (arch != "386" || register != "SP") ||
							strings.Contains(" AL AH BL BH CL CH DL DH ", " "+register+" ") ||
							arch == "amd64" && strings.Contains(" BPB SIB DIB R8B R15B ", " "+register+" ")
					}
					ins := x86YMMReadSource(t, row.name+" "+register)
					before := ins
					before.Args = append([]Operand(nil), ins.Args...)
					_, known, err := x86ImplicitDivideProperties(ins.Op, ins, arch)
					if !known || (err == nil) != valid || !reflect.DeepEqual(ins, before) {
						t.Fatal("Go Ymb/Yml register class or original identity changed", valid, err)
					}
					if valid {
						fmt.Fprintf(&witnesses, "TEXT ·Format%d(SB),4,$0-8\n%s\nRET\n", count, ins.Raw)
						count++
					}
				})
			}
			for _, memory := range []string{
				"(AX)", "1(AX)(CX*2)", "-128(BX)(SI*8)", "17", "·cell(SB)",
				"param+0(FP)", "tmp-8(SP)", "8(AX)(FS)", "8(AX)(GS)",
			} {
				t.Run(arch+"/"+row.name+"/"+memory, func(t *testing.T) {
					ins := x86YMMReadSource(t, row.name+" "+memory)
					if _, known, err := x86ImplicitDivideProperties(ins.Op, ins, arch); !known || err != nil {
						t.Fatal("complete memory grammar inferred a missing source permission", err)
					}
					fmt.Fprintf(&witnesses, "TEXT ·Format%d(SB),4,$0-8\n%s\nRET\n", count, ins.Raw)
					count++
				})
			}
		}
		if count == 0 {
			t.Fatal("empty complete original Go source-bank/shape inventory")
		}
		requireX86GoAssemblerResult(t, arch, witnesses.String(), true)
	}
}

func TestX86ImplicitDivideRejectsGrammarBeforeIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86ImplicitDivideOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			original := x86YMMReadSource(t, row.name+" CX")
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"dispatch", func(i *Instr) { i.Op = "MOVL" }},
				{"suffix", func(i *Instr) { i.Op += ".Z" }},
				{"missing-source", func(i *Instr) { i.Args = nil }},
				{"extra-source", func(i *Instr) { i.Args = append(i.Args, Operand{Kind: OpReg, Reg: DX}) }},
				{"immediate", func(i *Instr) { i.Args[0] = Operand{Kind: OpImm, Imm: 3} }},
				{"vector", func(i *Instr) { i.Args[0] = Operand{Kind: OpReg, Reg: "X0"} }},
				{"SIB-index", func(i *Instr) { i.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX, Index: SP, Scale: 1}} }},
				{"SIB-scale", func(i *Instr) { i.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX, Index: CX, Scale: 3}} }},
				{"address-immediate", func(i *Instr) { i.Args[0] = Operand{Kind: OpSym, Sym: "$·cell(SB)"} }},
			} {
				t.Run(arch+"/"+row.name+"/"+control.name, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					control.change(&ins)
					var ir strings.Builder
					ctx := &amd64Ctx{b: &ir, goarch: arch, targetTriple: triple}
					known, terminated, err := ctx.lowerScalarMultiplyDivide(Op(row.name), ins)
					if !known || terminated || err == nil || ir.Len() != 0 || ctx.tmp != 0 {
						t.Fatal("division emitted before its complete source grammar rejected", known, terminated, err, ir.String())
					}
				})
			}
		}
	}
}
