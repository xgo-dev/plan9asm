package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86AuxiliaryCase struct {
	name string
	op   string
	bits int
	form int
}

// Operand axes are tested independently of the existing complete encoder-row
// tests. All arithmetic flag producers, including exchange/string comparisons,
// must feed the same architectural AF bit consumed by LAHF and PUSHF.
func x86AuxiliaryCases(arch string) []x86AuxiliaryCase {
	var cases []x86AuxiliaryCase
	widths := []int{8, 16, 32}
	if arch == "amd64" {
		widths = append(widths, 64)
	}
	for _, op := range []string{"ADD", "SUB", "ADC", "SBB", "CMP", "INC", "DEC", "NEG", "XADD", "CMPXCHG", "CMPS", "SCAS"} {
		forms := 4 // Register, memory source, memory destination, immediate.
		switch op {
		case "INC", "DEC", "NEG", "XADD", "CMPXCHG":
			forms = 2
		case "CMPS", "SCAS":
			forms = 3 // Single comparison; zero-count REP and REPN with NULL inputs.
		}
		for _, bits := range widths {
			for form := 0; form < forms; form++ {
				cases = append(cases, x86AuxiliaryCase{fmt.Sprintf("aux%d", len(cases)), op, bits, form})
			}
		}
	}
	return append(cases, x86AuxiliaryCase{"auxpopf", "POPF", 0, 0}, x86AuxiliaryCase{"auxsahf", "SAHF", 0, 0})
}

func x86AuxiliaryAssembly(arch string, cases []x86AuxiliaryCase) string {
	saved := "R8"
	if arch == "386" {
		saved = "BP"
	}
	return x86AuxiliaryAssemblyWithSavedRegister(arch, cases, saved)
}

func x86AuxiliaryAssemblyWithSavedRegister(arch string, cases []x86AuxiliaryCase, saved string) string {
	move, push, flags, slot := "Q", "Q", "Q", 8
	if arch == "386" {
		move, push, flags, slot = "L", "L", "L", 4
	}
	var source strings.Builder
	for _, row := range cases {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", row.name, slot*4)
		fmt.Fprintf(&source, "MOV%s out+0(FP),DI\nMOV%s a+%d(FP),BX\nMOV%s b+%d(FP),DX\nMOV%s seed+%d(FP),CX\n", move, move, slot, move, slot*2, move, slot*3)
		fmt.Fprintf(&source, "MOV%s BX,0(DI)\nMOV%s DX,8(DI)\n", move, move)
		if row.op == "SAHF" {
			fmt.Fprintf(&source, "MOV%s CX,AX\nSHL%s $8,AX\n", move, move)
		}
		if row.op == "CMPXCHG" {
			fmt.Fprintf(&source, "MOV%s DX,AX\n", move)
		}
		if row.op == "CMPS" || row.op == "SCAS" {
			// Use an ordinary GP, not AMD64's independently owned BP frame.
			fmt.Fprintf(&source, "PUSH%s %s\n", push, saved)
			fmt.Fprintf(&source, "MOV%s DI,%s\nMOV%s DI,SI\nADD%s $8,DI\nMOV%s BX,AX\n", move, saved, move, move, move)
		}
		fmt.Fprintf(&source, "PUSH%s CX\nPOPF%s\n", push, flags)
		suffix := map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[row.bits]
		opcode := row.op + suffix
		switch row.op {
		case "POPF": // The seed is already installed above.
		case "SAHF":
			source.WriteString("SAHF\n")
		case "CMPS", "SCAS":
			if row.form != 0 {
				fmt.Fprintf(&source, "MOV%s $0,CX\nMOV%s $0,SI\nMOV%s $0,DI\n", move, move, move)
				prefix := "REP"
				if row.form == 2 {
					prefix = "REPN"
				}
				fmt.Fprintf(&source, "%s\n", prefix)
			}
			fmt.Fprintf(&source, "%s\nMOV%s %s,DI\n", opcode, move, saved)
		case "INC", "DEC", "NEG":
			destination := "BX"
			if row.form == 1 {
				destination = "0(DI)"
			}
			fmt.Fprintf(&source, "%s %s\n", opcode, destination)
		case "XADD", "CMPXCHG":
			destination := "BX"
			if row.form == 1 {
				destination = "0(DI)"
			}
			fmt.Fprintf(&source, "%s DX,%s\n", opcode, destination)
		case "CMP":
			operands := []string{"BX,DX", "BX,8(DI)", "0(DI),DX", "BX,$1"}
			fmt.Fprintf(&source, "%s %s\n", opcode, operands[row.form])
		default:
			operands := []string{"DX,BX", "8(DI),BX", "DX,0(DI)", "$1,BX"}
			fmt.Fprintf(&source, "%s %s\n", opcode, operands[row.form])
		}
		fmt.Fprintf(&source, "PUSHF%s\nPOP%s CX\nMOV%s CX,24(DI)\nLAHF\nMOVB AH,32(DI)\n", flags, push, move)
		source.WriteString("SETCS 33(DI)\nSETPS 34(DI)\nSETEQ 35(DI)\nSETMI 36(DI)\nSETOS 37(DI)\nSETLT 38(DI)\n")
		if row.op == "CMPS" || row.op == "SCAS" {
			fmt.Fprintf(&source, "POP%s %s\n", push, saved)
		}
		source.WriteString("RET\n")
	}
	return source.String()
}

func TestX86AuxiliaryCarryOriginalPhysicalBPRemainsContext(t *testing.T) {
	cases := []x86AuxiliaryCase{{name: "PhysicalFrame", op: "CMPS", bits: 8}}
	source := x86AuxiliaryAssemblyWithSavedRegister("amd64", cases, "BP")
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // The whole-family owner retains the ordinary mode32 BP form.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source,
					"func PhysicalFrame(out *byte,a,b,seed uint64)", target.arch, target.triple, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("original BP source borrowed ordinary numerical GP transport", api, err)
				}
			}
		})
	}
}

func x86AuxiliaryOptions(arch, triple string, cases []x86AuxiliaryCase) Options {
	typ, slot := I64, int64(8)
	if arch == "386" {
		typ, slot = I32, 4
	}
	sigs := make(map[string]FuncSig, len(cases))
	for _, row := range cases {
		sigs[row.name] = FuncSig{Name: row.name, Args: []LLVMType{Ptr, typ, typ, typ}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: slot, Type: typ, Index: 1, Field: -1},
				{Offset: slot * 2, Type: typ, Index: 2, Field: -1},
				{Offset: slot * 3, Type: typ, Index: 3, Field: -1},
			}},
		}
	}
	return Options{Goarch: arch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	}
}

func TestX86AuxiliaryCarryWholeFamilyObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			cases := x86AuxiliaryCases(target.arch)
			source := x86AuxiliaryAssembly(target.arch, cases)
			requireX86GoAssemblerResult(t, target.arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, x86AuxiliaryOptions(target.arch, target.triple, cases))
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "auxiliary.ll", "auxiliary.o", ir)
			if !strings.Contains(ir, "%flags_af = alloca i1") {
				t.Fatal("arithmetic status consumers silently omit architectural AF")
			}
		})
	}
}
