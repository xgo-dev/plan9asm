package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The fixture encoding is independent of the production decoder. ARM ARM
// DDI0406C.c VCMP/VCMPE A1 has E at bit 7 and sz at bit 8. Go asm5 types
// 82/83 select E=1 and append VMRS APSR_nzcv,FPSCR, with the same condition.
type armCompareMatrixForm struct {
	bits, lhs, rhs int
	kind           string
	zero, live     bool
	condition      string
}

func (form armCompareMatrixForm) word() uint32 {
	word := uint32(0xeeb40a40)
	if form.kind == "signaling" || form.kind == "named" {
		word |= 1 << 7
	}
	if form.bits == 64 {
		word |= 1 << 8
		word |= uint32(form.lhs%16)<<12 | uint32(form.lhs/16)<<22
		if !form.zero {
			word |= uint32(form.rhs%16) | uint32(form.rhs/16)<<5
		}
	} else {
		word |= uint32(form.lhs/2)<<12 | uint32(form.lhs%2)<<22
		if !form.zero {
			word |= uint32(form.rhs/2) | uint32(form.rhs%2)<<5
		}
	}
	if form.zero {
		word |= 1 << 16
	}
	return word
}

func (form armCompareMatrixForm) instruction() string {
	if form.kind != "named" {
		return fmt.Sprintf("WORD $%#x", form.word())
	}
	op, lhs, rhs := "CMPD", form.lhs, form.rhs
	if form.bits == 32 {
		op, lhs, rhs = "CMPF", lhs/2, rhs/2
	}
	if form.condition != "" {
		op += "." + form.condition
	}
	if form.zero {
		return fmt.Sprintf("%s F%d", op, lhs)
	}
	return fmt.Sprintf("%s F%d,F%d", op, rhs, lhs)
}

func armCompareMatrixBanks() []armCompareMatrixForm {
	var forms []armCompareMatrixForm
	for _, bits := range []int{32, 64} {
		for _, kind := range []string{"named", "quiet", "signaling"} {
			banks := 32
			if kind == "named" {
				banks = 16
			}
			for bank := 0; bank < banks; bank++ {
				lhs, rhs := bank, (bank+7)%banks
				if kind == "named" && bits == 32 {
					lhs, rhs = lhs*2, rhs*2
				}
				for _, shape := range []string{"zero", "register", "alias"} {
					form := armCompareMatrixForm{bits: bits, kind: kind, lhs: lhs, rhs: rhs, zero: shape == "zero", live: true}
					if shape == "alias" {
						form.rhs = form.lhs
					}
					forms = append(forms, form)
				}
			}
		}
	}
	return forms
}

func armCompareMatrixStates() []armCompareMatrixForm {
	var forms []armCompareMatrixForm
	for _, bits := range []int{32, 64} {
		for _, kind := range []string{"named", "quiet", "signaling"} {
			for _, live := range []bool{false, true} {
				for _, shape := range []string{"zero", "register", "alias"} {
					form := armCompareMatrixForm{bits: bits, kind: kind, lhs: 0, rhs: 2, zero: shape == "zero", live: live}
					if shape == "alias" {
						form.rhs = form.lhs
					}
					forms = append(forms, form)
				}
			}
		}
	}
	return forms
}

func armCompareMatrixConditions() []armCompareMatrixForm {
	var forms []armCompareMatrixForm
	for _, bits := range []int{32, 64} {
		for _, condition := range []string{"AL", "EQ", "NE", "CS", "HS", "CC", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE"} {
			for _, zero := range []bool{false, true} {
				forms = append(forms, armCompareMatrixForm{bits: bits, kind: "named", lhs: 0, rhs: 2, zero: zero, live: true, condition: condition})
			}
		}
	}
	return forms
}

// Only the runtime harness loads/stores the complete physical D bank. The
// smaller object matrix exercises exactly the same compare and source proof.
func armCompareMatrixSource(forms []armCompareMatrixForm, fullBank bool) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, form := range forms {
		name := fmt.Sprintf("matrixCompare%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-12\nMOVW input+0(FP),R0\nMOVW output+4(FP),R1\n", name)
		if fullBank {
			for bank := 0; bank < 32; bank++ {
				word := uint32(0xed900b00 | (bank%16)<<12 | (bank/16)<<22 | bank*2)
				fmt.Fprintf(&source, "WORD $%#x\n", word)
			}
		}
		source.WriteString("WORD $0xeef14a10\nMOVW 256(R0),R3\nWORD $0xeee13a10\n")
		if form.kind == "named" || form.live {
			// A typed parameter is an existing whole-value CPSR witness. This
			// does not grant an unproved pointer load native status authority.
			source.WriteString("MOVW status+8(FP),R2\nMOVW R2,CPSR\n")
		}
		source.WriteString(form.instruction() + "\n")
		if form.kind != "named" && form.live {
			source.WriteString("WORD $0xeef1fa10\n")
		}
		if form.live {
			source.WriteString("MOVW CPSR,R2\nAND $0xf0000000,R2\nMOVW R2,260(R1)\n")
		}
		source.WriteString("WORD $0xeef13a10\nWORD $0xeee14a10\nMOVW R3,256(R1)\n")
		if fullBank {
			for bank := 0; bank < 32; bank++ {
				word := uint32(0xed810b00 | (bank%16)<<12 | (bank/16)<<22 | bank*2)
				fmt.Fprintf(&source, "WORD $%#x\n", word)
			}
		}
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, I32}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: Ptr, Index: 1, Field: -1},
				{Offset: 8, Type: I32, Index: 2, Field: -1},
			}},
		}
	}
	return source.String(), sigs
}

func armCompareMatrixTranslate(t *testing.T, file *File, options Options, api string) (string, error) {
	t.Helper()
	if api == "Translate" {
		return Translate(file, options)
	}
	if api == "TranslateModule" {
		module, err := TranslateModule(file, options)
		if err != nil {
			return "", err
		}
		defer module.Dispose()
		return module.String(), nil
	}
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, options)
	if err != nil {
		return "", err
	}
	defer module.Dispose()
	return module.String(), nil
}

func TestARMScalarCompareFullMatrixObjects(t *testing.T) {
	forms := armCompareMatrixBanks()
	if len(forms) != 480 {
		t.Fatalf("incomplete bank/alias matrix: %d", len(forms))
	}
	forms = append(forms, armCompareMatrixConditions()...)
	source, sigs := armCompareMatrixSource(forms, false)
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := armCompareMatrixTranslate(t, file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs}, api)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "arm-compare-matrix.ll", "arm-compare-matrix.o", ir)
			})
		}
	}
}

func TestARMScalarCompareFullMatrixNativeEffects(t *testing.T) {
	forms := armCompareMatrixStates()
	source, sigs := armCompareMatrixSource(forms, false)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(api, func(t *testing.T) {
			ir, err := armCompareMatrixTranslate(t, file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs}, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
				if count := strings.Count(variant.ir, `asm sideeffect "vcmp`); count != len(forms) {
					t.Errorf("%s native compare effects: got %d want %d (including dead APSR)", variant.name, count, len(forms))
				}
				if strings.Contains(variant.ir, " = fcmp ") {
					t.Errorf("%s substitutes a pure comparison for native FPSCR effects", variant.name)
				}
			}
		})
	}
}

func TestARMScalarCompareFullMatrixClosedRawFlagsBoundary(t *testing.T) {
	for _, bits := range []int{32, 64} {
		for _, kind := range []string{"quiet", "signaling"} {
			form := armCompareMatrixForm{bits: bits, kind: kind, lhs: 1, rhs: 31}
			for _, sequence := range []string{
				fmt.Sprintf("WORD $%#x\nMOVW CPSR,R2", form.word()),
				fmt.Sprintf("WORD $%#x\nMOVW $0,R3\nWORD $0xeef1fa10\nMOVW CPSR,R2", form.word()),
				fmt.Sprintf("WORD $%#x\nWORD $0x0ef1fa10\nMOVW CPSR,R2", form.word()&0x0fffffff),
			} {
				source := "TEXT boundary(SB),4,$0-0\nMOVW $0x60000000,R2\nMOVW R2,CPSR\n" + sequence + "\nRET\n"
				requireARMGoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM, source)
				if err != nil {
					t.Fatal(err)
				}
				for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					ir, err := armCompareMatrixTranslate(t, file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"boundary": {Name: "boundary", Ret: Void}}}, api)
					if err == nil || ir != "" || !strings.Contains(err.Error(), "closed unconditional compare/VMRS") {
						t.Fatalf("%s silently widened raw flags authority: %s: %v", api, sequence, err)
					}
				}
			}
		}
	}
}

func TestARMScalarCompareFullMatrixRawPredicateRequiresAllPaths(t *testing.T) {
	for name, prefix := range map[string]string{
		"bypassed_writer":   "B compare\nMOVW $0,R0\nCMP R0,R0\ncompare:\n",
		"call_kills_writer": "MOVW $0,R0\nCMP R0,R0\nCALL helper(SB)\n",
		"one_path_calls":    "MOVW $0,R0\nCMP R0,R0\nBEQ compare\nCALL helper(SB)\ncompare:\n",
	} {
		for _, word := range []uint32{0x0eb50a40, 0x1eb50ac0, 0x0eb50b40, 0x1eb50bc0} {
			t.Run(fmt.Sprintf("%s/%08x", name, word), func(t *testing.T) {
				// No following modeled condition/CPSR read can accidentally
				// trigger the status proof on behalf of this raw predicate.
				source := "TEXT helper(SB),4,$0-0\nRET\nTEXT boundary(SB),4,$0-0\n" + prefix + fmt.Sprintf("WORD $%#x\nRET\n", word)
				requireARMGoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM, source)
				if err != nil {
					t.Fatal(err)
				}
				sigs := map[string]FuncSig{"boundary": {Name: "boundary", Ret: Void}, "helper": {Name: "helper", Ret: Void}}
				for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					ir, err := armCompareMatrixTranslate(t, file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs}, api)
					if err == nil || ir != "" {
						t.Errorf("%s admitted raw predicate without all-path status authority: %v", api, err)
					}
				}
			})
		}
	}
}
