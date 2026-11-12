package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func arm64ControlMultiplyForms() []string {
	var forms []string
	for _, op := range []string{"MUL", "MULW", "MNEG", "MNEGW", "SMULL", "UMULL", "SMNEGL", "UMNEGL", "SMULH", "UMULH"} {
		forms = append(forms, op+" R4,R30", op+" R4,R5,R30")
	}
	for _, op := range []string{"MADD", "MSUB", "MADDW", "MSUBW", "SMADDL", "SMSUBL", "UMADDL", "UMSUBL"} {
		forms = append(forms, op+" R4,R5,R6,R30")
	}
	return forms
}

func TestARM64ControlScalarMultiplyCompleteGoRows(t *testing.T) {
	bytes, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(bytes)
	for _, family := range []struct {
		name string
		rows int
	}{
		{name: "AMUL", rows: 2}, {name: "AMADD", rows: 1},
	} {
		// Go 1.20 predates optab's extra suffix-class column. Both layouts
		// retain the same three input classes and one destination class.
		rows := regexp.MustCompile(`\{`+family.name+`, C_ZREG, C_(?:ZREG|NONE), C_(?:ZREG|NONE), C_ZREG,(?: C_NONE,)? 15,`).FindAllString(source, -1)
		if len(rows) != family.rows {
			t.Fatalf("Go %s operand rows changed: %v", family.name, rows)
		}
		block := regexp.MustCompile(`case ` + family.name + `:\s*\n((?:\s*oprangeset\([^\n]+\n)+)`).FindStringSubmatch(source)
		if len(block) != 2 {
			t.Fatalf("Go %s alias registration not recognized", family.name)
		}
		names := []string{strings.TrimPrefix(family.name, "A")}
		for _, alias := range regexp.MustCompile(`oprangeset\(A([A-Z0-9]+), t\)`).FindAllStringSubmatch(block[1], -1) {
			names = append(names, alias[1])
		}
		registered := make(map[string]bool)
		for _, form := range arm64ControlMultiplyForms() {
			parts := strings.SplitN(form, " ", 2)
			four := len(strings.Split(parts[1], ",")) == 4
			if four == (family.name == "AMADD") {
				registered[parts[0]] = true
			}
		}
		if len(registered) != len(names) {
			t.Fatalf("Go %s names differ from complete fixture: %v vs %v", family.name, names, registered)
		}
		for _, name := range names {
			if !registered[name] {
				t.Fatalf("Go %s alias %s is unobserved", family.name, name)
			}
		}
	}
}

func TestARM64ControlScalarMultiplyInputOutputDirection(t *testing.T) {
	for _, text := range arm64ControlMultiplyForms() {
		t.Run(text, func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT multiply(SB),$0-0\n"+text+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			requireARM64GoAssemblerResult(t, "TEXT multiply(SB),$0-0\n"+text+"\nRET\n", true)
			state := &arm64ControlState{regs: map[Reg]arm64ControlValue{"R30": arm64ControlFromMap(map[string]bool{"label:entry_lr": true})}, memory: make(map[string]arm64ControlValue)}
			state.transfer(ins, ins.Op, false, nil)
			value := arm64ControlRead(state.regs, "R30")
			if len(ins.Args) == 2 {
				if !arm64ControlHas(value, "code-derived:") {
					t.Fatal("two-operand multiply lost its destination input")
				}
			} else if arm64ControlCount(arm64ControlLabels(value)) != 0 {
				t.Fatalf("write-only multiply destination read its stale LR: %v", value)
			}
			// Every explicit source, including an alias of Rd, remains tainted.
			for index := 0; index < len(ins.Args)-1; index++ {
				alias := ins
				alias.Args = append([]Operand(nil), ins.Args...)
				alias.Args[index].Reg = "R30"
				state.regs["R30"] = arm64ControlFromMap(map[string]bool{"label:entry_lr": true})
				state.transfer(alias, alias.Op, false, nil)
				if !arm64ControlHas(arm64ControlRead(state.regs, "R30"), "code-derived:") {
					t.Fatalf("source %d alias washed away transformed caller PC", index)
				}
			}
		})
	}
}

func TestARM64ControlScalarMultiplyDerivedCodeAndInvalidFormsStayClosed(t *testing.T) {
	for _, form := range arm64ControlMultiplyForms() {
		if len(strings.Split(strings.SplitN(form, " ", 2)[1], ",")) == 2 {
			continue
		}
		body := "MOVD R30,R4\n" + form + "\nMOVD R5,(R1)(R30)\n"
		file, err := Parse(ArchARM64, arm64RawZeroFrameFixture(516, false, body))
		if err != nil {
			t.Fatal(err)
		}
		sig := arm64RawZeroFrameSig()
		_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{sig.Name: sig}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("computed caller PC gained a pure-code/disjointness permission: %s: %v", form, err)
		}
	}
	for _, text := range []string{"MUL $1,R4,R30", "MULW R4,(R5),R30", "MUL.P R4,R5,R30", "MULS R4,R5,R30", "MADD R4,R5,R30", "MADD RSP,R4,R5,R30"} {
		source := "TEXT bad(SB),$0-0\n" + text + "\nRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		ins := file.Funcs[0].Instrs[1]
		if _, _, valid := arm64ScalarMultiplyInputs(arm64ControlOp(ins), ins); valid {
			t.Fatalf("invalid Go multiply form supplied a write-direction proof: %s", text)
		}
		if _, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"bad": {Ret: Void}}}); err == nil {
			t.Fatalf("invalid Go multiply accepted: %s", text)
		}
	}
}

func TestARM64ControlScalarMultiplyCallerContinuationObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, text := range arm64ControlMultiplyForms() {
		if len(strings.Split(strings.SplitN(text, " ", 2)[1], ",")) == 2 {
			continue // This form actually consumes old Rd, independently tested above.
		}
		name := fmt.Sprintf("multiplyCaller%d", index)
		body := text + "\nMOVD R4,(R1)(R30)\n"
		source.WriteString(strings.Replace(arm64RawZeroFrameFixture(516, false, body), "rawZero", name, 1))
		sig := arm64RawZeroFrameSig()
		sig.Name = name
		sigs[name] = sig
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "multiply-caller.ll", "multiply-caller.o", ir)
	}
}
