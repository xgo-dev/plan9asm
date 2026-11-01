//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func armSymbolOffsetActualGo(t *testing.T, source string, success bool) {
	t.Helper()
	directory := t.TempDir()
	input, object := filepath.Join(directory, "symbol.s"), filepath.Join(directory, "symbol.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-p", "example.com/symbol", "-o", object, input)
	command.Dir = directory
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm", "GOARM=5")
	stdout, stderr, err := runtimeOracleMachineOutput(ctx, command)
	if failure := goasmoracle.CheckOutcome(input, object, stdout, stderr,
		err, ctx.Err(), success, 0, nil); failure != nil {
		t.Fatalf("actual Go ARM source prior failed: %v\n%s", failure, stderr)
	}
}

func TestARMSymbolOffsetNeedsGeneratedConstantContext(t *testing.T) {
	// cmd/asm/internal/asm/parse.go symbolReference consumes a signed expr
	// after the symbol; expr/term/factor use integer Go precedence, not a
	// second symbol relocation. The generated-header identifiers below are
	// replaced only in the independent stock-Go prior, never in the probe.
	var instructions []string
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, suffix := range []string{"", ".EQ", ".NE.P"} {
			instructions = append(instructions,
				op+suffix+" ·memory+OFFSET(SB),R2",
				op+suffix+" R2,·memory-OFFSET(SB)")
		}
	}
	for _, expression := range []string{
		"+(OFFSET+4)", "+(OFFSET*2)", "+(OFFSET/2)", "+(OFFSET%3)",
		"+(OFFSET<<1)", "+(OFFSET>>1)", "+(OFFSET&3)", "+(OFFSET|3)",
		"+(OFFSET^3)", "+(~OFFSET)", "+(OFFSET+'x')",
		"+(OFFSET/(OFFSET+1))", "+(1/(OFFSET-1))", "+(OFFSET<<OFFSET)",
	} {
		instructions = append(instructions, "MOVW ·memory"+expression+"(SB),R2")
	}
	instructions = append(instructions,
		"MOVW $·memory+OFFSET(SB),R2", "MOVW.EQ $·memory-OFFSET(SB),R2",
		"MOVB internal∕cpu·ARM+const_offsetARMHasV7Atomics(SB),R11",
		"MOVBU internal∕cpu·ARM+const_offsetARMHasIDIVA(SB),R11")
	definitions := "#define OFFSET 4\n#define const_offsetARMHasV7Atomics 8\n#define const_offsetARMHasIDIVA 12\n"
	armSymbolOffsetActualGo(t, definitions+"TEXT symbolic(SB),$0-0\n"+
		strings.Join(instructions, "\n")+"\nRET\n", true)

	for _, row := range instructions {
		t.Run(row, func(t *testing.T) {
			file, err := Parse(ArchARM, "TEXT symbolic(SB),$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			original := append([]Operand(nil), instruction.Args...)
			for _, err := range []error{
				ProbeInstruction(ArchARM, "arm", instruction),
				ProbeInstructionSequence(ArchARM, "arm", []Instr{instruction}),
			} {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("valid unresolved symbol addend lost its source context: %v", err)
				}
			}
			options := Options{Goarch: "arm", TargetTriple: "armv5te-unknown-linux-gnueabi",
				Sigs: map[string]FuncSig{"symbolic": {Name: "symbolic", Ret: Void}}}
			if _, err := Translate(file, options); err == nil {
				t.Error("unresolved symbol addend acquired a guessed numerical relocation")
			}
			module, err := TranslateModule(file, options)
			if !module.IsNil() {
				module.Dispose()
			}
			if err == nil {
				t.Error("unresolved symbol addend acquired a direct-module relocation")
			}
			if !reflect.DeepEqual(file.Funcs[0].Instrs[1].Args, original) {
				t.Fatal("probe/translation rewrote the original unresolved symbol operand")
			}
		})
	}
}

func TestARMSymbolOffsetContextDoesNotHideInvalidForms(t *testing.T) {
	var instructions []string
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		instructions = append(instructions,
			op+" ·memory+OFFSET(SB),SP", op+" SP,·memory+OFFSET(SB)",
			op+".S ·memory+OFFSET(SB),R2", op+" ·memory+OFFSET(SB),·other(SB)")
		if op != "MOVW" {
			instructions = append(instructions, op+" $·memory+OFFSET(SB),R2")
		}
	}
	instructions = append(instructions,
		"MOVW ·memory+(OFFSET+)(SB),R2", "MOVW ·memory+(OFFSET/0)(SB),R2",
		"MOVW ·memory+(OFFSET%0)(SB),R2", "MOVW ·memory+(OFFSET<<-1)(SB),R2",
		"MOVW ·memory+(OFFSET<<1*2)(SB),R2", "MOVW ·memory+(OFFSET<<1<<2)(SB),R2",
		"MOVW ·memory+((-1)/OFFSET)(SB),R2", "MOVW ·memory+((1<<63)>>OFFSET)(SB),R2",
		"MOVW ·memory+1.5(SB),R2", "MOVW ·memory+(OFFSET==4)(SB),R2",
		"MOVW ·memory+OFFSET(XX),R2", "MOVW ·memory+OFFSET(SB)",
		"MOVW ·memory+OFFSET(SB),R2,R3")
	for _, row := range instructions {
		t.Run(row, func(t *testing.T) {
			source := "#define OFFSET 4\nTEXT invalidsymbol(SB),$0-0\n" + row + "\nRET\n"
			armSymbolOffsetActualGo(t, source, false)
			file, err := Parse(ArchARM, strings.Replace(source, "#define OFFSET 4\n", "", 1))
			if err != nil {
				return // A real parser refusal cannot acquire an instruction role.
			}
			instruction := file.Funcs[0].Instrs[1]
			for _, err := range []error{
				ProbeInstruction(ArchARM, "arm", instruction),
				ProbeInstructionSequence(ArchARM, "arm", []Instr{instruction}),
			} {
				if err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("invalid complete operand grammar was hidden as source context: %v", err)
				}
			}
		})
	}
}

func TestARMSymbolOffsetConcreteFormsStayConcrete(t *testing.T) {
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, row := range []string{op + " ·memory+4(SB),R2", op + " R2,·memory-4(SB)"} {
			t.Run(row, func(t *testing.T) {
				file, err := Parse(ArchARM, fmt.Sprintf("TEXT concrete(SB),$0-0\n%s\nRET\n", row))
				if err != nil {
					t.Fatal(err)
				}
				if err := ProbeInstruction(ArchARM, "arm", file.Funcs[0].Instrs[1]); err != nil {
					t.Fatalf("concrete symbol displacement became unresolved: %v", err)
				}
			})
		}
	}
}
