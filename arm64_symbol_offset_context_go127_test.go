//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const arm64SymbolOffsetDefinitions = "#define OFFSET 4\n" +
	"#define const_offsetARM64HasATOMICS 8\n#define machTimebaseInfo_denom 4\n"

// Independent asm7 C_ADDR rows 64/65 cover these seven spellings. Row 68
// additionally admits MOVD/MOVWU address values, not the five narrow aliases.
func arm64SymbolOffsetContextRows() []string {
	var rows []string
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		rows = append(rows,
			op+" ·memory+OFFSET(SB),R2", op+" R2,·memory-OFFSET(SB)",
			op+" ZR,·memory+OFFSET(SB)", op+" $0,·memory+OFFSET(SB)",
			op+" ·memory+OFFSET(SB),ZR", op+" ·memory+OFFSET(SB),R27")
	}
	for _, expression := range []string{
		"+(OFFSET+4)", "+(OFFSET*2)", "+(OFFSET/2)", "+(OFFSET%3)",
		"+(OFFSET<<1)", "+(OFFSET>>1)", "+(OFFSET&3)", "+(OFFSET|3)",
		"+(OFFSET^3)", "+(~OFFSET)", "+(OFFSET+'x')",
		"+(OFFSET/(OFFSET+1))", "+(1/(OFFSET-1))", "+(OFFSET<<OFFSET)",
	} {
		rows = append(rows, "MOVD ·memory"+expression+"(SB),R2")
	}
	rows = append(rows,
		"MOVD $·memory+OFFSET(SB),R2", "MOVWU $·memory-OFFSET(SB),R2",
		"MOVD ·memory<>+OFFSET(SB),R2", "MOVD R2,·memory<>-OFFSET(SB)",
		"MOVBU internal∕cpu·ARM64+const_offsetARM64HasATOMICS(SB),R4",
		"MOVD $timebase<>+machTimebaseInfo_denom(SB),R21",
		"MOVD $timebase<>+machTimebaseInfo_denom(SB),R22")
	return rows
}

func TestARM64SymbolOffsetNeedsGeneratedConstantContext(t *testing.T) {
	rows := arm64SymbolOffsetContextRows()
	if len(rows) != 63 {
		t.Fatal("incomplete independent seven-member memory/address inventory", len(rows))
	}
	// Only this original-Go prior receives generated definitions. The public
	// probes and translations retain the exact unresolved source below.
	requireARM64GoAssemblerResult(t, arm64SymbolOffsetDefinitions+
		"TEXT symbolic(SB),$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", true)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			source := "TEXT symbolic(SB),$0-0\n" + row + "\nRET\n"
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			original := append([]Operand(nil), instruction.Args...)
			for _, err := range []error{
				ProbeInstruction(ArchARM64, "arm64", instruction),
				ProbeInstructionSequence(ArchARM64, "arm64", []Instr{instruction}),
			} {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("valid unresolved GP symbol addend lost its source context: %v", err)
				}
			}
			options := Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"symbolic": {Name: "symbolic", Ret: Void}}}
			ir, err := Translate(file, options)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Errorf("unresolved GP symbol acquired textual output or lost Context: IR=%q error=%v", ir, err)
			}
			module, err := TranslateModule(file, options)
			empty := module.IsNil()
			if !empty {
				module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) || !empty {
				t.Errorf("unresolved GP symbol acquired a module or lost Context: empty=%v error=%v", empty, err)
			}
			if !reflect.DeepEqual(file.Funcs[0].Instrs[1].Args, original) ||
				file.Funcs[0].Instrs[1].Raw != row {
				t.Fatal("probe/translation changed the original unresolved operand")
			}
		})
	}
}

func TestARM64SymbolOffsetContextDoesNotHideInvalidForms(t *testing.T) {
	var rows []string
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		rows = append(rows,
			op+".P ·memory+OFFSET(SB),R2", op+".W R2,·memory+OFFSET(SB)",
			op+" ·memory+OFFSET(SB),SP", op+" RSP,·memory+OFFSET(SB)",
			op+" ·memory+OFFSET(SB),W2", op+" R27,·memory+OFFSET(SB)",
			op+" ·memory+OFFSET(SB),·other(SB)", op+" $0.0,·memory+OFFSET(SB)",
			op+" ·memory+OFFSET(SB)", op+" ·memory+OFFSET(SB),R2,R3")
		if op != "MOVD" && op != "MOVWU" {
			rows = append(rows, op+" $·memory+OFFSET(SB),R2")
		}
	}
	for _, op := range []string{"MOVD", "MOVWU"} {
		rows = append(rows,
			op+".P $·memory+OFFSET(SB),R2", op+".W $·memory+OFFSET(SB),R2",
			op+" $·memory+OFFSET(SB),SP", op+" $·memory+OFFSET(SB),W2")
	}
	for _, expression := range []string{
		"+(OFFSET+)", "+(OFFSET/0)", "+(OFFSET%0)", "+(OFFSET<<-1)",
		"+(OFFSET<<1*2)", "+(OFFSET<<1<<2)", "+((-1)/OFFSET)",
		"+((1<<63)>>OFFSET)", "+1.5", "+(OFFSET==4)",
	} {
		rows = append(rows, "MOVD ·memory"+expression+"(SB),R2")
	}
	rows = append(rows,
		"MOVD ·memory+OFFSET(XX),R2", "MOVD ·memory+OFFSET(SB),F2",
		"MOVD F2,·memory+OFFSET(SB)", "MOVD $1,·memory+OFFSET(SB)")
	if len(rows) != 97 {
		t.Fatal("incomplete independent invalid GP symbol inventory", len(rows))
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			source := "TEXT invalidsymbol(SB),$0-0\n" + row + "\nRET\n"
			requireARM64GoAssemblerResult(t, arm64SymbolOffsetDefinitions+source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			instruction := file.Funcs[0].Instrs[1]
			for _, err := range []error{
				ProbeInstruction(ArchARM64, "arm64", instruction),
				ProbeInstructionSequence(ArchARM64, "arm64", []Instr{instruction}),
			} {
				if err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("invalid complete GP grammar was hidden as Context: %v", err)
				}
			}
		})
	}
}

func TestARM64SymbolOffsetConcreteFormsStayConcrete(t *testing.T) {
	var rows []string
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		rows = append(rows, op+" ·memory+4(SB),R2", op+" R2,·memory-4(SB)")
	}
	rows = append(rows, "MOVD $·memory+4(SB),R2", "MOVWU $·memory-4(SB),R2")
	requireARM64GoAssemblerResult(t, "TEXT concrete(SB),$0-0\n"+
		strings.Join(rows, "\n")+"\nRET\n", true)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			file, err := Parse(ArchARM64, fmt.Sprintf("TEXT concrete(SB),$0-0\n%s\nRET\n", row))
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			if strings.Contains(row, "$·memory") {
				if err := ProbeInstruction(ArchARM64, "arm64", instruction); err != nil {
					t.Fatalf("a concrete GP address became unresolved: %v", err)
				}
				return
			}
			op, _ := splitOpcode(row)
			form, handled, err := parseARM64ScalarMemoryForm(Op(op), instruction)
			store := strings.Contains(row, " R2,")
			wantSymbol, wantOffset := "·memory+4(SB)", int64(4)
			if store {
				wantSymbol, wantOffset = "·memory-4(SB)", -4
			}
			bits := map[string]int{"MOVB": 8, "MOVBU": 8, "MOVH": 16, "MOVHU": 16,
				"MOVW": 32, "MOVWU": 32, "MOVD": 64}[op]
			if !handled || err != nil || form.memory.Kind != OpSym || form.memory.Sym != wantSymbol ||
				form.data != "R2" || form.store != store || form.bits != bits ||
				form.signed != (op == "MOVB" || op == "MOVH" || op == "MOVW") ||
				form.pre || form.post || !form.scratch || !form.scratchAddress || form.scratchKnown {
				t.Fatalf("concrete typed symbol/access facts changed: %+v handled=%v error=%v", form, handled, err)
			}
			if symbol, offset, resolved := parseSBRef(form.memory.Sym); !resolved ||
				symbol != "·memory" || offset != wantOffset {
				t.Fatalf("concrete relocation was not retained: %q offset=%d resolved=%v", symbol, offset, resolved)
			}
			// This isolated probe has no original Go R27/layout observation.
			// Concrete syntax cannot manufacture that independent authority.
			if err := ProbeInstruction(ArchARM64, "arm64", instruction); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "unbound original Go memory scratch") ||
				strings.Contains(err.Error(), "generated assembler constants") {
				t.Fatalf("concrete offset lost its existing physical-scratch boundary: %v", err)
			}
		})
	}
}
