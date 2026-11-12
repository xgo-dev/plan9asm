package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// All helpers have register-only source contracts, without Go declarations.
// Only Value owns arguments, results and the ordinary Go entry/return ABI.
func x86PrivateCallSource(arch, body, helpers string) (string, string) {
	source := `TEXT ·Value(SB),4,$0-24
 MOVQ a+0(FP),AX
 MOVQ b+8(FP),BX
 ` + body + `
 MOVQ AX,ret+16(FP)
 RET
` + helpers
	declaration := "func Value(a,b uint64) uint64"
	if arch == "386" {
		source = strings.NewReplacer("$0-24", "$0-12", "b+8(FP)", "b+4(FP)", "ret+16(FP)", "ret+8(FP)",
			"MOVQ", "MOVL", "ADDQ", "ADDL", "SUBQ", "SUBL", "CMPQ", "CMPL", "ROLQ", "ROLL").Replace(source)
		declaration = strings.ReplaceAll(declaration, "uint64", "uint32")
	}
	return source, declaration
}

func x86PrivateCallCases() []struct{ name, body, helpers string } {
	return []struct{ name, body, helpers string }{
		{"two_calls", "CALL helper<>(SB)\n ROLQ $1,AX\n MOVQ $3,BX\n CALL helper<>(SB)",
			"TEXT helper<>(SB),4,$0-0\n ADDQ BX,AX\n RET\n"},
		{"incoming_flags", "CMPQ AX,BX\n CALL helper<>(SB)\n SETCS CL\n MOVBLZX CL,AX",
			"TEXT helper<>(SB),4,$0-0\n MOVQ AX,DX\n MOVL BX,X0\n RET\n"},
		{"nested_incoming_flags", "CMPQ AX,BX\n CALL outer<>(SB)\n SETCS CL\n MOVBLZX CL,AX",
			"TEXT outer<>(SB),4,$0-0\n CALL inner<>(SB)\n RET\nTEXT inner<>(SB),4,$0-0\n MOVQ AX,DX\n RET\n"},
		{"outgoing_flags", "CALL helper<>(SB)\n SETCS CL\n MOVBLZX CL,AX",
			"TEXT helper<>(SB),4,$0-0\n CMPQ AX,BX\n RET\n"},
		{"vector_result", "CALL helper<>(SB)\n MOVL X0,AX\n PSRLDQ $12,X0\n MOVL X0,CX\n ADDQ CX,AX",
			"TEXT helper<>(SB),4,$0-0\n MOVL BX,X0\n MOVL AX,X1\n PSLLDQ $12,X1\n POR X1,X0\n RET\n"},
		{"nested_return", "CALL outer<>(SB)", `TEXT outer<>(SB),4,$0-0
 CALL inner<>(SB)
 ADDQ $1,AX
 RET
TEXT inner<>(SB),4,$0-0
 ADDQ BX,AX
 RET
`},
		{"nested_noframe_tail", "CALL outer<>(SB)", `TEXT outer<>(SB),516,$0-0
 CALL inner<>(SB)
 JMP last<>(SB)
TEXT inner<>(SB),4,$0-0
 ADDQ BX,AX
 RET
TEXT last<>(SB),4,$0-0
 ADDQ $1,AX
 RET
`},
		{"called_leaf_tail", "CALL first<>(SB)", `TEXT first<>(SB),4,$0-0
 JMP last<>(SB)
TEXT last<>(SB),4,$0-0
 ADDQ BX,AX
 RET
`},
		{"two_returns", "CALL helper<>(SB)", `TEXT helper<>(SB),4,$0-0
 CMPQ AX,BX
 JB less
 ADDQ $1,AX
 RET
less:
 SUBQ $1,AX
 RET
`},
		{"two_call_flags", "CMPQ AX,BX\n CALL helper<>(SB)\n MOVQ DX,AX\n CMPQ AX,$1\n CALL helper<>(SB)\n MOVQ DX,AX",
			"TEXT helper<>(SB),4,$0-0\n SETCS CL\n MOVBLZX CL,DX\n RET\n"},
		{"two_call_vectors", "MOVL AX,X0\n CALL helper<>(SB)\n MOVL X1,AX\n MOVL BX,X0\n CALL helper<>(SB)\n MOVL X1,BX\n ADDQ BX,AX",
			"TEXT helper<>(SB),4,$0-0\n MOVOU X0,X1\n RET\n"},
	}
}

func x86PrivateCallWholeSource(arch string) (string, string) {
	var assembly, declarations strings.Builder
	for index, row := range x86PrivateCallCases() {
		source, declaration := x86PrivateCallSource(arch, row.body, row.helpers)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.NewReplacer("·Value", "·"+name, "<>", fmt.Sprintf("%d<>", index)).Replace(source))
		declarations.WriteString(strings.Replace(declaration, "Value", name, 1) + "\n")
	}
	return assembly.String(), declarations.String()
}

func TestX86PrivateCallSourceContinuations(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range x86PrivateCallCases() {
			source, declaration := x86PrivateCallSource(arch, row.body, row.helpers)
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err != nil {
						t.Fatal("closed ordinary helper call rejected", err)
					}
					if strings.Count(ir, "define ") != 1 || strings.Contains(ir, "call void") || strings.Contains(ir, "call i") {
						t.Fatal("private source continuation acquired a standalone helper ABI", ir)
					}
				})
			}
		}
	}
}

func TestX86PrivateCallKeepsOriginalPointsAndReturnSites(t *testing.T) {
	row := x86PrivateCallCases()[0]
	source, declaration := x86PrivateCallSource("amd64", row.body, row.helpers)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	before := x86DirectTailSnapshot(file)
	resolve := testResolveSym("example.com/privatecalls")
	sigs, err := goSigsForAsmFile(mustGoPackage(t, "example.com/privatecalls", "package p\n"+declaration), file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatal("fixture invented helper signatures", sigs)
	}
	prepared, err := PrepareX86DirectTailSource(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	view := prepared.x86DirectTailView("·Value")
	if view == nil {
		t.Fatal("complete call graph was not prepared")
	}
	if _, err := view.graph.root(0, map[string]int{"·Value": 0, "helper<>": 1}, 4096, false); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("ordinary CALL support widened the separate custom-register helper route", err)
	}
	returns := make(map[int]bool)
	for pc, point := range view.points {
		original := file.Funcs[point.text].Instrs[point.instruction]
		if !reflect.DeepEqual(view.instructions[pc], original) || view.ordinals[pc] != point.instruction {
			t.Fatal("continuation rewrote original source coordinates", pc, point)
		}
		if point.text != view.text && original.Op == OpRET {
			if len(view.edges[pc]) != 1 {
				t.Fatal("called helper RET has no unique original callsite continuation", pc, view.edges[pc])
			}
			next := view.edges[pc][0]
			if next < 0 || next >= len(view.points) || view.points[next].text != view.text {
				t.Fatal("helper RET escaped its real caller", next)
			}
			returns[next] = true
		}
	}
	if len(returns) != 2 || !reflect.DeepEqual(file, before) || len(sigs) != 1 {
		t.Fatal("two callsites merged their returns or mutated source/signatures", returns)
	}
	seen := make(map[string]bool)
	for _, block := range view.blocks() {
		if seen[block.name] {
			t.Fatal("duplicated source point reused another callsite's LLVM block", block.name)
		}
		seen[block.name] = true
	}
	file.Funcs[1].Instrs[1].Raw += " // changed after complete call graph preparation"
	if _, err := PrepareX86DirectTailSource(prepared, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs,
	}); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed original helper retained both prepared callsite copies", err)
	}
}

func TestX86PrivateCallAuditsBeforeKeepFunc(t *testing.T) {
	row := x86PrivateCallCases()[0]
	complete, declaration := x86PrivateCallSource("amd64", row.body, row.helpers)
	other, _ := x86PrivateCallSource("amd64", "MOVQ DX,BX\n CALL helper<>(SB)", "")
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			source := complete
			declarations := declaration
			if invalid {
				source += strings.Replace(other, "·Value", "·Other", 1)
				declarations += "\nfunc Other(a,b uint64) uint64"
			}
			pkg := mustGoPackage(t, "example.com/privatecalls", "package p\n"+declarations)
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path),
				KeepFunc: func(source, _ string) bool { return source == "·Value" },
			})
			if translated != nil {
				defer translated.Module.Dispose()
			}
			if invalid {
				if translated != nil || err == nil {
					t.Fatal("KeepFunc hid a callsite's undefined helper input", err)
				}
			} else if err != nil || translated == nil || len(translated.Functions) != 1 {
				t.Fatal("complete private call source did not retain its sole declared root", err)
			}
		})
	}
}

func TestX86PrivateCallRejectsUnclosedSource(t *testing.T) {
	const helper = "TEXT helper<>(SB),4,$0-0\n ADDQ BX,AX\n RET\n"
	for _, row := range []struct{ name, body, helpers string }{
		{"missing_input", "CALL helper<>(SB)", strings.Replace(helper, "BX,AX", "DX,AX", 1)},
		{"second_call_missing_flags", "CMPQ AX,BX\n CALL helper<>(SB)\n MULQ BX\n CALL helper<>(SB)",
			"TEXT helper<>(SB),4,$0-0\n SETEQ CL\n MOVBLZX CL,AX\n RET\n"},
		{"no_root_result", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n MOVQ DX,AX\n RET\n"},
		{"helper_FP", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n MOVQ a+0(FP),AX\n RET\n"},
		{"helper_result_FP", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n MOVQ AX,ret+16(FP)\n RET\n"},
		{"helper_SP", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n MOVQ 0(SP),AX\n RET\n"},
		{"helper_BP", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n MOVQ BP,AX\n RET\n"},
		{"helper_implicit_stack", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n PUSHQ AX\n POPQ DX\n RET\n"},
		{"helper_unbalanced_stack", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n PUSHQ AX\n RET\n"},
		{"helper_raw", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n BYTE $0x90\n RET\n"},
		{"helper_frame", "CALL helper<>(SB)", strings.Replace(helper, "$0-0", "$8-0", 1)},
		{"helper_args", "CALL helper<>(SB)", strings.Replace(helper, "$0-0", "$0-8", 1)},
		{"helper_split", "CALL helper<>(SB)", strings.Replace(helper, ",4,", ",0,", 1)},
		{"helper_wrapper", "CALL helper<>(SB)", strings.Replace(helper, ",4,", ",36,", 1)},
		{"recursive", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n CALL helper<>(SB)\n RET\n"},
		{"mutual_recursive", "CALL helper<>(SB)", "TEXT helper<>(SB),516,$0-0\n CALL other<>(SB)\n RET\nTEXT other<>(SB),516,$0-0\n CALL helper<>(SB)\n RET\n"},
		{"tail_recursive", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n CALL next<>(SB)\n RET\nTEXT next<>(SB),4,$0-0\n JMP last<>(SB)\nTEXT last<>(SB),4,$0-0\n CALL next<>(SB)\n RET\n"},
		{"indirect", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n CALL AX\n RET\n"},
		{"foreign_call", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n CALL foreign(SB)\n RET\n"},
		{"address_escape", "LEAQ helper<>(SB),CX\n CALL helper<>(SB)", helper},
		{"offset_call", "CALL helper<>+1(SB)", helper},
		{"foreign_tail", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n JMP foreign(SB)\n"},
		{"implicit_BP_tail", "CALL helper<>(SB)", "TEXT helper<>(SB),4,$0-0\n CALL other<>(SB)\n JMP last<>(SB)\nTEXT other<>(SB),4,$0-0\n ADDQ BX,AX\n RET\nTEXT last<>(SB),4,$0-0\n RET\n"},
		{"root_implicit_BP_tail", "CALL helper<>(SB)\n JMP last<>(SB)", helper + "TEXT last<>(SB),4,$0-0\n MOVQ AX,ret+16(FP)\n RET\n"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source, declaration := x86PrivateCallSource("amd64", row.body, row.helpers)
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err == nil || ir != "" {
					t.Fatal("unclosed helper source acquired caller state or entry authority", err)
				}
			})
		}
	}
}

func TestX86PrivateCallExpansionBudget(t *testing.T) {
	var helpers strings.Builder
	for level := 0; level < 13; level++ {
		fmt.Fprintf(&helpers, "TEXT helper%d<>(SB),516,$0-0\n", level)
		if level < 12 {
			fmt.Fprintf(&helpers, "CALL helper%d<>(SB)\nCALL helper%d<>(SB)\n", level+1, level+1)
		}
		helpers.WriteString("RET\n")
	}
	source, declaration := x86PrivateCallSource("amd64", "CALL helper0<>(SB)", helpers.String())
	if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", "text"); err == nil || ir != "" || !strings.Contains(err.Error(), "budget") {
		t.Fatal("compact acyclic source bypassed the existing expanded instruction budget", err)
	}
}
