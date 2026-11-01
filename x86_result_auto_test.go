package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This fixture establishes only original Go AUTO byte behavior. It does not
// bind a native frame, caller memory, address lifetime or a translation right.
func x86ResultAUTOFixture(t *testing.T, arch, declaration string, frame int, body string) (*File, FuncSig, string) {
	t.Helper()
	_, _, sig, source := x86ResultInitializationFixture(t, arch, declaration, body)
	source = strings.Replace(source, ",$0-", fmt.Sprintf(",$%d-", frame), 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	goAssemblerOracleOutput(t, arch, source, "", true)
	return file, sig, source
}

func TestX86ABI0ResultInitializationNamedAUTONumericByteDomain(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := []struct{ typ, move, register string }{
			{"uint8", "MOVB", "AX"}, {"uint16", "MOVW", "AX"}, {"uint32", "MOVL", "AX"},
			{"float32", "MOVSS", "X0"}, {"float64", "MOVSD", "X0"},
		}
		if arch == "amd64" {
			rows = append(rows, struct{ typ, move, register string }{"uint64", "MOVQ", "R14"})
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.move, func(t *testing.T) {
				_, _, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(x "+row.typ+") "+row.typ, "RET")
				body := fmt.Sprintf("%s x+0(FP),%s\n%s %s,spill-16(SP)\n%s spill-16(SP),%s\n%s %s,ret0+%d(FP)\nRET",
					row.move, row.register, row.move, row.register, row.move, row.register, row.move, row.register, sig.Frame.Results[0].Offset)
				file, signature, source := x86ResultAUTOFixture(t, arch, "func Value(x "+row.typ+") "+row.typ, 32, body)
				before := fmt.Sprintf("%#v %#v", file, signature)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], signature, arch); err != nil {
					t.Fatalf("actual initialized logical AUTO bytes remain unmodeled: %v\n%s", err, source)
				}
				if after := fmt.Sprintf("%#v %#v", file, signature); after != before {
					t.Fatal("observer changed actual source or typed layout")
				}
			})
		}
	}
	for name, body := range map[string]string{
		"overlapping names are physical bytes": "MOVL $7,first-16(SP)\nMOVL $9,second-12(SP)\nMOVQ third-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"all branch stores":                    "MOVL $1,AX\nCMPL AX,$0\nJE other\nMOVQ $7,a-16(SP)\nJMP end\nother:\nMOVQ $9,b-16(SP)\nend:\nMOVQ c-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"initialized scalar loop":              "MOVL $3,count-8(SP)\nMOVQ $7,value-16(SP)\nloop:\nMOVL count-8(SP),AX\nSUBL $1,AX\nMOVL AX,count-8(SP)\nCMPL AX,$0\nJNE loop\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"byte SET into AUTO":                   "MOVQ $0,value-16(SP)\nMOVL $7,AX\nCMPL AX,$0\nSETNE value-16(SP)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			file, sig, source := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", 32, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatalf("actual defined byte/CFG AUTO input remains unmodeled: %v\n%s", err, source)
			}
		})
	}
}

func TestX86ABI0ResultInitializationAUTOUnknownAndEscapeStayContext(t *testing.T) {
	for name, body := range map[string]string{
		"entry not initialized":       "MOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"missing upper AUTO bytes":    "MOVL $1,value-16(SP)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"missing GP byte stored":      "MOVB $1,AX\nMOVQ AX,value-16(SP)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"join missing initialization": "MOVL $1,AX\nCMPL AX,$0\nJE end\nMOVQ $7,value-16(SP)\nend:\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"loop no entry definition":    "MOVL $1,AX\nJMP condition\nbody:\nMOVQ $1,value-16(SP)\ncondition:\nCMPL AX,$0\nJNE body\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"AUTO positive offset":        "MOVQ $1,value+0(SP)\nMOVQ value+0(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"past frame start":            "MOVQ $1,value-40(SP)\nMOVQ value-40(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"cross frame end":             "MOVQ $1,value-4(SP)\nMOVQ value-4(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"physical SP not AUTO":        "MOVQ $1,-16(SP)\nMOVQ -16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"address materialization":     "MOVQ $1,value-16(SP)\nLEAQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"SP copied":                   "MOVQ SP,AX\nMOVQ AX,ret0+0(FP)\nRET",
		"SP adjusted":                 "ADDQ $8,SP\nMOVQ $1,value-16(SP)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"unknown native load":         "MOVQ $1,value-16(SP)\nMOVQ (R8),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"calling frame":               "MOVQ $1,value-16(SP)\nCALL ·Other(SB)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"raw instruction":             "MOVQ $1,value-16(SP)\nBYTE $0x90\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"dead unknown effect":         "MOVQ $1,value-16(SP)\nJMP end\nMOVQ (R8),AX\nend:\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", 32, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown bytes/address/call/extent were washed into result initialization: %v", err)
			}
		})
	}
}

func TestX86ABI0ResultInitializationAUTOLiteralRoleCannotBeInvented(t *testing.T) {
	file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", 32,
		"MOVQ $1,value-16(SP)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET")
	for name, mutate := range map[string]func(*Func){
		"different parsed offset": func(fn *Func) { fn.Instrs[1].Args[1].Mem.Off = -24 },
		"different original role": func(fn *Func) { fn.Instrs[1].Raw = "MOVQ $1,-16(SP)" },
		"empty original literal":  func(fn *Func) { fn.Instrs[1].Raw = "" },
		"different TEXT frame":    func(fn *Func) { fn.FrameSize = 64 },
		"no AUTO extent":          func(fn *Func) { fn.FrameSize = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			for index := range fn.Instrs {
				fn.Instrs[index].Args = append([]Operand(nil), fn.Instrs[index].Args...)
			}
			mutate(&fn)
			before := fmt.Sprintf("%#v %#v", fn, sig)
			if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed AUTO source identity obtained byte knowledge: %v", err)
			}
			if !reflect.DeepEqual(before, fmt.Sprintf("%#v %#v", fn, sig)) {
				t.Fatal("observer modified identity to manufacture AUTO source")
			}
		})
	}
}

func TestX86ABI0ResultInitializationAUTOScalarVectorAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, move := range []string{"MOVSS", "MOVSD"} {
			t.Run(arch+"/"+move, func(t *testing.T) {
				// A legacy scalar memory load clears the other X bytes. A
				// register copy, however, does not initialize those bytes.
				body := "MOVL $7,value-16(SP)\n"
				if move == "MOVSD" {
					body += "MOVL $9,value-12(SP)\n"
				}
				body += move + " value-16(SP),X1\nMOVSD X1,ret0+0(FP)\nRET"
				file, sig, _ := x86ResultAUTOFixture(t, arch, "func Value() float64", 32, body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatalf("actual scalar memory load's upper zeros were lost: %v", err)
				}
				if move == "MOVSS" {
					body = strings.Replace(body, "MOVSD X1,ret0", "MOVSS X1,X0\nMOVSD X0,ret0", 1)
					file, sig, _ = x86ResultAUTOFixture(t, arch, "func Value() float64", 32, body)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("register merge invented unknown upper bytes: %v", err)
					}
				}
			})
		}
	}
}

func TestX86ABI0ResultInitializationAUTOSourceAndSharedBudget(t *testing.T) {
	for _, spelling := range []string{"spill-0x10(SP)", "spill-(8+8)(SP)", "spill-16( SP )"} {
		t.Run(spelling, func(t *testing.T) {
			body := "MOVQ $7," + spelling + "\nMOVQ " + spelling + ",AX\nMOVQ AX,ret0+0(FP)\nRET"
			file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", 32, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatalf("actual evaluable named AUTO spelling was lost: %v", err)
			}
		})
	}
	for name, frame := range map[string]int{"complete combined byte budget": 4096, "frame extent bounded": 4104} {
		t.Run(name, func(t *testing.T) {
			body := "MOVQ $7,value-16(SP)\n" + strings.Repeat("NOP\n", 2100) + "MOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET"
			file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", frame, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("oversized logical domain obtained initialization: %v", err)
			}
		})
	}
	file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value() uint64", 32,
		"MOVQ $7,value-16(SP)\nMOVQ value-16(SP),AX\nMOVQ AX,ret0+0(FP)\nRET")
	// Explicit source mutations, not claimed actual assembler diagnostics.
	for name, mutate := range map[string]func(*Func){
		"extra TEXT":                 func(fn *Func) { fn.Instrs[1].Raw = "TEXT ·Other(SB),4,$32-8\nMOVQ $7,value-16(SP)" },
		"unknown operand extent":     func(fn *Func) { fn.Instrs[1].Args[1].Mem.OffRaw = "unknown" },
		"different symbol":           func(fn *Func) { fn.Sym = "·Other" },
		"oversized original literal": func(fn *Func) { fn.Instrs[1].Raw = strings.Repeat(" ", 1<<20) + fn.Instrs[1].Raw },
	} {
		t.Run(name, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			for index := range fn.Instrs {
				fn.Instrs[index].Args = append([]Operand(nil), fn.Instrs[index].Args...)
			}
			mutate(&fn)
			if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("invented source/budget obtained byte initialization: %v", err)
			}
		})
	}
}

func TestX86ABI0ResultInitializationAUTOExistingTranslationContracts(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		for _, row := range []struct{ typ, move, register string }{
			{"uint8", "MOVB", "AX"}, {"uint16", "MOVW", "AX"}, {"uint32", "MOVL", "AX"},
			{"float32", "MOVSS", "X0"}, {"float64", "MOVSD", "X0"},
		} {
			t.Run(target.triple+"/"+row.move, func(t *testing.T) {
				pkg, _, sig, _ := x86ResultInitializationFixture(t, target.arch, "func Value(x "+row.typ+") "+row.typ, "RET")
				body := fmt.Sprintf("%s x+0(FP),%s\n%s %s,spill-16(SP)\n%s spill-16(SP),%s\n%s %s,ret0+%d(FP)\nRET",
					row.move, row.register, row.move, row.register, row.move, row.register, row.move, row.register, sig.Frame.Results[0].Offset)
				file, sig, source := x86ResultAUTOFixture(t, target.arch, "func Value(x "+row.typ+") "+row.typ, 32, body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig},
					ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
				text, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, text, "text")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, module.String(), "module")
				translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch,
					TargetTriple: target.triple, ResolveSym: options.ResolveSym})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, translated.Module.String(), "typed-go")
			})
		}
	}
}
