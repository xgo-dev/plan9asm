package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86FPAccessBytesOrderedForms(t *testing.T) {
	rows := []struct {
		instruction string
		index       int
		bytes       int64
		write       bool
	}{
		{"MOVB a+0(FP),AL", 0, 1, false}, {"MOVW AX,a+0(FP)", 1, 2, true},
		{"MOVL a+0(FP),AX", 0, 4, false}, {"MOVQ $7,a+0(FP)", 1, 8, true},
		{"MOVB $7,a+0(FP)", 1, 1, true}, {"MOVSS a+0(FP),X0", 0, 4, false},
		{"MOVSD X0,a+0(FP)", 1, 8, true}, {"MOVBQSX a+0(FP),AX", 0, 1, false},
		{"VMOVSS.Z a+0(FP),K1,X0", 0, 4, false},
		{"MOVWQZX a+0(FP),AX", 0, 2, false}, {"MOVLQSX a+0(FP),AX", 0, 4, false},
		{"VPSRLW a+0(FP),Y0,Y1", 0, 16, false},
		{"VPSRLVD.BCST a+0(FP),Z0,Z1", 0, 4, false},
		{"VPSUBQ a+0(FP),Y0,Y1", 0, 32, false},
		{"VPADDD.BCST a+0(FP),Z0,Z1", 0, 4, false},
		{"VMOVDQU Y0,a+0(FP)", 1, 32, true},
		{"KMOVW a+0(FP),K1", 0, 2, false},
	}
	for _, op := range []string{"MOVOU", "MOVOA", "MOVO", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD"} {
		rows = append(rows, struct {
			instruction string
			index       int
			bytes       int64
			write       bool
		}{op + " a+0(FP),X0", 0, 16, false})
	}
	for _, row := range rows {
		t.Run(row.instruction, func(t *testing.T) {
			source := "TEXT ·probe(SB),4,$0-64\n" + row.instruction + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			width, write, known := X86FPAccessBytes(file.Funcs[0].Instrs[1], row.index, "amd64")
			if !known || width != row.bytes || write != row.write {
				t.Fatalf("native operand width/direction = %d/%v/%v, want %d/%v", width, write, known, row.bytes, row.write)
			}
		})
	}
}

func TestX86FPAccessBytesUnknownDoesNotInferPermission(t *testing.T) {
	for _, instruction := range []string{
		"ADDQ a+0(FP),BAD", "ADDQ.Z a+0(FP),AX", "ADDQ a+0(FP),b+8(FP)",
		"MOVQ a+0(FP),BAD", "MOVQ a+0(FP),Y0", "MOVOU a+0(FP),Y0",
		"MOVL a+0(FP),M8", "MOVQ a+0(FP),M8", "MOVD a+0(FP),M8",
		"VMOVD a+0(FP),M0", "VMOVQ M0,a+0(FP)", "MOVL a+0(FP),M0,M1",
		"MOVQ a+0(FP),b+8(FP)", "MOVQ $1.0,a+0(FP)", "MOVQ $0x100000000,a+0(FP)",
		"LEAQ a+0(FP),AX", "MOVQ a+0(FP)(SI*1),AX", "MOVQ $a+0(FP),AX",
	} {
		t.Run(instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·probe(SB),4,$0-16\n"+instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			for index := range ins.Args {
				if width, _, known := X86FPAccessBytes(ins, index, "amd64"); known || width != 0 {
					t.Fatalf("unknown/malformed/native-address %s inferred bytes: %d/%v", instruction, width, known)
				}
			}
		})
	}
	for _, instruction := range []string{"MOVQ a+0(FP),AX", "MOVOU a+0(FP),X8", "MOVL a+0(FP),R8"} {
		file, err := Parse(ArchAMD64, "TEXT ·probe(SB),4,$0-16\n"+instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if width, _, known := X86FPAccessBytes(file.Funcs[0].Instrs[1], 0, "386"); known || width != 0 {
			t.Fatalf("unbound 386 physical bank/width %s: %d/%v", instruction, width, known)
		}
	}
}

func TestX86FPAccessBytesScalarRMWOrderedObservation(t *testing.T) {
	// This independent syntax inventory is checked against the complete Go
	// ordered tables by TestX86LockScalarRMWCompleteGoTables. Observation of
	// an FP width is not admission of LOCK on virtual FP storage.
	for _, arch := range []string{"amd64", "386"} {
		forms := x86LockScalarOracleForms(arch)
		for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR"} {
			widths := "BWL"
			if arch == "amd64" {
				widths += "Q"
			}
			for _, width := range widths {
				register := "AX"
				if width == 'B' {
					register = "AL"
				}
				op := stem + string(width)
				forms = append(forms, x86LockScalarOracleForm{op, op + " a+0(FP)," + register})
			}
		}
		for _, form := range forms {
			instruction := strings.Replace(form.text, "1(SI)", "a+0(FP)", 1)
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT ·probe(SB),4,$0-8\n" + instruction + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				before := append([]Operand(nil), ins.Args...)
				wantWidth := map[byte]int64{'B': 1, 'W': 2, 'L': 4, 'Q': 8}[form.op[len(form.op)-1]]
				for index, operand := range ins.Args {
					width, write, known := X86FPAccessBytes(ins, index, arch)
					if operand.Kind != OpFP {
						if known || width != 0 || write {
							t.Fatal("non-FP operand acquired a frame observation", index, width, write, known)
						}
						continue
					}
					if !known || width != wantWidth || write != (index == len(ins.Args)-1) {
						t.Fatalf("ordered native FP observation = %d/%t/%t, want %d/%t/true", width, write, known, wantWidth, index == len(ins.Args)-1)
					}
				}
				if !reflect.DeepEqual(ins.Args, before) {
					t.Fatal("observation changed the original operands")
				}
			})
		}
	}
}

func TestX86FPAccessBytesKnownReadDoesNotSupplyInitializedBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			body := "MOVL $0,AX\nADDL ret0+0(FP),AX\nMOVL AX,ret0+0(FP)\nRET"
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
			goAssemblerOracleOutput(t, arch, source, "", true)
			width, write, known := X86FPAccessBytes(file.Funcs[0].Instrs[2], 0, arch)
			if width != 4 || write || !known {
				t.Fatal("registered ADDL read lost its native width", width, write, known)
			}
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("pure native-width observation granted uninitialized result bytes", err)
			}
		})
	}
}

func TestX86FPAccessBytesScalarIdentityClosed(t *testing.T) {
	// Actual original assembler rejection is distinct from constructed API
	// mutations. Neither can borrow the generic source-stack suffix fallback.
	goAssemblerOracleOutput(t, "amd64", "TEXT ·probe(SB),4,$0-8\nMOVQ.Z a+0(FP),AX\nRET\n", "", false)
	file, err := Parse(ArchAMD64, "TEXT ·probe(SB),4,$0-8\nMOVQ a+0(FP),AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, opcode := range []Op{"MOVQ.Z", "movq", " MOVQ"} {
		ins := file.Funcs[0].Instrs[1]
		ins.Op = opcode
		ins.Args = append([]Operand(nil), ins.Args...)
		ins.Args[1].Reg = "BAD"
		if width, _, known := X86FPAccessBytes(ins, 0, "amd64"); known || width != 0 {
			t.Fatalf("constructed scalar identity %q inferred width %d/%v", opcode, width, known)
		}
	}
}

func TestX86FPAliasThreeAPIsFiveObjects(t *testing.T) {
	for _, target := range []struct{ arch, triple, op, typ string }{
		{"amd64", "x86_64-apple-darwin", "MOVQ", "uint64"},
		{"amd64", "x86_64-unknown-linux-gnu", "MOVQ", "uint64"},
		{"amd64", "x86_64-pc-windows-msvc", "MOVQ", "uint64"},
		{"386", "i386-unknown-linux-gnu", "MOVL", "uint32"},
		{"386", "i686-pc-windows-msvc", "MOVL", "uint32"},
	} {
		for _, shape := range []string{"scalar", "slice", "array"} {
			t.Run(target.triple+"/"+shape, func(t *testing.T) {
				declaration := "func Value(x,y " + target.typ + ") " + target.typ
				if shape == "slice" {
					declaration = "func Value(x []" + target.typ + ") " + target.typ
				} else if shape == "array" {
					declaration = "func Value(x [2]" + target.typ + ") " + target.typ
				}
				fset := token.NewFileSet()
				syntax, err := parser.ParseFile(fset, "alias.go", "package alias\n"+declaration+"\n", 0)
				if err != nil {
					t.Fatal(err)
				}
				sizes := types.SizesFor("gc", target.arch)
				typed, err := (&types.Config{Sizes: sizes}).Check("alias", fset, []*ast.File{syntax}, nil)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := DeriveGoFuncABI0Signature("Value", typed.Scope().Lookup("Value").(*types.Func), target.arch, sizes)
				if err != nil {
					t.Fatal(err)
				}
				word := sizes.Sizeof(types.Typ[types.Uintptr])
				result := sig.Frame.Results[0].Offset
				alias := "x"
				if shape == "array" {
					alias = "x_0"
				}
				source := fmt.Sprintf("TEXT Value(SB),4,$0-%d\n%s %s+%d(FP),AX\n%s AX,ret+%d(FP)\nRET\n", result+word, target.op, alias, word, target.op, result)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig}}
				ir, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM22 llc required")
				}
				compileLLVMToObject(t, llc, target.triple, "alias-text.ll", "alias-text.o", ir)
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "alias-module.ll", "alias-module.o", module.String())
				pkg := GoPackage{Path: "alias", Types: typed, Syntax: []*ast.File{syntax}}
				resultModule, err := translateGoModuleInContext(ctx, pkg, []byte(strings.Replace(source, "Value(SB)", "·Value(SB)", 1)), GoModuleOptions{GOARCH: target.arch, Sizes: sizes, TargetTriple: target.triple})
				if resultModule != nil && !resultModule.Module.IsNil() {
					defer resultModule.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "alias-go-module.ll", "alias-go-module.o", resultModule.Module.String())
			})
		}
	}
}
