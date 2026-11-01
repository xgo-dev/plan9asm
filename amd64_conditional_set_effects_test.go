package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var x86ConditionalSetTestNames = strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS")

func TestX86ConditionalSetActualGoTableAndOrderedForms(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{A(SET[A-Z]+), yscond, Pb, opBytes\{0x0f, (0x[0-9a-f]+), 00\}\}`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 16 || !strings.Contains(string(data), "var yscond = []ytab{\n\t{Zo_m, 2, argList{Ymb}},\n}") {
		t.Fatalf("actual SDK SETcc row/class inventory changed: %d", len(rows))
	}
	for _, row := range rows {
		if _, registered := x86ConditionalSetConditions[Op(row[1])]; !registered {
			t.Fatalf("actual Go row has no shared conditional byte form: %v", row)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		registers := "AX BX CX DX AH AL BH BL CH CL DH DL BP SI DI"
		if arch == "amd64" {
			registers += " SP BPB SIB DIB R8 R9 R10 R11 R12 R13 R14 R15 R8B R9B R10B R11B R12B R13B R14B R15B"
		}
		var source strings.Builder
		source.WriteString("TEXT ·Value(SB),4,$0-1\n")
		for _, op := range x86ConditionalSetTestNames {
			for _, destination := range append(strings.Fields(registers), "(AX)", "7(AX)(CX*4)", "state(SB)", "ret0+0(FP)") {
				line := op + " " + destination
				file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-1\n"+line+"\nRET")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				before := fmt.Sprintf("%#v", ins)
				if _, recognized, err := x86ConditionalSetProperties(ins.Op, ins, arch); !recognized || err != nil {
					t.Fatalf("%s %s shared row: %v", arch, line, err)
				}
				if !x86SourceStackInstructionKnown(ins, "MOVQ", "Q", arch) {
					t.Fatalf("valid lowerer row is missing source-stack registration: %s", line)
				}
				if isAMD64MemoryOperand(ins.Args[0]) {
					width, write, known := x86InstructionMemoryShape(ins, 0, arch)
					if width != 1 || !write || !known || x86ScalarMoveMemoryBytes(ins, 0, arch) != 1 {
						t.Fatalf("conditional byte memory shape: %s %d/%t/%t", line, width, write, known)
					}
					if ins.Args[0].Kind == OpFP {
						if width, write, known := X86FPAccessBytes(ins, 0, arch); width != 1 || !write || !known {
							t.Fatal("FP observation disagrees with the ordered form")
						}
					}
				}
				if fmt.Sprintf("%#v", ins) != before {
					t.Fatal("typed form changed source identity")
				}
				source.WriteString(line + "\n")
			}
		}
		source.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
	}
}

func TestX86ConditionalSetRejectsMalformedAndConflictingIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{"SETNE", "SETNE $1", "SETNE X0", "SETNE M0", "SETNE K1", "SETNE AX,BX", "SETNE.Z AX", "SETNE (AX)(SP*1)"} {
			source := "TEXT ·Value(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, arch, source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				continue
			}
			ins := file.Funcs[0].Instrs[1]
			if _, recognized, err := x86ConditionalSetProperties(ins.Op, ins, arch); !recognized || err == nil {
				t.Fatalf("malformed source obtained a conditional byte effect: %s/%s", arch, row)
			}
		}
	}
	for _, identity := range []Op{"", "SETNE", "setne", "SETEQ", "SETNE.BAD"} {
		var output strings.Builder
		ctx := amd64Ctx{b: &output, goarch: "amd64"}
		ins := Instr{Op: identity, Args: []Operand{{Kind: OpReg, Reg: AX}}}
		// Success is tested at the grammar seam without relying on default
		// LLVM flags. Contradictions must fail before even loading flags.
		_, recognized, err := x86ConditionalSetProperties("SETNE", ins, "amd64")
		valid := identity == "" || strings.EqualFold(string(identity), "SETNE")
		if !recognized || (err == nil) != valid {
			t.Fatalf("dispatch identity %q: %v", identity, err)
		}
		if !valid {
			if _, _, err := ctx.lowerConditionalSet("SETNE", ins); err == nil || output.Len() != 0 {
				t.Fatal("contradictory dispatch emitted IR")
			}
		}
	}
}

func TestX86ConditionalSetCallerConsumesOnlyDefinedFlagsAndExactByte(t *testing.T) {
	for _, op := range x86ConditionalSetTestNames {
		for _, destination := range []string{"AX", "AH", "(DX)"} {
			body := "CMPL AX,$0\n" + op + " " + destination
			if destination != "(DX)" {
				body += "\nMOVB " + destination + ",(DX)"
			}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			source := strings.NewReplacer("var res float32", "var res uint8", ") float32 {", ") uint8 {").Replace(x86CallerFixtureSource)
			pkg, _ := x86CallerCoreFixture(t, source, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatalf("%s byte admission: %v", body, err)
			}
		}
	}
	for name, body := range map[string]string{
		"unknown flags":   "SETNE AX\nMOVB AX,(DX)",
		"pointer flags":   "CMPQ DX,$0\nSETNE AX\nMOVB AX,(DX)",
		"partial pointer": "CMPL AX,$0\nSETNE DX\nMOVB AX,(DX)",
		"input write":     "CMPL AX,$0\nSETNE (DI)",
		"unknown address": "CMPL AX,$0\nSETNE (BX)",
		"wide result":     "CMPL AX,$0\nSETNE 4(DX)",
		"undefined upper": "CMPL AX,$0\nSETNE BX\nMOVL BX,(DX)",
		"join flags":      "CMPL AX,$0\nJE other\nADDQ $0,DX\nother:\nSETNE AX\nMOVB AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved flags/byte/address acquired continuation: %v", err)
			}
		})
	}
	// A private-region pointer is never washed into a number by an eight-bit
	// output. The exact AH bit mask preserves unrelated known bytes.
	state := x86SourceStackState{numericFlags: true, known: map[Reg]uint8{AX: 1}, callers: map[Reg]x86CallerPointerValue{DX: {argument: 0}}}
	ins := Instr{Op: "SETNE", Args: []Operand{{Kind: OpReg, Reg: AH}}}
	if _, valid := x86CallerConditionalSetStep(&ins, &state, nil); !valid || state.known[AX] != 3 || !state.numericFlags {
		t.Fatal("SETcc does not preserve exact byte knowledge and flags")
	}
	ins.Args[0].Reg = DX
	if _, valid := x86CallerConditionalSetStep(&ins, &state, nil); valid || len(state.callers) != 1 {
		t.Fatal("SETcc washed surviving pointer bytes")
	}
}

func TestX86ConditionalSetThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var body strings.Builder
			fmt.Fprintf(&body, "%s x+0(FP),SI\nMOVL $7,AX\nCMPL AX,$3\n", move)
			for _, op := range x86ConditionalSetTestNames {
				fmt.Fprintf(&body, "%s AX\n%s AH\n%s (SI)\n%s ret0+%d(FP)\n", op, op, op, op, word)
			}
			body.WriteString("RET")
			pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x *uint8) uint8", body.String())
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig}, ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }}
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
			translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: options.ResolveSym})
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

func TestX86ABI0OccupiedPointerAndSetRetainUnavailableInputs(t *testing.T) {
	for name, body := range map[string]string{
		"pointer bytes":         "MOVQ x+0(FP),AX\nMOVL AX,ret0+24(FP)\nRET",
		"partial pointer bytes": "MOVB x+0(FP),AX\nMOVL AX,ret0+24(FP)\nRET",
		"pointer dereference":   "MOVQ x+0(FP),AX\nMOVL (AX),BX\nMOVL BX,ret0+24(FP)\nRET",
		"unknown flags":         "SETNE AX\nMOVB AX,ret0+24(FP)\nRET",
		"unknown upper":         "MOVL $1,BX\nCMPL BX,$0\nSETNE AX\nMOVL AX,ret0+24(FP)\nRET",
		"missing result bytes":  "MOVL $1,AX\nCMPL AX,$0\nSETNE ret0+24(FP)\nRET",
		"flags join":            "MOVL $1,AX\nCMPL AX,$0\nJE other\nSETNE ret0+24(FP)\nother:\nRET",
		"call":                  "MOVL $1,ret0+24(FP)\nCALL ·other(SB)\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x []uint32) uint32", body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			before := fmt.Sprintf("%#v %#v", file, sig)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("occupied pointer or byte output manufactured input/result: %v", err)
			}
			if !reflect.DeepEqual(before, fmt.Sprintf("%#v %#v", file, sig)) {
				t.Fatal("observer mutated source/layout")
			}
		})
	}
	// Result initialization observes reachable execution, not unused source
	// bytes. A complete result followed by an unconditional jump does not read
	// the dead pointer input. Transporting an unused opaque pointer is also
	// legal; consuming its bytes as a numeric result must still fail.
	const dead = "MOVL $1,ret0+24(FP)\nJMP end\nMOVQ x+0(FP),AX\nend:\nRET"
	for _, fixture := range []struct {
		name, body string
		context    bool
	}{
		{"dead pointer bytes", dead, false},
		{"reachable opaque pointer unused", strings.Replace(dead, "JMP end", "JMP input\ninput:", 1), false},
		{"reachable pointer result", strings.Replace(strings.Replace(dead, "JMP end", "JMP input\ninput:", 1),
			"MOVQ x+0(FP),AX", "MOVQ x+0(FP),AX\nMOVL AX,ret0+24(FP)", 1), true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x []uint32) uint32", fixture.body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			before := fmt.Sprintf("%#v %#v", file, sig)
			err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
			if fixture.context && !errors.Is(err, ErrProbeNeedsContext) || !fixture.context && err != nil {
				t.Fatalf("reachable result/input boundary changed: %v", err)
			}
			if before != fmt.Sprintf("%#v %#v", file, sig) {
				t.Fatal("result observer changed source or manufactured pointer layout")
			}
		})
	}
	// A derived pointer layout still cannot become a pointer result contract.
	pkg := mustGoPackage(t, "example.invalid/pointer", "package pointer\nfunc Value(x *uint32) *uint32\n")
	sig, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-16\nMOVQ x+0(FP),AX\nMOVQ AX,ret0+8(FP)\nRET")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("pointer result gained numeric result authority")
	}
}
