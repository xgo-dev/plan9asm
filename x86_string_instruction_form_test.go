package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86StringInstructionCompleteOfficialYnoneRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := string(data)
	if !strings.Contains(table, "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}") {
		t.Fatal("complete official zero-operand class changed")
	}

	// This independent encoder inventory proves the complete operand/encoding
	// grammar, not prefix adjacency, initialized memory, FLAGS or entry roles.
	want := map[string]string{
		"REP":  "{AREP, ynone, Px, opBytes{0xf3}},",
		"REPN": "{AREPN, ynone, Px, opBytes{0xf2}},",
	}
	for _, family := range []struct {
		name       string
		byteOpcode byte
		wideOpcode byte
	}{
		{"MOVS", 0xa4, 0xa5},
		{"STOS", 0xaa, 0xab},
		{"SCAS", 0xae, 0xaf},
		{"CMPS", 0xa6, 0xa7},
		{"LODS", 0xac, 0xad},
	} {
		for _, width := range []struct{ suffix, prefix string }{
			{"B", "Pb"}, {"W", "Pe"}, {"L", "Px"}, {"Q", "Pw"},
		} {
			opcode := family.wideOpcode
			if width.suffix == "B" {
				opcode = family.byteOpcode
			}
			name := family.name + width.suffix
			want[name] = fmt.Sprintf("{A%s, ynone, %s, opBytes{0x%x}},", name, width.prefix, opcode)
		}
	}
	rows := regexp.MustCompile(`(?m)^\s*\{A((?:MOVS|STOS|SCAS|CMPS|LODS)[BWLQ]|REP|REPN),[^\n]+`).FindAllStringSubmatch(table, -1)
	if len(rows) != 22 || len(want) != 22 || len(x86StringSpecs) != 20 {
		t.Fatal("complete two-prefix/twenty-string inventory changed", len(rows), len(want), len(x86StringSpecs))
	}
	for _, row := range rows {
		name := row[1]
		if strings.TrimSpace(row[0]) != want[name] {
			t.Fatal("official complete encoding row differs", name, row[0], want[name])
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatal("official family omitted a row", want)
	}
}

func TestX86StringInstructionCompleteGrammar(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{"MOVS", "STOS", "SCAS", "CMPS", "LODS"} {
			for _, width := range []struct {
				suffix string
				typ    LLVMType
				bytes  int
			}{{"B", I8, 1}, {"W", I16, 2}, {"L", I32, 4}, {"Q", I64, 8}} {
				for _, prefix := range []string{"", "REP", "REPN"} {
					op := Op(stem + width.suffix)
					t.Run(arch+"/"+string(op)+"/"+prefix, func(t *testing.T) {
						kind, typ, bytes, known := x86StringProperties(op)
						if !known || kind != strings.ToLower(stem) || typ != width.typ || bytes != width.bytes {
							t.Fatal("complete independent operation/width differs", kind, typ, bytes, known)
						}
						var output strings.Builder
						ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, arch, "", false)
						ctx.directionSlot = "%direction"
						if prefix != "" {
							if terminated, err := ctx.lowerInstr(0, 0, Instr{Op: Op(prefix), Raw: prefix}, nil, nil); terminated || err != nil || ctx.repeatPrefix != prefix {
								t.Fatal("existing prefix dispatcher differs", terminated, err, ctx.repeatPrefix)
							}
						}
						ins := Instr{Op: op, Raw: string(op)}
						before := ins
						known, terminated, err := ctx.lowerString(ins)
						if !known || terminated || !reflect.DeepEqual(before, ins) || ctx.repeatPrefix != "" {
							t.Fatal("string handling/source/prefix identity changed", known, terminated, err, ctx.repeatPrefix)
						}
						if arch == "386" && width.suffix == "Q" {
							if err == nil || output.Len() != 0 {
								t.Fatal("mode32 qword form emitted", err, output.String())
							}
							return
						}
						if err != nil || !strings.Contains(output.String(), "call ") || !strings.Contains(output.String(), "load i1, ptr %direction") {
							t.Fatal("valid existing emitter form changed", err, output.String())
						}
						if prefix != "" && (stem == "SCAS" || stem == "CMPS") && strings.Count(output.String(), " = select i1 ") < 6 {
							t.Fatal("zero-count compare no longer preserves all six old status flags", output.String())
						}
					})
				}
			}
		}
	}
}

func TestX86StringInstructionRejectsOperandsAndSuffixes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{"MOVS", "STOS", "SCAS", "CMPS", "LODS"} {
			for _, width := range []string{"B", "W", "L", "Q"} {
				for _, mutation := range []struct {
					name   string
					suffix string
					args   []Operand
				}{
					{name: "register", args: []Operand{{Kind: OpReg, Reg: AX}}},
					{name: "immediate", args: []Operand{{Kind: OpImm, Imm: 1}}},
					{name: "memory", args: []Operand{{Kind: OpMem, Mem: MemRef{Base: DI}}}},
					{name: "logical-FP", args: []Operand{{Kind: OpFP, FPOffset: 0}}},
					{name: "two-operands", args: []Operand{{Kind: OpReg, Reg: SI}, {Kind: OpReg, Reg: DI}}},
					{name: "zero-suffix", suffix: ".Z"},
					{name: "SAE-suffix", suffix: ".SAE"},
					{name: "unknown-suffix", suffix: ".invalid"},
				} {
					op := Op(stem + width + mutation.suffix)
					t.Run(arch+"/"+string(op)+"/"+mutation.name, func(t *testing.T) {
						var output strings.Builder
						ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, arch, "", false)
						ctx.repeatPrefix = "REPN"
						known, terminated, err := ctx.lowerString(Instr{Op: op, Raw: string(op), Args: mutation.args})
						if !known || terminated || err == nil || output.Len() != 0 {
							t.Fatal("malformed complete family form reached emitter", known, terminated, err, output.String())
						}
						wantPrefix := ""
						if mutation.suffix != "" {
							wantPrefix = "REPN"
						}
						if ctx.repeatPrefix != wantPrefix {
							t.Fatal("existing fatal-validation prefix consumption order changed", ctx.repeatPrefix, wantPrefix)
						}
					})
				}
			}
		}
	}
}

func TestX86StringInstructionDoesNotConsumeOtherFamilies(t *testing.T) {
	for _, op := range []Op{"REP", "REPN", "REPE", "REPNE", "MOVSS", "MOVSD", "CMPSS", "CMPSD", "INSB", "OUTSB", "SCAS", "NOP"} {
		t.Run(string(op), func(t *testing.T) {
			var output strings.Builder
			ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, "amd64", "", false)
			ctx.repeatPrefix = "REPN"
			known, terminated, err := ctx.lowerString(Instr{Op: op, Raw: string(op)})
			if known || terminated || err != nil || output.Len() != 0 || ctx.repeatPrefix != "REPN" {
				t.Fatal("unrelated prefix/SIMD/I/O operation borrowed string grammar", known, terminated, err)
			}
		})
	}
}

func TestX86StringInstructionTypedFormHasOnlyValidatedGrammar(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, stem := range []string{"MOVS", "STOS", "SCAS", "CMPS", "LODS"} {
			for _, width := range []struct {
				suffix string
				typ    LLVMType
				bytes  int
			}{{"B", I8, 1}, {"W", I16, 2}, {"L", I32, 4}, {"Q", I64, 8}} {
				op := Op(stem + width.suffix)
				t.Run(arch+"/"+string(op), func(t *testing.T) {
					ins := Instr{Op: op, Raw: string(op)}
					form, known, err := x86StringInstructionProperties(ins, arch)
					if !known || (err != nil) != (arch == "386" && width.suffix == "Q") {
						t.Fatal("complete typed mode restriction differs", known, err)
					}
					if form.kind != strings.ToLower(stem) || form.typ != width.typ || form.width != width.bytes {
						t.Fatal("typed operation/width differs", form)
					}
					for _, invalid := range []Instr{
						{Op: Op(string(op) + ".Z"), Raw: string(op) + ".Z"},
						{Op: op, Raw: string(op), Args: []Operand{{Kind: OpReg, Reg: AX}}},
					} {
						if _, known, err := x86StringInstructionProperties(invalid, arch); !known || err == nil {
							t.Fatal("typed form lost suffix/operand validation", invalid, known, err)
						}
					}
				})
			}
		}
	}
	for _, arch := range []string{"", "arm", "arm64", "wasm"} {
		t.Run("not-x86/"+arch, func(t *testing.T) {
			ins := Instr{Op: "SCASB", Raw: "SCASB"}
			if _, known, err := x86StringInstructionProperties(ins, arch); !known || err == nil {
				t.Fatal("x86 grammar borrowed a different source mode", known, err)
			}
		})
	}
	for _, op := range []Op{"REP", "REPN", "MOVSS", "CMPSD", "INSB", "OUTSB", "NOP"} {
		ins := Instr{Op: op, Raw: string(op)}
		if form, known, err := x86StringInstructionProperties(ins, "amd64"); known || err != nil || form != (x86StringSpec{}) {
			t.Fatal("another family acquired a typed string form", op, form, known, err)
		}
	}
	for _, test := range []struct {
		ins   Instr
		arch  string
		known bool
		typ   LLVMType
		fail  bool
	}{
		{Instr{Op: "SCASB", Raw: "SCASQ"}, "386", true, I8, false},
		{Instr{Op: "SCASQ", Raw: "SCASB"}, "386", true, I64, true},
		{Instr{Op: "scasb", Raw: "SCASQ"}, "386", true, I8, false},
		{Instr{Op: "scasb.z", Raw: "SCASB"}, "386", true, "", true},
		{Instr{Op: "MOVSS", Raw: "SCASB"}, "amd64", false, "", false},
		{Instr{Raw: "SCASB"}, "amd64", false, "", false},
	} {
		form, known, err := x86StringInstructionProperties(test.ins, test.arch)
		if known != test.known || (err != nil) != test.fail || form.typ != test.typ {
			t.Fatal("typed form did not derive its one actual instruction head", test, form, known, err)
		}
	}
}

func TestX86StringRepeatPrefixExistingGrammarAndBinding(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, prefix := range []string{"REP", "REPN"} {
			for _, mutation := range []struct {
				name string
				ins  Instr
			}{
				{"register", Instr{Op: Op(prefix), Raw: prefix, Args: []Operand{{Kind: OpReg, Reg: AX}}}},
				{"immediate", Instr{Op: Op(prefix), Raw: prefix, Args: []Operand{{Kind: OpImm, Imm: 1}}}},
				{"suffix", Instr{Op: Op(prefix + ".Z"), Raw: prefix + ".Z"}},
			} {
				t.Run(arch+"/"+prefix+"/"+mutation.name, func(t *testing.T) {
					var output strings.Builder
					ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, arch, "", false)
					terminated, err := ctx.lowerInstr(0, 0, mutation.ins, nil, nil)
					if terminated || err == nil || output.Len() != 0 || ctx.repeatPrefix != "" {
						t.Fatal("invalid prefix acquired an emitter effect", terminated, err, output.String())
					}
				})
			}
			for _, follower := range []Op{"NOP", "RET", "REP", "REPN"} {
				t.Run(arch+"/"+prefix+"/followed-by-"+string(follower), func(t *testing.T) {
					var output strings.Builder
					ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, nil, nil, arch, "", false)
					ctx.repeatPrefix = prefix
					terminated, err := ctx.lowerInstr(0, 0, Instr{Op: follower, Raw: string(follower)}, nil, nil)
					if terminated || err == nil || output.Len() != 0 || ctx.repeatPrefix != "" {
						t.Fatal("prefix was treated as an independent NOP", terminated, err, output.String())
					}
				})
			}
		}
	}
}
