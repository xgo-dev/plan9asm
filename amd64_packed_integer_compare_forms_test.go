package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedIntegerCompareCompleteActualGoRowsAndAttributes(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(data)), "")
	}
	legacy, vector := read("asm6.go"), read("avx_optabs.go")
	for _, definition := range []string{
		"var ymm = []ytab{ {Zm_r_xm, 1, argList{Ymm, Ymr}}, {Zm_r_xm, 2, argList{Yxm, Yxr}}, }",
		"var yxm_q4 = []ytab{ {Zm_r, 1, argList{Yxm, Yxr}}, }",
	} {
		if !strings.Contains(legacy, strings.Join(strings.Fields(definition), "")) {
			t.Fatal("actual selected SDK legacy operand rows changed", definition)
		}
	}
	rows := []string{
		"{zcase:Zvex_rm_v_r,zoffset:2,args:argList{Yxm,Yxr,Yxr}}",
		"{zcase:Zvex_rm_v_r,zoffset:2,args:argList{Yym,Yyr,Yyr}}",
		"{zcase:Zevex_rm_v_r,zoffset:0,args:argList{YxmEvex,YxrEvex,Yk}}",
		"{zcase:Zevex_rm_v_k_r,zoffset:3,args:argList{YxmEvex,YxrEvex,Yknot0,Yk}}",
		"{zcase:Zevex_rm_v_r,zoffset:0,args:argList{YymEvex,YyrEvex,Yk}}",
		"{zcase:Zevex_rm_v_k_r,zoffset:3,args:argList{YymEvex,YyrEvex,Yknot0,Yk}}",
		"{zcase:Zevex_rm_v_r,zoffset:0,args:argList{Yzm,Yzr,Yk}}",
		"{zcase:Zevex_rm_v_k_r,zoffset:3,args:argList{Yzm,Yzr,Yknot0,Yk}}",
	}
	if !strings.Contains(vector, "var_yvpcmpeqb=[]ytab{"+strings.Join(rows, ",")+",}") {
		t.Fatal("actual selected SDK ordered eight-row compare table changed")
	}
	opcodes := []int{0x74, 0x75, 0x76, 0x29, 0x64, 0x65, 0x66, 0x37}
	bits := []int{8, 16, 32, 64, 8, 16, 32, 64}
	for index, op := range x86PackedIntegerCompareTestNames[:8] {
		table, prefix, code := "ymm", "Py1", fmt.Sprintf("0x%x,Pe,0x%x", opcodes[index], opcodes[index])
		if bits[index] == 64 {
			table, prefix, code = "yxm_q4", "Pq4", fmt.Sprintf("0x%x", opcodes[index])
		}
		if !strings.Contains(legacy, fmt.Sprintf("{A%s,%s,%s,opBytes{%s}}", op, table, prefix, code)) {
			t.Fatal("actual selected SDK legacy opcode attributes changed", op)
		}
	}
	for index, op := range x86PackedIntegerCompareTestNames[8:] {
		mapName, evexW, broadcast := "0F", "W0", ""
		if bits[index] == 64 {
			mapName, evexW, broadcast = "0F38", "W1", "|evexBcstN8"
		} else if bits[index] == 32 {
			broadcast = "|evexBcstN4"
		}
		var attributes strings.Builder
		for _, width := range []int{128, 256} {
			fmt.Fprintf(&attributes, "avxEscape|vex%d|vex66|vex%s|vexW0,0x%X,", width, mapName, opcodes[index])
		}
		for _, width := range []int{128, 256, 512} {
			fmt.Fprintf(&attributes, "avxEscape|evex%d|evex66|evex%s|evex%s,evexN%d%s,0x%X,", width, mapName, evexW, width/8, broadcast, opcodes[index])
		}
		if !strings.Contains(vector, "{as:A"+op+",ytab:_yvpcmpeqb,prefix:Pavx,op:opBytes{"+attributes.String()+"}},") {
			t.Fatal("actual selected SDK complete five encoding attributes changed", op)
		}
	}
	actual := map[string]int{}
	for _, source := range []string{legacy, vector} {
		for _, match := range regexp.MustCompile(`\{(?:as:)?A(V?PCMP(?:EQ|GT)[BWLQD]),`).FindAllStringSubmatch(source, -1) {
			actual[match[1]]++
		}
	}
	if len(actual) != 16 || len(x86PackedIntegerCompareSpecs) != 16 {
		t.Fatal("complete Go named-family denominator changed", actual)
	}
	for index, op := range x86PackedIntegerCompareTestNames {
		spec := x86PackedIntegerCompareSpecs[Op(op)]
		if actual[op] != 1 || spec.laneBits != bits[index%8] || spec.greater != (index%8 >= 4) || spec.legacy != (index < 8) || spec.mmx != (index < 8 && bits[index%8] < 64) {
			t.Fatal("Go registration and typed semantics differ", op, spec)
		}
	}
}

func TestX86PackedIntegerCompareLogicalFPSpanRequiresEveryByteEvenMaskZero(t *testing.T) {
	for _, op := range x86PackedIntegerCompareTestNames[8:] {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
				if broadcast && bits < 32 {
					continue
				}
				span, instruction := width, op
				if broadcast {
					span, instruction = bits/8, op+".BCST"
				}
				t.Run(fmt.Sprintf("%s/%d/bcst=%t", op, width, broadcast), func(t *testing.T) {
					var parameters strings.Builder
					for index := 0; index < span; index++ {
						if index != 0 {
							parameters.WriteByte(',')
						}
						fmt.Fprintf(&parameters, "a%d uint8", index)
					}
					pkg := mustGoPackage(t, "compare", "package compare\nfunc query("+parameters.String()+")\n")
					bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
					source := fmt.Sprintf("TEXT ·query(SB),4,$0-%d\nMOVQ $0,AX\nKMOVQ AX,K1\n%s a0+0(FP),%s1,K1,K2\nRET\n", span, instruction, bank)
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
					if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("zero mask supplied the missing second vector input", err)
					}
					// This test owns FP byte spans, not an exception to vector
					// initialization. Keep the original source as a negative and
					// initialize every second-input byte in the positive control.
					initialized := strings.Replace(source, "KMOVQ AX,K1\n", "KMOVQ AX,K1\nVPXORD Z1,Z1,Z1\n", 1)
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", initialized)
					file, err = Parse(ArchAMD64, initialized)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Translate(file, options); err != nil {
						t.Fatal("complete logical FP fields", err)
					}
					for missing := 0; missing < span; missing++ {
						t.Run(fmt.Sprint(missing), func(t *testing.T) {
							sig := sigs["query"]
							sig.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
							sig.Frame.Params = append(sig.Frame.Params[:missing], sig.Frame.Params[missing+1:]...)
							mutated := options
							mutated.Sigs = map[string]FuncSig{"query": sig}
							if ir, err := Translate(file, mutated); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("mask0 borrowed absent logical FP byte%d: %v", missing, err)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86PackedIntegerCompareMMXActualEncodedBankAndDefinedness(t *testing.T) {
	for opIndex, op := range x86PackedIntegerCompareTestNames[:8] {
		if opIndex%4 == 3 {
			continue
		}
		opcode := []byte{0x74, 0x75, 0x76, 0x29, 0x64, 0x65, 0x66, 0x37}[opIndex]
		for index, spelling := range []string{"M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			t.Run(op+"/"+spelling, func(t *testing.T) {
				source := "TEXT probe(SB),4,$0-0\n" + op + " " + spelling + ",M7\nRET\n"
				want := []byte{0x0f, opcode, 0xf8 | byte(index&7), 0xc3}
				if index >= 16 {
					want = append([]byte{0x41}, want...)
				}
				if got := x86PackedShiftActualGoBytes(t, "amd64", source); !bytes.Equal(got, want) {
					t.Fatalf("actual Go GP spelling changed native MMX identity: %x != %x", got, want)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				if !known || err != nil || effect.operands[0].operand.Reg != Reg(fmt.Sprintf("M%d", index&7)) || effect.operands[0].width != 8 {
					t.Fatal("pure query confused GP initialization with MMX", effect, err)
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				for i := range state.gp {
					state.gp[i] = 0xff
				}
				if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
					t.Fatal("numeric GP bytes supplied unproved MMX state")
				}
			})
		}
	}
	for _, op := range x86PackedIntegerCompareTestNames[:8] {
		ins := Instr{Op: Op(op), Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}}
		for input := 0; input < 2; input++ {
			for missing := 0; missing < 16; missing++ {
				t.Run(fmt.Sprintf("%s/input%d/byte%d", op, input, missing), func(t *testing.T) {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.xmm[0], state.xmm[1] = 0xffff, 0xffff
					state.xmm[1-input] &^= uint16(1) << uint(missing)
					if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
						t.Fatal("compare borrowed undefined input byte")
					}
				})
			}
		}
	}
}

type x86PackedIntegerCompareCase struct {
	op, operands               string
	width, bits                int
	legacy, mmx                bool
	mask, memory               bool
	broadcast                  bool
	first, second, destination int
}

func x86PackedIntegerCompareCases(arch string) []x86PackedIntegerCompareCase {
	var cases []x86PackedIntegerCompareCase
	for index, op := range x86PackedIntegerCompareTestNames {
		bits := []int{8, 16, 32, 64}[index%4]
		if index < 8 {
			for _, row := range []struct {
				operands      string
				first, second int
				memory        bool
			}{
				{"X0,X1", 0, 1, false}, {"X1,X0", 1, 0, false}, {"X0,X0", 0, 0, false}, {"(BX),X1", 0, 1, true},
			} {
				cases = append(cases, x86PackedIntegerCompareCase{op: op, operands: row.operands, width: 16, bits: bits, legacy: true, memory: row.memory, first: row.first, second: row.second, destination: row.second})
			}
			if arch == "amd64" && bits < 64 {
				for _, memory := range []bool{false, true} {
					operand := "M0,M1"
					if memory {
						operand = "(BX),M1"
					}
					cases = append(cases, x86PackedIntegerCompareCase{op: op, operands: operand, width: 8, bits: bits, legacy: true, mmx: true, memory: memory, first: 0, second: 1, destination: 1})
				}
			}
			continue
		}
		for _, width := range []int{16, 32, 64} {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			if width < 64 {
				for _, alias := range [][3]int{{0, 1, 2}, {0, 1, 0}, {0, 1, 1}, {0, 0, 0}} {
					cases = append(cases, x86PackedIntegerCompareCase{op: op, operands: fmt.Sprintf("%s%d,%s%d,%s%d", bank, alias[0], bank, alias[1], bank, alias[2]), width: width, bits: bits, first: alias[0], second: alias[1], destination: alias[2]})
				}
				cases = append(cases, x86PackedIntegerCompareCase{op: op, operands: fmt.Sprintf("(BX),%s1,%s2", bank, bank), width: width, bits: bits, memory: true, first: 0, second: 1, destination: 2})
			}
			for _, masked := range []bool{false, true} {
				if arch == "386" && masked {
					continue
				}
				for _, memory := range []bool{false, true} {
					for _, alias := range [][3]int{{0, 1, 0}, {0, 1, 2}, {1, 0, 1}, {0, 0, 7}} {
						first := fmt.Sprintf("%s%d", bank, alias[0])
						if memory {
							first = "(BX)"
						}
						mask := ""
						if masked {
							mask = "K2,"
						}
						cases = append(cases, x86PackedIntegerCompareCase{op: op, operands: fmt.Sprintf("%s,%s%d,%sK%d", first, bank, alias[1], mask, alias[2]), width: width, bits: bits, mask: masked, memory: memory, first: alias[0], second: alias[1], destination: alias[2]})
					}
					if memory && bits >= 32 {
						mask := ""
						if masked {
							mask = "K2,"
						}
						cases = append(cases, x86PackedIntegerCompareCase{op: op + ".BCST", operands: fmt.Sprintf("(BX),%s1,%sK2", bank, mask), width: width, bits: bits, mask: masked, memory: true, broadcast: true, first: 0, second: 1, destination: 2})
					}
				}
			}
		}
	}
	return cases
}

func TestX86PackedIntegerCompareThreeAPIsFiveTargetsO0O2Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			cases := x86PackedIntegerCompareCases(target.arch)
			for index, row := range cases {
				fmt.Fprintf(&source, "TEXT ·compare%d(SB),4,$0-0\n%s %s\nRET\n", index, row.op, row.operands)
			}
			file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
			ir := x86InstructionFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0,
				func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerPackedIntegerCompare(ins.Op, ins)
				})
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, text, level)
				}
			}
			t.Logf("%d original Go forms, three-API Context, emitter-only IR/backend O0/O2 objects; initialized public inputs have their own owner", len(cases))
		})
	}
}

func TestX86PackedIntegerCompareDescriptorPermissionsAndMalformedForms(t *testing.T) {
	for _, row := range x86PackedIntegerCompareCases("amd64") {
		file, err := Parse(ArchAMD64, "TEXT query(SB),4,$0-0\n"+row.op+" "+row.operands+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, known, err := x86PackedIntegerCompareProperties(ins.Op, ins, "amd64")
		if !known || err != nil || form.byteWidth != row.width || form.spec.laneBits != row.bits || form.mmx != row.mmx || form.broadcast != row.broadcast || (form.mask >= 0) != row.mask || (form.memory >= 0) != row.memory {
			t.Fatal("complete form lost an independent axis", row, form, err)
		}
		effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
		if !known || err != nil || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
			t.Fatal("pure descriptor lost unchanged flags", effect, err)
		}
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": 0xffff, "Z1": 0xff}, masks: map[Reg]bool{"K2": true}}
		before := state
		before.vectors, before.masks = x86CloneCallerVectorState(state.vectors, state.masks)
		if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &state, nil) || x86SourceStackInstructionKnown(ins, OpMOVQ, "Q", "amd64") || !reflect.DeepEqual(state, before) || ins.x86CallerMemory != nil {
			t.Fatal("query descriptor invented caller input/permission", row)
		}
		for _, mutate := range []func(*Instr){
			func(i *Instr) { i.Op += ".Z" },
			func(i *Instr) { i.Args = append(i.Args, Operand{Kind: OpReg, Reg: "X0"}) },
			func(i *Instr) { i.Args[len(i.Args)-1] = Operand{Kind: OpReg, Reg: "AX"} },
			func(i *Instr) { i.Args[0] = Operand{Kind: OpImm, Imm: 3} },
		} {
			local := ins
			local.Args = append([]Operand(nil), ins.Args...)
			mutate(&local)
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			ctx.goarch = "amd64"
			before, temporary := output.String(), ctx.tmp
			known, _, err := ctx.lowerPackedIntegerCompare(local.Op, local)
			if !known || err == nil || output.String() != before || ctx.tmp != temporary {
				t.Fatal("malformed form emitted before rejection", row, local, err)
			}
		}
	}
}
