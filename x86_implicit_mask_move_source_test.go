package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type x86RawImplicitVectorMaskMoveFixture struct {
	op         string
	mask, data int
	encoding   []byte
}

func x86RawImplicitVectorMaskMoveFixtures(arch string) []x86RawImplicitVectorMaskMoveFixture {
	forms := []x86RawImplicitVectorMaskMoveFixture{
		{"MASKMOVOU", 1, 0, []byte{0x66, 0x0f, 0xf7, 0xc1}},
		{"VMASKMOVDQU", 1, 0, []byte{0xc5, 0xf9, 0xf7, 0xc1}},
		{"VMASKMOVDQU", 1, 0, []byte{0xc4, 0xe1, 0xf9, 0xf7, 0xc1}}, // VEX3 with ignored W set
	}
	if arch != "amd64" {
		return forms
	}
	// Go's amd64enc.s contains all four register combinations.
	return append(forms, []x86RawImplicitVectorMaskMoveFixture{
		{"MASKMOVOU", 2, 2, []byte{0x66, 0x0f, 0xf7, 0xd2}},
		{"MASKMOVOU", 11, 2, []byte{0x66, 0x41, 0x0f, 0xf7, 0xd3}},
		{"MASKMOVOU", 2, 11, []byte{0x66, 0x44, 0x0f, 0xf7, 0xda}},
		{"MASKMOVOU", 11, 11, []byte{0x66, 0x45, 0x0f, 0xf7, 0xdb}},
		{"VMASKMOVDQU", 2, 2, []byte{0xc5, 0xf9, 0xf7, 0xd2}},
		{"VMASKMOVDQU", 11, 2, []byte{0xc4, 0xc1, 0x79, 0xf7, 0xd3}},
		{"VMASKMOVDQU", 2, 11, []byte{0xc5, 0x79, 0xf7, 0xda}},
		{"VMASKMOVDQU", 11, 11, []byte{0xc4, 0x41, 0x79, 0xf7, 0xdb}},
	}...)
}

func (f x86RawImplicitVectorMaskMoveFixture) program(arch, name string, raw bool) (string, string) {
	source, declaration := x86ImplicitMaskMoveOracleRegisters(arch, f.op, name, f.mask, f.data)
	if raw {
		named := fmt.Sprintf("%s X%d,X%d\n", f.op, f.mask, f.data)
		source = strings.Replace(source, named, x86RawDisplacementDirectives(f.encoding), 1)
	}
	return source, declaration
}

func TestX86RawImplicitVectorMaskMove(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 required for raw implicit mask stores")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			forms := x86RawImplicitVectorMaskMoveFixtures(target.arch)
			mode := 64
			if target.arch == "386" {
				mode = 32
			}
			var source, declarations strings.Builder
			for index, f := range forms {
				named := fmt.Sprintf("%s X%d,X%d", f.op, f.mask, f.data)
				encoded := x86AddressOverrideNamedBytes(t, target.arch, named)
				if f.encoding[0] != 0xc4 || f.encoding[2]&0x80 == 0 {
					if !bytes.HasPrefix(encoded, f.encoding) {
						t.Fatalf("Go encoded %s as %x, want %x", named, encoded, f.encoding)
					}
				}
				for _, ins := range x86AddressOverrideDecoded(t, mode, f.encoding) {
					if ins.Op == OpTEXT || ins.Op == OpRET {
						continue
					}
					want := []Operand{
						{Kind: OpReg, Reg: Reg(fmt.Sprint("X", f.mask))},
						{Kind: OpReg, Reg: Reg(fmt.Sprint("X", f.data))},
					}
					if !reflect.DeepEqual(ins.Args, want) || ins.x86SourceRaw == nil || ins.x86UnboundAddressOverride {
						t.Fatalf("raw %x lost its mask/data order or origin: %+v", f.encoding, ins)
					}
				}
				program, declaration := f.program(target.arch, fmt.Sprint("Store", index), true)
				source.WriteString(program)
				declarations.WriteString(declaration)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatalf("initialized physical mask store: %v", err)
					}
					for _, content := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for index, f := range forms {
							body := x86StringMemoryFunction(t, content, fmt.Sprint("Store", index))
							mnemonic := "maskmovdqu"
							if f.op == "VMASKMOVDQU" {
								mnemonic = "vmaskmovdqu"
							}
							if !strings.Contains(body, "asm sideeffect \""+mnemonic+" ") || !strings.Contains(body, "~{memory}") {
								t.Fatalf("raw %x lost its non-temporal store: %s", f.encoding, body)
							}
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, content, level)
						}
					}
				})
			}
		})
	}
}

var x86ImplicitMaskMoveOracleNames = []string{
	"MASKMOVQ", "MASKMOVOU", "MASKMOVDQU", "VMASKMOVDQU",
}

func x86ImplicitMaskMoveOracleProgram(arch, op, name string) (string, string) {
	return x86ImplicitMaskMoveOracleRegisters(arch, op, name, 0, 1)
}

func x86ImplicitMaskMoveOracleRegisters(arch, op, name string, mask, data int) (string, string) {
	word, move, bank, width := 8, "MOVQ", "X", 16
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	load, closeTags := "MOVOU", ""
	if op == "MASKMOVQ" {
		bank, width, load, closeTags = "M", 8, "MOVQ", "EMMS\n"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n"+
		"%s out+0(FP),DI\n%s mask+%d(FP),AX\n%s data+%d(FP),BX\n"+
		"%s (AX),%s%d\n%s (BX),%s%d\n%s %s%d,%s%d\n%sSFENCE\nRET\n",
		name, 3*word, move, move, word, move, 2*word,
		load, bank, mask, load, bank, data, op, bank, mask, bank, data, closeTags)
	declaration := fmt.Sprintf("func %s(out,mask,data *[%d]byte)\n", name, width)
	return source, declaration
}

func TestX86ImplicitMaskMoveCompleteOfficialRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := strings.Join(strings.Fields(string(data)), "")
	for _, row := range []string{
		"varyxr=[]ytab{{Zm_r_xm,1,argList{Yxr,Yxr}},}",
		"varymr=[]ytab{{Zm_r,1,argList{Ymr,Ymr}},}",
		"{AMASKMOVOU,yxr,Pe,opBytes{0xf7}}",
		"{AMASKMOVQ,ymr,Pm,opBytes{0xf7}}",
	} {
		if !strings.Contains(table, row) {
			t.Fatal("complete original implicit-mask-store row changed", row)
		}
	}
	data, err = os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	table = strings.Join(strings.Fields(string(data)), "")
	for _, row := range []string{
		"var_yvmaskmovdqu=[]ytab{{zcase:Zvex_rm_v_r,zoffset:2,args:argList{Yxr,Yxr}},}",
		"{as:AVMASKMOVDQU,ytab:_yvmaskmovdqu,prefix:Pavx,op:opBytes{avxEscape|vex128|vex66|vex0F|vexW0,0xF7,}}",
	} {
		if !strings.Contains(table, row) {
			t.Fatal("complete original VEX implicit-mask-store row changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		for index, op := range x86ImplicitMaskMoveOracleNames {
			program, _ := x86ImplicitMaskMoveOracleProgram(arch, op, fmt.Sprint("Prior", index))
			source.WriteString(program)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
	}
}

// Intel SDM Vol.2B, MASKMOVDQU/MASKMOVQ: even a zero mask can retain
// implementation-dependent address faults and the non-temporal protocol.
// Preserve the actual instruction, not a removable llvm.masked.store.
func TestX86ImplicitMaskMoveInitializedNativeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required for implicit mask-store objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var operations []string
			for _, op := range x86ImplicitMaskMoveOracleNames {
				last := 15
				if target.arch == "386" || op == "MASKMOVQ" {
					last = 7
				}
				for _, registers := range [][2]int{{0, 1}, {0, last}, {last, 0}} {
					name := fmt.Sprint("Store", len(operations))
					program, declaration := x86ImplicitMaskMoveOracleRegisters(target.arch, op, name, registers[0], registers[1])
					source.WriteString(program)
					declarations.WriteString(declaration)
					operations = append(operations, op)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original implicit mask-store lost its own inputs", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for index, op := range operations {
							body := x86StringMemoryFunction(t, text, fmt.Sprint("Store", index))
							mnemonic := strings.ToLower(op)
							if op == "MASKMOVOU" {
								mnemonic = "maskmovdqu"
							}
							if !strings.Contains(body, "asm sideeffect") || !strings.Contains(body, mnemonic) ||
								!strings.Contains(body, "~{memory}") || strings.Contains(body, "call void @llvm.masked.store") {
								t.Fatal("implicit non-temporal store lost its original access/fault opcode", op)
							}
							if op == "MASKMOVQ" && !strings.Contains(body, "emms") {
								t.Fatal("physical MMX store lost the original x87 tag cleanup")
							}
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86ImplicitMaskMoveUnknownInputsRemainContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, op := range x86ImplicitMaskMoveOracleNames {
			source, declaration := x86ImplicitMaskMoveOracleProgram(arch, op, "Store")
			load, bank := "MOVOU", "X"
			if op == "MASKMOVQ" {
				load, bank = "MOVQ", "M"
			}
			for name, before := range map[string]string{
				"pointer":      fmt.Sprintf("%s out+0(FP),DI\n", move),
				"mask-pointer": fmt.Sprintf("%s mask+%d(FP),AX\n", move, word),
				"data-pointer": fmt.Sprintf("%s data+%d(FP),BX\n", move, 2*word),
				"mask":         fmt.Sprintf("%s (AX),%s0\n", load, bank),
				"data":         fmt.Sprintf("%s (BX),%s1\n", load, bank),
			} {
				changed := strings.Replace(source, before, "", 1)
				if changed == source {
					t.Fatal("missing-input mutation did not change its original program", name)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+op+"/"+name+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, testTargetTriple("linux", arch), api)
						if arch == "amd64" && op != "MASKMOVQ" && (name == "mask" || name == "data") {
							x86VectorScratchCodegenControl(t, changed, declaration, arch, testTargetTriple("linux", arch), ir, err)
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("implicit store invented source bytes or its DI destination", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ImplicitMaskMoveBareFormsCannotInventInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ImplicitMaskMoveOracleNames {
			bank := "X"
			if op == "MASKMOVQ" {
				bank = "M"
			}
			source := fmt.Sprintf("TEXT ·Store(SB),4,$0-0\n%s %s0,%s1\nRET\n", op, bank, bank)
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+op+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Store()", arch, testTargetTriple("linux", arch), api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("bare implicit store invented a mask, data or native DI address", err)
					}
				})
			}
		}
	}
}

func TestX86ImplicitMaskMoveTypedRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86ImplicitMaskMoveOracleNames {
			t.Run(arch+"/"+op, func(t *testing.T) {
				bank, width := "X", int64(16)
				if op == "MASKMOVQ" {
					bank, width = "M", 8
				}
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s0,%s1", op, bank, bank))
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 || effect.dynamicMemory {
					t.Fatal("implicit store lacks its mandatory pure typed memory obligation", known, err)
				}
				reads, writes := 0, 0
				for _, operand := range effect.operands {
					if operand.width != width {
						t.Fatal("implicit byte mask narrowed its possible native write extent", operand.width)
					}
					if operand.read {
						reads++
						if operand.write || operand.index < 0 || operand.index > 1 || !reflect.DeepEqual(operand.operand, ins.Args[operand.index]) {
							t.Fatal("implicit store changed a mask or data source role")
						}
					}
					if operand.write {
						writes++
						if operand.index != -1 || !reflect.DeepEqual(operand.operand, Operand{Kind: OpMem, Mem: MemRef{Base: DI}}) {
							t.Fatal("implicit destination lost its architectural DI address")
						}
					}
				}
				if reads != 2 || writes != 1 || len(effect.operands) != 3 {
					t.Fatal("implicit source/write denominator changed", reads, writes)
				}
			})
		}
	}
}
