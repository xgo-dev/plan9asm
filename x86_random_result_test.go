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

// These are the independent yrdrand opcode rows, not the production grammar.
var x86RandomResultOracle = []struct {
	op, prefix string
	width      int64
	extension  byte
}{
	{"RDRANDW", "Pe", 2, 6}, {"RDRANDL", "Px", 4, 6}, {"RDRANDQ", "Pw", 8, 6},
	{"RDSEEDW", "Pe", 2, 7}, {"RDSEEDL", "Px", 4, 7}, {"RDSEEDQ", "Pw", 8, 7},
}

func x86RandomOracleBytes(width int64, extension byte, register int) []byte {
	var code []byte
	if width == 2 {
		code = append(code, 0x66)
	}
	rex := byte(0x40)
	if width == 8 {
		rex |= 8
	}
	if register >= 8 {
		rex |= 1
	}
	if rex != 0x40 {
		code = append(code, rex)
	}
	return append(code, 0x0f, 0xc7, 0xc0|extension<<3|byte(register&7))
}

func TestX86HardwareRandomCompleteGoRowsAndPhysicalRegisters(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), "var yrdrand = []ytab{\n\t{Zo_m, 2, argList{Yrl}},\n}") {
		t.Fatal("complete Go yrdrand operand row changed")
	}
	registers := []Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		var expected []byte
		source.WriteString("TEXT random(SB),4,$0-0\n")
		for _, row := range x86RandomResultOracle {
			want := fmt.Sprintf("{A%s, yrdrand, %s, opBytes{0x0f, 0xc7, 0%d}}", row.op, row.prefix, row.extension)
			if !strings.Contains(string(table), want) {
				t.Fatal("complete Go random encoding changed", row.op)
			}
			if arch == "386" && row.width == 8 {
				continue // Go has no Q operand row in this source mode.
			}
			for index, register := range registers {
				if arch == "386" && index >= 8 {
					break
				}
				fmt.Fprintf(&source, "%s %s\n", row.op, register)
				code := x86RandomOracleBytes(row.width, row.extension, index)
				expected = append(expected, code...)
				file, err := Parse(ArchAMD64, "TEXT random(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				fn, err := decodeX86RawDirectives(file.Funcs[0], arch)
				if err != nil || len(fn.Instrs) != 3 || fn.Instrs[1].Op != Op(row.op) ||
					!reflect.DeepEqual(fn.Instrs[1].Args, []Operand{{Kind: OpReg, Reg: register}}) {
					t.Fatal("independent physical random encoding lost its whole form", arch, row.op, register, err)
				}
			}
		}
		source.WriteString("RET\n")
		expected = append(expected, 0xc3)
		if actual := assembleX87ControlBytes(t, arch, source.String()); !bytes.Equal(actual, expected) {
			t.Fatalf("%s original Go physical register/width encodings differ: %x / %x", arch, actual, expected)
		}
	}
}

func TestX86HardwareRandomEveryRegisterByteAndStatusEffect(t *testing.T) {
	registers := []Reg{AX, CX, DX, BX, SP, BP, SI, DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RandomResultOracle {
			if arch == "386" && row.width == 8 {
				continue
			}
			for index, register := range registers {
				if arch == "386" && index >= 8 {
					break
				}
				t.Run(arch+"/"+row.op+"/"+string(register), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" "+string(register))
					for _, prior := range []uint8{0, 0xa5, 0xff} {
						state := x86ResultState{direction: x86ResultDirectionBackward}
						state.gp[index], state.pointerGP[index] = prior, true
						state.xmm[3], state.masks[2] = 0x1234, true
						state.valueStack = &x86ResultValueStack{bytes: []uint8{1, 2, 3, 4}, id: true}
						want := state.clone()
						// Physical SP, and AMD64 BP, are not ordinary NUM destinations.
						valid := register != SP && !(arch == "amd64" && register == BP)
						if valid {
							want.flags = 0x3f
							want.pointerGP[index] = false
							want.gp[index] = 0xff
							if row.width == 2 {
								want.gp[index] = prior | 3
							}
						}
						if x86ResultTransfer(ins, &state, nil, 0, arch) != valid || !reflect.DeepEqual(state, want) {
							t.Error("random must define only written bytes and six FLAGS, preserving unrelated state", prior)
						}
					}
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if !known || err != nil || !effect.requiresResultProof || effect.flagsRead != 0 ||
						effect.flagsDefined != 0x3f || effect.flagsKilled != 0x3f || len(effect.operands) != 1 ||
						effect.operands[0].read || !effect.operands[0].write || effect.operands[0].width != row.width {
						t.Error("missing complete write-only typed random effect", err)
					}
				})
			}
		}
	}
}

func TestX86HardwareRandomDispatchIdentityBeforeEmission(t *testing.T) {
	for _, row := range x86RandomResultOracle {
		for _, invalid := range []string{"dispatch", "suffix", "constructed-operand", "foreign-mode"} {
			t.Run(row.op+"/"+invalid, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.op+" AX")
				op := ins.Op
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = "amd64"
				switch invalid {
				case "dispatch":
					ins.Op = "NOP"
				case "suffix":
					op += ".Z"
				case "constructed-operand":
					ins.Args[0].ImmRaw = "$unknown"
				case "foreign-mode":
					ctx.goarch = "arm64"
				}
				before, temporary := output.String(), ctx.tmp
				known, terminated, err := ctx.lowerHardwareRandom(op, ins)
				if !known || terminated || err == nil || before != output.String() || temporary != ctx.tmp {
					t.Error("invalid random dispatch emitted partial IR", known, terminated, err)
				}
			})
		}
	}
}

func TestX86HardwareRandomInitializedThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, value, size := "L", "uint32", 4
			if target.arch == "amd64" {
				word, value, size = "Q", "uint64", 8
			}
			var source, declarations strings.Builder
			for _, row := range x86RandomResultOracle {
				if target.arch == "386" && row.width == 8 {
					continue
				}
				for _, raw := range []bool{false, true} {
					name := fmt.Sprintf("%s%t", row.op, raw)
					body := row.op + " BX\n"
					if raw {
						body = x86RawDisplacementDirectives(x86RandomOracleBytes(row.width, row.extension, 3))
					}
					fmt.Fprintf(&declarations, "func %s(seed %s) (%s,%s)\n", name, value, value, value)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s seed+0(FP),BX\nPUSH%s $0x8d7\nPOPF%s\n%sPUSHF%s\nPOP%s AX\nMOV%s BX,value+%d(FP)\nMOV%s AX,status+%d(FP)\nRET\n",
						name, 3*size, word, word, word, body, word, word, word, size, word, 2*size)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("initialized random value/FLAGS program", api, err)
				}
				for _, row := range x86RandomResultOracle {
					if target.arch == "386" && row.width == 8 {
						continue
					}
					intrinsic := fmt.Sprintf("@llvm.x86.%s.%d()", strings.ToLower(row.op[:len(row.op)-1]), row.width*8)
					if !strings.Contains(ir, intrinsic) {
						t.Fatal("actual hardware random intrinsic missing", intrinsic)
					}
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86HardwareRandomCannotSupplyFrameOrMissingResult(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86RandomResultOracle {
			if target.arch == "386" && row.width == 8 {
				continue
			}
			for _, invalid := range []struct{ name, body, declaration string }{
				{"stack", row.op + " SP\n", "func Value()"},
				{"missing-result", row.op + " BX\n", "func Value() uint32"},
				{"missing-upper", row.op + " BX\nMOVL BX,ret+0(FP)\n", "func Value() uint32"},
			} {
				if invalid.name == "missing-upper" && row.width != 2 {
					continue
				}
				t.Run(target.triple+"/"+row.op+"/"+invalid.name, func(t *testing.T) {
					extent := 4
					if invalid.name == "stack" {
						extent = 0
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sRET\n", extent, invalid.body)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, invalid.declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("random invented an entry/result/upper-byte role", api, err)
						}
					}
				})
			}
		}
	}
}
