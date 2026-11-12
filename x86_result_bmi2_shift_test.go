package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

var x86BMI2ResultNames = []string{
	"SARXL", "SARXQ", "SHLXL", "SHLXQ", "SHRXL", "SHRXQ", "RORXL", "RORXQ",
}

func TestX86BMI2ResultCompleteIndependentEncoderAttributes(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range x86BMI2ResultNames {
		prefix, table, zcase, opcode := "vexF3", "_ybextrl", "Zvex_v_rm_r", "0xF7"
		classes, advance := []string{"Yrl", "Yml", "Yrl"}, 2
		if strings.HasPrefix(name, "SHLX") {
			prefix = "vex66"
		} else if strings.HasPrefix(name, "SHRX") {
			prefix = "vexF2"
		} else if strings.HasPrefix(name, "RORX") {
			prefix, table, zcase, opcode = "vexF2", "_yrorxl", "Zvex_i_rm_r", "0xF0"
			classes, advance = []string{"Yu8", "Yml", "Yrl"}, 0
		}
		mapName, wide := "vex0F38", 0
		if opcode == "0xF0" {
			mapName = "vex0F3A"
		}
		if strings.HasSuffix(name, "Q") {
			wide = 1
		}
		first := goasmrules.X86AVXRule{
			Opcode: name, Ytab: table, Prefix: "Pavx", Classes: classes,
			ZCase: zcase, ZOffset: advance,
			OpBytes: []string{fmt.Sprintf("avxEscape | vex128 | %s | %s | vexW%d", prefix, mapName, wide), opcode},
		}
		expected := []goasmrules.X86AVXRule{first}
		if advance == 0 {
			second := first
			second.Classes = []string{"Yi8", "Yml", "Yrl"}
			second.RowIndex, second.ZOffset = 1, 2
			expected = append(expected, second)
		}
		var actual []goasmrules.X86AVXRule
		for _, rule := range rules {
			if rule.Opcode == name {
				actual = append(actual, rule)
			}
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("complete independent BMI2 encoding rows changed", name, actual, expected)
		}
	}
}

func x86BMI2ResultInstruction(t *testing.T, arch, op, input string, raw bool) string {
	t.Helper()
	count := "CX"
	if strings.HasPrefix(op, "RORX") {
		count = "$7"
	}
	instruction := op + " " + count + "," + input + ",AX"
	if !raw {
		return instruction
	}
	code := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
	return x86DwordProductDirectives(code[:len(code)-1])
}

func TestX86BMI2ResultDeadAndObservableUnknownInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86BMI2ResultNames {
			for _, raw := range []bool{false, true} {
				for _, unusedBool := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/raw=%t/bool=%t", target.triple, op, raw, unusedBool), func(t *testing.T) {
						extent, declaration := 0, "func Value()"
						if unusedBool {
							extent, declaration = 1, "func Value(unused bool)"
						}
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\nRET\n", extent,
							x86BMI2ResultInstruction(t, target.arch, op, "BX", raw))
						word, move := 8, "MOVQ"
						if target.arch == "386" {
							word, move = 4, "MOVL"
						}
						for _, api := range []string{"text", "module", "Go"} {
							if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err != nil || ir == "" {
								t.Fatal("dead nontrapping GP value must remain unknown, not prevent an independent return", api, err)
							}
							// Observing that same low result must fail. No private
							// implementation zeros or dead-value rule supply its bytes.
							observed := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n%s AX,ret+%d(FP)\nRET\n",
								extent+word, x86BMI2ResultInstruction(t, target.arch, op, "BX", raw), move, extent)
							if unusedBool {
								// uintptr results use the compiler's actual word alignment.
								observed = fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n%s AX,ret+%d(FP)\nRET\n",
									2*word, x86BMI2ResultInstruction(t, target.arch, op, "BX", raw), move, word)
							}
							ir, err := x86ScalarFPBitViewAPI(t, observed, declaration+" uintptr", target.arch, target.triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unknown BMI2 result borrowed implementation zeros", api, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86BMI2ResultVoidRoutesCompleteInputProof(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BMI2ResultNames {
			source := "TEXT Value(SB),4,$0-0\n" + x86BMI2ResultInstruction(t, arch, op, "BX", false) + "\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn, sig := file.Funcs[0], FuncSig{Name: "Value", Ret: Void}
			if !x86TypedFPResultNeedsProof(fn, sig, arch) {
				t.Fatal("dead named shift lost its mandatory source proof", arch, op)
			}
			ctx := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: arch}
			if err := checkX86ScalarFPResultInitialization(fn, sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("strict result observer invented missing input", arch, op, err)
			}
			if err := ctx.validateScalarFPSourceViews(); err != nil {
				t.Fatal("whole lowering proof lost the bounded dead-unknown GP contract", arch, op, err)
			}
		}
	}
}

func TestX86BMI2ResultInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, op := range x86BMI2ResultNames {
				for _, memory := range []bool{false, true} {
					for _, raw := range []bool{false, true} {
						name := fmt.Sprintf("Value%d", count)
						input, argument := "BX", "uintptr"
						if memory {
							input, argument = "(BX)", "*[8]byte"
						}
						fmt.Fprintf(&declarations, "func %s(value %s,count uintptr) uintptr\n", name, argument)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s value+0(FP),BX\n%s count+%d(FP),CX\n%s\n%s AX,ret+%d(FP)\nRET\n",
							name, 3*word, move, move, word, x86BMI2ResultInstruction(t, target.arch, op, input, raw), move, 2*word)
						count++
					}
				}
			}
			if count != 32 {
				t.Fatal("complete register/memory and named/raw denominator changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete BMI2 source lost its numerical/native continuation", api, err)
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

func TestX86BMI2ResultRawOriginCannotBeRebound(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BMI2ResultNames {
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+
				x86BMI2ResultInstruction(t, arch, op, "BX", true)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawBMI2ShiftSource(ins, arch) {
				t.Fatal("original shift/rotate lost its complete source binding", arch, op)
			}
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
				{"opcode", func(ins *Instr) {
					ins.Op = "SHLXL"
					if strings.HasPrefix(op, "SHLX") {
						ins.Op = "SARXL"
					} else if strings.HasPrefix(op, "RORX") {
						ins.Op = "RORXQ"
						if ins.x86SourceRaw.op == "RORXQ" {
							ins.Op = "RORXL"
						}
					}
				}},
				{"operand", func(ins *Instr) { ins.Args[1].Reg = DX }},
				{"source-operand", func(ins *Instr) { ins.x86SourceRaw.args[1].Reg = DX }},
				{"vector", func(ins *Instr) { ins.x86VectorBytes = 16 }},
				{"address", func(ins *Instr) { ins.x86AddressBits = 32 }},
				{"override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
				{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
				{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
			} {
				t.Run(arch+"/"+op+"/"+control.name, func(t *testing.T) {
					changed := ins
					changed.Args = append([]Operand(nil), ins.Args...)
					origin := *ins.x86SourceRaw
					origin.args = append([]Operand(nil), origin.args...)
					changed.x86SourceRaw = &origin
					control.change(&changed)
					state := x86ResultState{flags: x86ByteFlagsAll}
					for i := range state.gp {
						state.gp[i] = 0xff
					}
					before := state.clone()
					accepted, known := x86LoweredBMI2ShiftResultStep(changed, &state, nil, 0, arch)
					if accepted || known != (control.name != "origin") ||
						x86RawBMI2ShiftSource(changed, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("changed source acquired raw shift/rotate authority", accepted, known)
					}
				})
			}
		}
	}
}

func TestX86BMI2ResultEveryInputByteBeforeAliasedWrite(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BMI2ResultNames {
			for _, raw := range []bool{false, true} {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+
					x86BMI2ResultInstruction(t, arch, op, "AX", raw)+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				width := 4
				if arch == "amd64" && strings.HasSuffix(op, "Q") {
					width = 8
				}
				for missing := -2; missing < width; missing++ {
					t.Run(fmt.Sprintf("%s/%s/raw=%t/missing=%d", arch, op, raw, missing), func(t *testing.T) {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0] = (1 << uint(width)) - 1
						state.gp[1] = 1 // Only the count's low byte is consumed.
						if missing >= 0 {
							state.gp[0] &^= 1 << uint(missing)
						} else if missing == -1 {
							state.gp[1] = 0
							if strings.HasPrefix(op, "RORX") {
								return // Immediate rotates have no register-count input.
							}
						}
						before := state.clone()
						accepted := false
						if raw {
							var known bool
							accepted, known = x86LoweredBMI2ShiftResultStep(ins, &state, nil, 0, arch)
							if !known {
								t.Fatal("exact raw input not owned by its paired transfer")
							}
						} else {
							accepted = x86ResultTransfer(ins, &state, nil, 0, arch)
						}
						if raw && missing != -2 {
							// The lowering-only nontrapping continuation retains an
							// unknown output, just like its named counterpart. It must
							// never invent bytes from the aliased old destination.
							before.gp[0] = 0
							if width == 4 {
								before.gp[0] = 0xf0
							}
							if !accepted || !reflect.DeepEqual(state, before) {
								t.Fatal("paired dead-unknown output acquired numerical bytes or changed unrelated state")
							}
							return
						}
						if accepted != (missing == -2) || !accepted && !reflect.DeepEqual(state, before) {
							t.Fatal("aliased destination hid missing data/count or mutated rejected state", accepted)
						}
						if accepted && (state.gp[0] != 0xff || state.flags != x86ByteFlagsAll) {
							t.Fatal("BMI2 failed zero extension or FLAGS preservation", state.gp[0], state.flags)
						}
					})
				}
			}
		}
	}
}
