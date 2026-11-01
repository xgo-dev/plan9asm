package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86UnlockedScalarRMWRows(arch string) []x86LockScalarOracleForm {
	var rows []x86LockScalarOracleForm
	for _, row := range x86LockScalarOracleForms(arch) {
		if !strings.HasPrefix(row.op, "BT") {
			rows = append(rows, row)
		}
	}
	return rows
}

func x86UnlockedScalarRMWFixture(arch, instruction string, result bool) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	bytes := word * 2
	declaration := "func Value(p *[16]byte,value uintptr)"
	finish := ""
	if result {
		bytes += 4
		declaration += " uint32"
		finish = fmt.Sprintf("MOVL $7,AX\nMOVL AX,ret+%d(FP)\n", word*2)
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),DI\n%s value+%d(FP),CX\nMOVL $1,BX\nCLC\n%s\n%sRET\n",
		bytes, move, move, word, strings.Replace(instruction, "1(SI)", "-1(DI)(BX*1)", 1), finish)
	return source, declaration
}

func TestX86UnlockedScalarRMWCompleteFamilyThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86UnlockedScalarRMWRows(target.arch)
			want := 72
			if target.arch == "386" {
				want = 54
			}
			if len(rows) != want {
				t.Fatal("incomplete independent scalar RMW family", len(rows), want)
			}
			var complete, declarations strings.Builder
			for index, row := range rows {
				source, declaration := x86UnlockedScalarRMWFixture(target.arch, row.text, true)
				name := fmt.Sprintf("RMW%d", index)
				complete.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
				declarations.WriteString(strings.Replace(declaration, "Value", name, 1) + "\n")
				for _, result := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/result=%t", row.text, result), func(t *testing.T) {
						source, declaration := x86UnlockedScalarRMWFixture(target.arch, row.text, result)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
								if err != nil || ir == "" {
									t.Fatal("complete numerical RMW lost its paired native continuation", err)
								}
							})
						}
					})
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, complete.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run("complete-objects/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, complete.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						x86UnlockedScalarRMWCheckBodies(t, text, rows)
						if strings.Count(text, "load volatile i") != want || strings.Count(text, "store volatile i") != want ||
							strings.Contains(text, "atomicrmw ") || strings.Contains(text, "lock; ") {
							t.Fatal("unlocked family lost exact native accesses or acquired atomic semantics")
						}
						for _, backend := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, backend)
						}
					}
				})
			}
		})
	}
}

// Bind each original body, not just totals or unused helper definitions.
func x86UnlockedScalarRMWCheckBodies(t *testing.T, ir string, rows []x86LockScalarOracleForm) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	for index, row := range rows {
		function := module.NamedFunction(fmt.Sprintf("RMW%d", index))
		if function.IsNil() || function.FirstBasicBlock().IsNil() {
			t.Fatal("original native RMW body disappeared", row.text)
		}
		body := function.String()
		for _, atomic := range []string{"atomicrmw ", "cmpxchg ", "load atomic ", "store atomic ", "lock;"} {
			if strings.Contains(body, atomic) {
				t.Fatal("ordinary body acquired an implicit atomic effect", row.text, atomic)
			}
		}
		bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[row.op[len(row.op)-1]]
		loads, stores := 0, 0
		for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
			for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
				opcode := instruction.InstructionOpcode()
				if opcode != llvm.Load && opcode != llvm.Store || !instruction.IsVolatile() {
					continue
				}
				typ := instruction.Type()
				if opcode == llvm.Store {
					typ = instruction.Operand(0).Type()
					stores++
				} else {
					loads++
				}
				if typ.TypeKind() != llvm.IntegerTypeKind || typ.IntTypeWidth() != bits || instruction.Alignment() != 1 {
					t.Fatal("body has an inexact native RMW width/alignment", row.text, instruction.String())
				}
			}
		}
		if loads != 1 || stores != 1 {
			t.Fatal("original body lost its exact paired native access", row.text, loads, stores)
		}
	}
}

func TestX86UnlockedScalarRMWCannotAcquireImplicitLockFromAtomicEntry(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86UnlockedScalarRMWRows(arch) {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, row.text)
				context, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{instruction}}, FuncSig{Ret: Void}, nil)
				context.goarch = arch
				before, temporary := output.String(), context.tmp
				known, terminated, err := context.lowerAtomic(instruction.Op, instruction)
				if known || terminated || err != nil || output.String() != before || context.tmp != temporary {
					t.Fatal("atomic entry must not silently lock an ordinary instruction", known, terminated, err)
				}
			})
		}
	}
}

func TestX86UnlockedScalarRMWEmitterKeepsNativeWidthAndNonAtomicIdentity(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86UnlockedScalarRMWRows(arch) {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.text)
				// This is an unbound emitter unit, not initialized source,
				// native-memory permission or an executable entry fixture.
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				ctx.blocks = []amd64Block{{instrs: []Instr{ins}}}
				if _, err := ctx.lowerInstr(0, 0, ins, nil, nil); err != nil {
					t.Fatal(err)
				}
				bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[row.op[len(row.op)-1]]
				text := output.String()
				if strings.Count(text, fmt.Sprintf("load volatile i%d,", bits)) != 1 ||
					strings.Count(text, fmt.Sprintf("store volatile i%d ", bits)) != 1 ||
					strings.Contains(text, "atomicrmw ") || strings.Contains(text, "lock; ") {
					t.Fatal("unlocked native RMW lost its exact volatile width or became atomic", text)
				}
			})
		}
	}
}

func TestX86UnlockedScalarRMWDoesNotInventInputsResultsOrStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple, resultOffset := "x86_64-unknown-linux-gnu", 16
		if arch == "386" {
			triple, resultOffset = "i386-unknown-linux-gnu", 8
		}
		for _, row := range x86UnlockedScalarRMWRows(arch) {
			if strings.Contains(row.text, "$1") {
				continue // Source-format positives are complete; these mutations need GP input.
			}
			for _, result := range []bool{true, false} {
				source, declaration := x86UnlockedScalarRMWFixture(arch, row.text, result)
				variants := map[string]string{
					"unknown-base":  strings.Replace(source, "p+0(FP),DI", "p+0(FP),SI", 1),
					"numeric-base":  strings.Replace(source, "CLC\n", "MOVL $42,DI\nCLC\n", 1),
					"unknown-index": strings.Replace(source, "MOVL $1,BX\n", "", 1),
					"pointer-index": strings.Replace(source, "MOVL $1,BX\n", "MOVL DI,BX\n", 1),
				}
				if result {
					variants["missing-result"] = strings.Replace(source,
						fmt.Sprintf("MOVL AX,ret+%d(FP)\n", resultOffset), "", 1)
				}
				if strings.Contains(row.text, ",") {
					variants["unknown-value"] = strings.Replace(source, ",CX\n", ",DX\n", 1)
					move := "MOVQ"
					if arch == "386" {
						move = "MOVL"
					}
					variants["pointer-value"] = strings.Replace(source, "CLC\n", move+" DI,CX\nCLC\n", 1)
				}
				if strings.HasPrefix(row.op, "ADC") || strings.HasPrefix(row.op, "SBB") {
					variants["unknown-carry"] = strings.Replace(source, "CLC\n", "", 1)
				}
				for name, changed := range variants {
					t.Run(fmt.Sprintf("%s/%s/result=%t/%s", arch, row.text, result, name), func(t *testing.T) {
						if changed == source {
							t.Fatal("negative mutation did not change the source")
						}
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
								if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
									t.Fatal("unlocked RMW manufactured a source, carry or native address", err)
								}
							})
						}
					})
				}
			}
		}
	}
}
