package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var x86AccumulatorSignExtendOracle = []struct {
	op, prefix, opcode string
	read, write        int64
	destination        Reg
}{
	{"CBW", "Pe", "0x98", 1, 2, AX},
	{"CWDE", "Px", "0x98", 2, 4, AX},
	{"CDQE", "Pw", "0x98", 4, 8, AX},
	{"CWD", "Pe", "0x99", 2, 2, DX},
	{"CDQ", "Px", "0x99", 4, 4, DX},
	{"CQO", "Pw", "0x99", 8, 8, DX},
}

func TestX86AccumulatorSignExtendCompleteEffectsAndGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}") {
		t.Fatal("complete original zero-operand encoder row changed")
	}
	for _, row := range x86AccumulatorSignExtendOracle {
		want := fmt.Sprintf("{A%s, ynone, %s, opBytes{%s}}", row.op, row.prefix, row.opcode)
		if !strings.Contains(string(data), want) {
			t.Fatal("independent Go opcode attributes changed", want)
		}
		for _, arch := range []string{"amd64", "386"} {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := Instr{Op: Op(row.op), Raw: row.op}
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if arch == "386" && row.write == 8 {
					if !known || err == nil {
						t.Fatal("Go-rejected physical qword acquired a result effect", known, err)
					}
					return
				}
				if !known || err != nil || len(effect.operands) != 2 || !effect.requiresResultProof ||
					effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatal("complete implicit AX dependency or preserved FLAGS is absent", effect, known, err)
				}
				read, write := effect.operands[0], effect.operands[1]
				if read.operand.Reg != AX || read.width != row.read || !read.read || read.write ||
					write.operand.Reg != row.destination || write.width != row.write || write.read || !write.write {
					t.Fatal("implicit source/destination byte roles diverged", effect)
				}
				for missing := int64(-1); missing < row.read; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0] = uint8(1<<uint(row.read) - 1)
					if missing >= 0 {
						state.gp[0] &^= 1 << uint(missing)
					}
					if got := x86ResultTransfer(ins, &state, nil, 0, arch); got != (missing < 0) {
						t.Fatal("implicit AX bytes borrowed implementation initialization", missing, got)
					}
					if state.flags != x86ByteFlagsAll {
						t.Fatal("sign extension changed source FLAGS")
					}
				}
			})
		}
	}
}

func TestX86AccumulatorSignExtendVoidNeedsSource(t *testing.T) {
	x86AccumulatorSignExtendVoidInputs(t, false)
}

func TestX86AccumulatorSignExtendRawVoidNeedsSource(t *testing.T) {
	x86AccumulatorSignExtendVoidInputs(t, true)
}

func x86AccumulatorSignExtendVoidInputs(t *testing.T, raw bool) {
	t.Helper()
	for _, row := range x86AccumulatorSignExtendOracle {
		for _, target := range x86RawReturnTargets {
			if target.arch == "386" && row.write == 8 {
				continue // Actual Go mode rejection is checked separately above.
			}
			instruction := x86AccumulatorSignExtendSource(t, row.op, target.arch, raw)
			source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("dead implicit input borrowed a zeroed register", row.op, target.triple, api, err)
				}
			}
		}
	}
}

func TestX86AccumulatorSignExtendDispatchRejectsBeforeIR(t *testing.T) {
	for _, row := range x86AccumulatorSignExtendOracle {
		for _, arch := range []string{"386", "amd64"} {
			for _, bad := range []Instr{
				{Op: "MOVL", Raw: "foreign dispatch"},
				{Op: Op(row.op), Args: []Operand{{Kind: OpReg, Reg: AX}}, Raw: "extra operand"},
			} {
				var ir strings.Builder
				consumer := &amd64Ctx{b: &ir, goarch: arch}
				known, terminated, err := consumer.lowerAccumulatorSignExtend(Op(row.op), bad)
				if !known || terminated || err == nil || ir.Len() != 0 {
					t.Fatal("invalid complete grammar emitted IR before rejection", row.op, arch, err, ir.String())
				}
			}
		}
	}
}

func TestX86AccumulatorSignExtendInitializedFiveTargetObjects(t *testing.T) {
	x86AccumulatorSignExtendTargetObjects(t, false)
}

func TestX86AccumulatorSignExtendRawInitializedFiveTargetObjects(t *testing.T) {
	x86AccumulatorSignExtendTargetObjects(t, true)
}

func x86AccumulatorSignExtendSource(t *testing.T, op, arch string, raw bool) string {
	t.Helper()
	if !raw {
		return op
	}
	code := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$0-0\n"+op+"\nRET\n")
	return x86DwordProductDirectives(code[:len(code)-1])
}

func x86AccumulatorSignExtendTargetObjects(t *testing.T, raw bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, typ := 8, "MOVQ", "uint64"
			if target.arch == "386" {
				word, move, typ = 4, "MOVL", "uint32"
			}
			var source, declarations strings.Builder
			for _, row := range x86AccumulatorSignExtendOracle {
				if target.arch == "386" && row.write == 8 {
					continue
				}
				fmt.Fprintf(&declarations, "func Value%s() %s\n", row.op, typ)
				fmt.Fprintf(&source, "TEXT ·Value%s(SB),4,$0-%d\n%s $-1,AX\n%s $7,DX\n%s\n%s %s,ret+0(FP)\nRET\n",
					row.op, word, move, move, x86AccumulatorSignExtendSource(t, row.op, target.arch, raw), move, row.destination)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("initialized implicit-source family lost its public result", api, err)
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

func TestX86AccumulatorSignExtendRawOriginCannotBeRebound(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86AccumulatorSignExtendOracle {
			if arch == "386" && row.write == 8 {
				continue
			}
			code := x86AccumulatorSignExtendSource(t, row.op, arch, true)
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+code+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawAccumulatorSignExtendSource(ins, arch) {
				t.Fatal("actual original implicit instruction lost its source identity", row.op, arch)
			}
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"absent-origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
				{"opcode", func(ins *Instr) {
					ins.Op = "CBW"
					if row.op == "CBW" {
						ins.Op = "CWD"
					}
				}},
				{"operand", func(ins *Instr) { ins.Args = []Operand{{Kind: OpReg, Reg: AX}} }},
				{"source-operand", func(ins *Instr) { ins.x86SourceRaw.args = []Operand{{Kind: OpReg, Reg: AX}} }},
				{"vector-width", func(ins *Instr) { ins.x86VectorBytes = 16 }},
				{"address", func(ins *Instr) { ins.x86AddressBits = 32 }},
				{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
				{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
			} {
				t.Run(arch+"/"+row.op+"/"+control.name, func(t *testing.T) {
					changed := ins
					origin := *ins.x86SourceRaw
					changed.x86SourceRaw = &origin
					control.change(&changed)
					state := x86ResultState{flags: x86ByteFlagsAll}
					before := state.clone()
					accepted, known := x86LoweredAccumulatorSignExtendResultStep(changed, &state, nil, 0, arch)
					// This decoder's ordinary scalar form has no encoded-only
					// flag. Removing its origin leaves a named instruction: the
					// paired raw consumer must decline ownership, not accept it.
					wantKnown := control.name != "absent-origin"
					if accepted || known != wantKnown || x86RawAccumulatorSignExtendSource(changed, arch) || !reflect.DeepEqual(before, state) {
						t.Fatal("changed raw origin borrowed implicit GP inputs or writes", accepted, known)
					}
				})
			}
		}
	}
}
