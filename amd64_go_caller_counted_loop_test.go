package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86CallerCountedLoopScalarAssembly(raw bool) string {
	control := "TESTB $3,R9\nJE done\nMOVL R9,AX\nANDL $3,AX\nXORL CX,CX"
	latch := "ADDQ $1,CX\nCMPL CX,AX\nJNE again"
	if raw {
		// The guard, bound, counter and latch are unchanged encodings from
		// the discovered dot_avx256 first loop. The body below is first-party
		// initialized integer arithmetic, not execution of that external source.
		control = "LONG $0x03c1f641\nJE done\nWORD $0x8944; BYTE $0xc8\nWORD $0xe083; BYTE $0x03\nWORD $0xc931"
		latch = "LONG $0x01c18348\nWORD $0xc839\nJNE again"
	}
	body := "MOVQ (CX),R9\nXORL R10,R10\n" + control + `
again:
MOVL (DI),BX
MOVL (SI),R11
ADDL R11,BX
ADDL BX,R10
ADDQ $4,DI
ADDQ $4,SI
` + latch + `
done:
MOVL R10,(DX)`
	return strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", body, 1)
}

func x86CallerCountedLoopScalarSource() string {
	return strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint32")
}

func x86CallerCountedLoopSeparateExitAssembly(raw bool) string {
	assembly := strings.Replace(x86CallerCountedLoopScalarAssembly(raw), "JE done", "JE empty", 1)
	epiloque := strings.SplitN(x86CallerFixtureAssembly, "MOVL AX,(DX)\n", 2)[1]
	return assembly + "empty:\nMOVL R10,(DX)\n" + epiloque
}

func TestX86GoCallerCountedLoopActualDecodedCounterAndGuard(t *testing.T) {
	assembly := x86CallerCountedLoopScalarAssembly(true)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var effects []string
	for _, ins := range decoded.Instrs {
		if ins.Op == "TESTB" || ins.Op == "ANDL" || ins.Op == "XORL" ||
			ins.Op == "CMPL" || ins.Op == "ADDQ" || ins.Op == "JE" || ins.Op == "JNE" {
			effects = append(effects, fmt.Sprintf("%s %v", ins.Op, ins.Args))
		}
	}
	t.Logf("actual raw-decoder guard/counter/latch effects: %s", strings.Join(effects, "; "))
	for _, want := range []struct {
		op   Op
		args []Operand
	}{
		{"TESTB", []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("R9")}}},
		{"ANDL", []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: AX}}},
		{"XORL", []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: CX}}},
		{"ADDQ", []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: CX}}},
		{"CMPL", []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: CX}}},
	} {
		found := false
		for _, ins := range decoded.Instrs {
			if ins.Op != want.op || len(ins.Args) != len(want.args) {
				continue
			}
			matched := true
			for index, arg := range ins.Args {
				if arg.Kind != want.args[index].Kind || arg.Reg != want.args[index].Reg || arg.Imm != want.args[index].Imm {
					matched = false
				}
			}
			found = found || matched
		}
		if !found {
			t.Fatalf("source-bound decoder lacks exact effect %s %v", want.op, want.args)
		}
	}
}

func TestX86GoCallerCountedLoopSafeInitializedSourceReachesObjects(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			assembly := x86CallerCountedLoopScalarAssembly(raw)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Errorf("bounded original-source integer loop %s: %v", triple, err)
				}
			}
		})
	}
}

func TestX86GoCallerCountedLoopSafeSeparateExitReachesObjects(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			assembly := x86CallerCountedLoopSeparateExitAssembly(raw)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerCountedLoopScalarSource(), assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Errorf("bounded original-source backedge %s: %v", triple, err)
				}
			}
		})
	}
}
