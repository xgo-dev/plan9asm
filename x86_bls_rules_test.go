package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86BLSCompleteIndependentGoRowsAndPhysicalMode(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	if !strings.Contains(compact, "var_yblsil=[]ytab{{zcase:Zvex_rm_r_vo,zoffset:3,args:argList{Yml,Yrl}},}") {
		t.Fatal("complete Go BLS encoder operand row changed")
	}
	families := []struct {
		name  string
		digit byte
		kind  x86BLSKind
	}{{"BLSI", 3, x86BLSIsolate}, {"BLSMSK", 2, x86BLSMask}, {"BLSR", 1, x86BLSReset}}
	if len(x86BLSSpecs) != 6 {
		t.Fatal("BLS spec differs from the complete six-member Go family")
	}
	for _, family := range families {
		for _, width := range []struct {
			suffix string
			w      int
			bits   int
		}{{"L", 0, 32}, {"Q", 1, 64}} {
			op := family.name + width.suffix
			row := fmt.Sprintf("{as:A%s,ytab:_yblsil,prefix:Pavx,op:opBytes{avxEscape|vex128|vex0F38|vexW%d,0xF3,0%d,}},", op, width.w, family.digit)
			if !strings.Contains(compact, row) {
				t.Fatal("complete BLS opcode attribute binding changed", row)
			}
			if x86BLSSpecs[Op(op)] != (x86BLSSpec{width.bits, family.kind, family.digit}) {
				t.Fatal("typed BLS attributes disagree with independent Go encoder", op)
			}
			for _, arch := range []string{"386", "amd64"} {
				code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+op+" AX,BX\nRET\n")
				want := []byte{0xc4, 0xe2, byte(0x60 | width.w<<7), 0xf3, byte(0xc0 | family.digit<<3), 0xc3}
				if !bytes.Equal(code, want) {
					t.Fatalf("%s/%s Go bytes %x, want %x", arch, op, code, want)
				}
				ins := x86ScalarLaneInstruction(t, op+" (AX),BX")
				physicalWidth := int64(4)
				if arch == "amd64" {
					physicalWidth = int64(width.bits / 8)
				}
				for index := range ins.Args {
					got, write, valid := x86InstructionMemoryShape(ins, index, arch)
					if valid != (index == 0) || valid && (got != physicalWidth || write) {
						t.Fatal("BLS source tuple differs from physical mode", arch, op, index, got, write, valid)
					}
				}
			}
		}
	}
}

func TestX86BLSResultByteHolesAliasesAndFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BLSTestNames {
			width := int64(4)
			if arch == "amd64" && strings.HasSuffix(op, "Q") {
				width = 8
			}
			for _, output := range []string{"AX", "BX", "CX", "SP", "BP"} {
				ins := x86ScalarLaneInstruction(t, op+" AX,"+output)
				for _, consumer := range x86ResultGPSIMDConsumers {
					for missing := -1; missing < int(width); missing++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.gp[0] = uint8((uint16(1) << uint(width)) - 1)
						if missing >= 0 {
							state.gp[0] &^= 1 << uint(missing)
						}
						before := state.clone()
						accept := missing == -1 && output != "SP" && (arch == "386" || output != "BP")
						if got := consumer.step(ins, &state, nil, 0, arch); got != accept {
							t.Fatal("BLS missing input or destination boundary changed", arch, op, output, consumer.name, missing, got)
						}
						want := before.clone()
						if accept {
							index, _, _ := x86ResultGP(Reg(output), width, arch)
							want.gp[index] = 0xff
							want.flags = x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF
						}
						if !reflect.DeepEqual(state, want) {
							t.Fatal("BLS changed unrelated state or partially applied failed inputs", arch, op, output, missing)
						}
					}
				}
			}
		}
	}
}

func TestX86BLSGrammarRejectsDispatchAndSourceMutation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BLSTestNames {
			for _, row := range []string{op + ".Z AX,BX", op + " $1,BX", op + " AL,BX", op + " X0,BX", op + " AX,(BX)"} {
				ins := x86ScalarLaneInstruction(t, row)
				before := ins
				before.Args = append([]Operand(nil), ins.Args...)
				if _, known, err := x86BLSProperties(ins.Op, ins, arch); !known || err == nil {
					t.Fatal("BLS invalid grammar accepted", arch, row, known, err)
				}
				if !reflect.DeepEqual(ins, before) {
					t.Fatal("BLS grammar mutated original source", row)
				}
			}
			if _, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+op+" (AX)(CX*3),BX\nRET\n"); err == nil {
				t.Fatal("invalid BLS scale escaped the source parser", arch, op)
			}
			memory := x86ScalarLaneInstruction(t, op+" (AX)(CX*2),BX")
			memory.Args[0].Mem.Scale = 3
			if _, known, err := x86BLSProperties(memory.Op, memory, arch); !known || err == nil {
				t.Fatal("invalid BLS scale escaped direct typed validation", arch, op)
			}
			ins := x86ScalarLaneInstruction(t, op+" AX,BX")
			ins.Op = "MOVL"
			if _, known, err := x86BLSProperties(Op(op), ins, arch); !known || err == nil {
				t.Fatal("BLS dispatch borrowed another instruction's source", arch, op)
			}
		}
	}
}
