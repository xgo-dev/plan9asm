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

func TestX86BEXTRCompleteIndependentGoRowsAndPhysicalMode(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	for _, row := range []string{
		"var_ybextrl=[]ytab{{zcase:Zvex_v_rm_r,zoffset:2,args:argList{Yrl,Yml,Yrl}},}",
		"{as:ABEXTRL,ytab:_ybextrl,prefix:Pavx,op:opBytes{avxEscape|vex128|vex0F38|vexW0,0xF7,}},",
		"{as:ABEXTRQ,ytab:_ybextrl,prefix:Pavx,op:opBytes{avxEscape|vex128|vex0F38|vexW1,0xF7,}},",
	} {
		if !strings.Contains(compact, row) {
			t.Fatal("complete BEXTR Go encoder row/attribute binding changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BEXTRL", "BEXTRQ"} {
			code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+op+" AX,BX,CX\nRET\n")
			want := []byte{0xc4, 0xe2, 0x78, 0xf7, 0xcb, 0xc3}
			if op == "BEXTRQ" {
				want[2] = 0xf8
			}
			if !bytes.Equal(code, want) {
				t.Fatalf("%s/%s original Go encoding %x, want %x", arch, op, code, want)
			}
			ins := x86ScalarLaneInstruction(t, op+" AX,(BX),CX")
			width := int64(4)
			if arch == "amd64" && op == "BEXTRQ" {
				width = 8
			}
			for index := range ins.Args {
				got, write, valid := x86InstructionMemoryShape(ins, index, arch)
				if valid != (index == 1) || valid && (got != width || write) {
					t.Fatal("BEXTR physical source tuple changed", arch, op, index, got, write, valid)
				}
			}
		}
	}
}

func TestX86BEXTRCompleteGoRegisterBanks(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		registers := strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15")
		if arch == "386" {
			registers = registers[:8]
		}
		var source strings.Builder
		source.WriteString("TEXT f(SB),4,$0-0\n")
		count := 0
		for _, op := range []string{"BEXTRL", "BEXTRQ"} {
			for _, control := range registers {
				for _, input := range registers {
					for _, output := range registers {
						row := fmt.Sprintf("%s %s,%s,%s", op, control, input, output)
						source.WriteString(row + "\n")
						ins := x86ScalarLaneInstruction(t, row)
						if _, known, err := x86BEXTRProperties(ins.Op, ins, arch); !known || err != nil {
							t.Fatal("complete Go GP bank rejected", arch, row, err)
						}
						count++
					}
				}
			}
		}
		source.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		if count != 2*len(registers)*len(registers)*len(registers) {
			t.Fatal("incomplete register-bank union", arch, count)
		}
	}
}

func TestX86BEXTRResultByteHolesAliasesAndFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BEXTRL", "BEXTRQ"} {
			width := int64(4)
			if arch == "amd64" && op == "BEXTRQ" {
				width = 8
			}
			for _, output := range []string{"AX", "BX", "CX", "SP", "BP"} {
				ins := x86ScalarLaneInstruction(t, op+" AX,BX,"+output)
				for _, consumer := range x86ResultGPSIMDConsumers {
					for missing := -1; missing < int(width)+2; missing++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.gp[0], state.gp[3] = 3, uint8((uint16(1)<<uint(width))-1)
						if missing < 2 && missing >= 0 {
							state.gp[0] &^= 1 << uint(missing)
						} else if missing >= 2 {
							state.gp[3] &^= 1 << uint(missing-2)
						}
						before := state.clone()
						accept := missing == -1 && output != "SP" && (arch == "386" || output != "BP")
						if got := consumer.step(ins, &state, nil, 0, arch); got != accept {
							t.Fatal("BEXTR input/destination boundary changed", arch, op, output, consumer.name, missing, got)
						}
						expected := before.clone()
						if accept {
							index, _, _ := x86ResultGP(Reg(output), width, arch)
							expected.gp[index] = 0xff
							expected.flags = x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF
						}
						if !reflect.DeepEqual(state, expected) {
							t.Fatal("BEXTR changed unrelated state or partially applied a failed effect", arch, op, output, missing)
						}
					}
				}
			}
		}
	}
}

func TestX86BEXTRNativeReadAndOpaqueInputsStaySeparate(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BEXTRL", "BEXTRQ"} {
			for _, role := range []string{"paired", "standalone", "missing control byte", "numerical base", "unknown index", "raw", "encoded", "address override", "opaque control"} {
				t.Run(arch+"/"+op+"/"+role, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, op+" AX,(BX),CX")
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.pointerGP[3] = 3, true
					native := true
					switch role {
					case "standalone":
						native = false
					case "missing control byte":
						state.gp[0] = 1
					case "numerical base":
						state.pointerGP[3], state.gp[3] = false, 0xff
					case "unknown index":
						ins.Args[1].Mem.Index, ins.Args[1].Mem.Scale = SI, 4
					case "raw":
						ins.x86SourceRaw = &x86SourceRawInstruction{}
					case "encoded":
						ins.x86Encoded = true
					case "address override":
						ins.x86AddressBits = 32
					case "opaque control":
						state.pointerGP[0] = true
					}
					before := state.clone()
					accepted, known := x86ResultScalarBitFieldStep(ins, &state, nil, 0, arch, native)
					if !known || accepted != (role == "paired") || !accepted && !reflect.DeepEqual(state, before) {
						t.Fatal("BEXTR numerical continuation borrowed an unrelated source role", role, known, accepted)
					}
				})
			}
			for _, ordinal := range []int{0, 1} {
				ins := x86ScalarLaneInstruction(t, op+" AX,BX,CX")
				state := x86ResultState{gp: [16]uint8{0: 0xff, 3: 0xff}}
				register := []int{0, 3}[ordinal]
				state.pointerGP[register] = true
				before := state.clone()
				if accepted, _ := x86ResultScalarBitFieldStep(ins, &state, nil, 0, arch, true); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("opaque bits became a BEXTR numerical input", arch, op, ordinal)
				}
			}
		}
	}
}
