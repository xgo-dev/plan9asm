package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86ScalarReciprocalNativeAccessAndExactSourceIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarReciprocalOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				args := "(AX),X2"
				if row.vector {
					args = "(AX),X1,X2"
				}
				ins := x86ScalarLaneInstruction(t, row.op+" "+args)
				initial := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				initial.xmm[1], initial.xmm[2] = 0xffff, 0xffff
				initial.pointerGP[0] = true
				state := initial.clone()
				if accepted, known := x86ResultScalarReciprocalStep(ins, &state, nil, arch, false); !known || accepted || !reflect.DeepEqual(state, initial) {
					t.Fatal("native m32 was invented by the numerical domain", accepted, known, state)
				}
				if accepted, known := x86ResultScalarReciprocalStep(ins, &state, nil, arch, true); !known || !accepted {
					t.Fatal("exact m32 native continuation was not available", accepted, known)
				}
				expected := initial.clone()
				expected.xmm[2], expected.vectorUpper[2] = state.xmm[2], state.vectorUpper[2]
				if !reflect.DeepEqual(state, expected) {
					t.Fatal("scalar estimate supplied a storage, pointer, FLAGS or frame fact", state)
				}
				missing := initial.clone()
				missing.pointerGP[0] = false
				before := missing.clone()
				if accepted, _ := x86ResultScalarReciprocalStep(ins, &missing, nil, arch, true); accepted || !reflect.DeepEqual(missing, before) {
					t.Fatal("dead native input became optional", missing)
				}

				code := []byte{0xf3, 0x0f, row.opcode, 0x10}
				if row.vector {
					code = []byte{0xc4, 0xe1, 0x72, row.opcode, 0x10}
				}
				mode := 64
				if arch == "386" {
					mode = 32
				}
				raw, _, recognized, err := decodedX86RawScalarReciprocalInstruction(code, mode)
				if !recognized || err != nil {
					t.Fatal("complete raw scalar estimate row missing", err)
				}
				raw.x86Encoded = true
				raw.x86SourceRaw = &x86SourceRawInstruction{
					op: raw.Op, args: append([]Operand(nil), raw.Args...),
				}
				if !x86RawScalarReciprocalSource(raw, arch) {
					t.Fatal("exact sealed source was not recognized")
				}
				state = initial.clone()
				if accepted, known := x86ResultScalarReciprocalStep(raw, &state, nil, arch, true); !known || !accepted {
					t.Fatal("sealed original m32 could not retain its native continuation")
				}
				for _, mutate := range []func(*Instr){
					func(ins *Instr) { ins.x86SourceRaw = nil },
					func(ins *Instr) { ins.x86VectorBytes = 32 },
					func(ins *Instr) { ins.x86AddressBits = 32 },
					func(ins *Instr) { ins.x86UnboundAddressOverride = true },
					func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
					func(ins *Instr) { ins.Args[0].Mem.Off = 4 },
					func(ins *Instr) { ins.Args[len(ins.Args)-1].Reg = "X3" },
				} {
					changed := raw
					changed.Args = append([]Operand(nil), raw.Args...)
					mutate(&changed)
					state = initial.clone()
					if x86RawScalarReciprocalSource(changed, arch) {
						t.Fatal("changed complete raw identity was authorized", changed)
					}
					if accepted, _ := x86ResultScalarReciprocalStep(changed, &state, nil, arch, true); accepted || !reflect.DeepEqual(state, initial) {
						t.Fatal("changed source mutated state or borrowed native inputs", changed, state)
					}
				}
			})
		}
	}
}
