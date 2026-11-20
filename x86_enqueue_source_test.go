package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86EnqueueRawIdentityAndReadOnlyState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, prefix := range []byte{0xf2, 0xf3} {
			source, _ := x86EnqueuePointerProgram(arch, prefix, "", "")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn, err := decodeX86RawDirectives(file.Funcs[0], arch)
			if err != nil || len(fn.Instrs) != 8 || fn.Instrs[3].x86SourceRaw == nil {
				t.Fatal("missing complete raw enqueue source", err)
			}
			original := fn.Instrs[3]
			for _, mutation := range []string{"unchanged", "source", "device", "origin-opcode", "origin-operand",
				"missing-origin", "encoded", "address-size", "implicit-size", "segment", "unbound", "raw-return"} {
				t.Run(fmt.Sprintf("%s/%x/%s", arch, prefix, mutation), func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					origin := *original.x86SourceRaw
					ins.x86SourceRaw = &origin
					switch mutation {
					case "source":
						ins.Args[0].Mem.Off++
					case "device":
						ins.Args[1].Reg = BX
					case "origin-opcode":
						origin.op = "NOP"
					case "origin-operand":
						origin.args = []Operand{{Kind: OpReg, Reg: AX}}
					case "missing-origin":
						ins.x86SourceRaw = nil
					case "encoded":
						ins.x86Encoded = true
					case "address-size":
						ins.x86AddressBits /= 2
					case "implicit-size":
						ins.x86AddressBits = 0
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "unbound":
						ins.x86UnboundAddressOverride = true
					case "raw-return":
						ins.x86RawNearReturn = new(x86RawNearReturnForm)
					}
					valid := mutation == "unchanged"
					state := x86ResultState{direction: x86ResultDirectionBackward,
						valueStack: &x86ResultValueStack{bytes: []uint8{1, 2, 3, 4}, id: true}}
					state.pointerGP[0], state.pointerGP[7] = true, true
					state.callerAddressGP[0], state.callerAddressGP[7] = true, true
					state.gp[3], state.xmm[2], state.masks[4] = 0x55, 0x1234, true
					before, want := state.clone(), state.clone()
					if valid {
						want.flags = x86ByteFlagsAll
					}
					accepted, known := x86LoweredEnqueueResultStep(ins, &state, arch)
					if !known || accepted != valid || !reflect.DeepEqual(state, want) {
						t.Fatal("enqueue changed an input register/storage or accepted changed raw identity", accepted, known)
					}
					// No paired hardware emission belongs to a declaration query.
					standalone := before.clone()
					if x86ResultTransfer(ins, &standalone, nil, 0, arch) || !reflect.DeepEqual(standalone, before) {
						t.Fatal("standalone observer borrowed native submission")
					}
					if valid && (!x86ResultValueStackContinuation(ins, &state, arch) ||
						x86ResultDirectionAfter(ins, state.direction) != state.direction ||
						x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch) != before.callerAddressGP) {
						t.Fatal("enqueue lost independent DF/private cells or read-only address identities")
					}
				})
			}
		}
	}
}

func TestX86EnqueueLivePrivateStackAndMissingResult(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, size := "L", 4
		if target.arch == "amd64" {
			word, size = "Q", 8
		}
		for _, prefix := range []byte{0xf2, 0xf3} {
			t.Run(fmt.Sprintf("%s/%x", target.triple, prefix), func(t *testing.T) {
				source, declaration := x86EnqueuePointerProgram(target.arch, prefix,
					"MOVL $0x1234,CX\nPUSH"+word+" CX\n", "POP"+word+" BX\n")
				result := fmt.Sprintf("MOVL AX,ret+%d(FP)\n", 2*size)
				source = strings.Replace(source, result, fmt.Sprintf("MOVL BX,ret+%d(FP)\n", 2*size), 1)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("enqueue lost a live independent numerical cell", api, err)
					}
					missing, _ := x86EnqueuePointerProgram(target.arch, prefix, "", "")
					missing = strings.Replace(missing, result, "", 1)
					ir, err = x86ScalarFPBitViewAPI(t, missing, declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("enqueue invented an unwritten ABI result", api, err)
					}
				}
			})
		}
	}
}
