package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ResultPackedStringCompleteRegisterDependenciesAndEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range go127PackedStringCompareSpecs() {
			for _, registers := range []string{"X0,X1", "X1,X0", "X0,X0", "X1,X1", "X7,X6"} {
				t.Run(arch+"/"+row.op+"/"+registers, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" $12,"+registers)
					initial := x86ResultState{flags: x86ByteFlagCF, direction: x86ResultDirectionBackward}
					for index := range initial.xmm {
						initial.xmm[index] = 0xffff
						initial.vectorUpper[index] = 0x123456780000
					}
					initial.gp[0], initial.gp[2] = 0x0f, 0x0f // Only the declared low32 length views.
					initial.canonicalGP[1] = 0xff
					initial.pointerGP[1], initial.callerAddressGP[1], initial.callerAddressOrigin[1] = true, true, 1
					initial.resultAddressGP[1] = x86ResultSlotAddress{start: 8, end: 16, valid: true}
					initial.predicate = x86ResultPredicate{kind: x86ResultNonzeroMaskGP, register: 1, width: 16}
					for _, missing := range []struct {
						role  string
						count int
					}{{"none", 1}, {"source", 16}, {"left", 16}, {"AX", 4}, {"DX", 4}} {
						for byteIndex := 0; byteIndex < missing.count; byteIndex++ {
							state := initial.clone()
							if missing.role == "source" || missing.role == "left" {
								arg := 1
								if missing.role == "left" {
									arg = 2
								}
								index, _ := amd64ParseXReg(ins.Args[arg].Reg)
								state.xmm[index] &^= 1 << uint(byteIndex)
							} else if missing.role == "AX" {
								state.gp[0] &^= 1 << uint(byteIndex)
							} else if missing.role == "DX" {
								state.gp[2] &^= 1 << uint(byteIndex)
							}
							before := state.clone()
							accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
							want := missing.role == "none" || !row.explicit && (missing.role == "AX" || missing.role == "DX")
							if accepted != want {
								t.Fatal("packed-string dependency was omitted or widened", missing.role, byteIndex, accepted, want)
							}
							if !want {
								if !reflect.DeepEqual(before, state) {
									t.Fatal("rejected input mutated output knowledge")
								}
								continue
							}
							if state.flags != x86ByteFlagsAll || state.direction != before.direction || state.predicate != (x86ResultPredicate{}) {
								t.Fatal("status effects borrowed DF or retained a stale predicate")
							}
							if row.mask {
								wantUpper := before.vectorUpper[0]
								if row.vector {
									wantUpper = ^uint64(0xffff)
								}
								if state.xmm[0] != 0xffff || state.vectorUpper[0] != wantUpper || state.gp != before.gp || state.pointerGP != before.pointerGP {
									t.Fatal("X0 mask result lost its exact legacy/VEX alias footprint")
								}
							} else if state.gp[1] != 0xff || state.canonicalGP[1] != 0 || state.pointerGP[1] || state.callerAddressGP[1] || state.callerAddressOrigin[1] != 0 || state.resultAddressGP[1].valid || state.xmm != before.xmm || state.vectorUpper != before.vectorUpper {
								t.Fatal("index output retained address/canonical authority or lost zero extension")
							}
						}
					}
				})
			}
		}
	}
}

func TestX86PackedStringPlainIndexNoProbeRequiresWholeSource(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"PCMPESTRI", "PCMPISTRI", "VPCMPESTRI", "VPCMPISTRI"} {
			for _, known := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/known=%t", arch, op, known), func(t *testing.T) {
					declaration := "func view() uint32\n"
					body := op + " $12,X0,X1\nMOVL CX,ret+RESULT(FP)"
					if known {
						body = "PXOR X0,X0\nPXOR X1,X1\nMOVL $3,AX\nMOVL $7,DX\n" + body
					}
					// No extra GP/X move or BSF probe can hide a missed cost gate.
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, known)
				})
			}
		}
	}
}

func TestX86PackedStringWholeFamilyThreeAPIsStatusAndMask(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range go127PackedStringCompareSpecs() {
			for _, missing := range []string{"none", "source", "left", "AX", "DX"} {
				t.Run(arch+"/"+row.op+"/"+missing, func(t *testing.T) {
					body := "PXOR X0,X0\nPXOR X1,X1\nMOVL $3,AX\nMOVL $7,DX\n"
					if missing == "source" {
						body = strings.Replace(body, "PXOR X0,X0\n", "", 1)
					}
					if missing == "left" {
						body = strings.Replace(body, "PXOR X1,X1\n", "", 1)
					}
					if missing == "AX" {
						body = strings.Replace(body, "MOVL $3,AX\n", "", 1)
					}
					if missing == "DX" {
						body = strings.Replace(body, "MOVL $7,DX\n", "", 1)
					}
					body += row.op + " $12,X0,X1\n"
					if row.mask {
						body += "MOVL X0,AX\n"
					} else {
						body += "MOVL CX,AX\n"
					}
					// A complete six-status result must be preserved by DF setters.
					body += "SETCS BL\nMOVBLZX BL,BX\nADDL BX,AX\nMOVL AX,ret+RESULT(FP)"
					declaration := "func view() uint32\n"
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, missing == "none" || !row.explicit && (missing == "AX" || missing == "DX"))
				})
			}
		}
	}
}

func TestX86PackedStringPublicMemoryDoesNotAcquirePointeeBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range go127PackedStringCompareSpecs() {
			state := x86ResultState{}
			state.xmm[1], state.gp[0], state.gp[2], state.pointerGP[7] = 0xffff, 0x0f, 0x0f, true
			ins := x86ScalarLaneInstruction(t, row.op+" $12,(DI),X1")
			if x86ResultTransfer(ins, &state, nil, 0, arch) {
				t.Fatal("descriptor gave an initialized pointer its full m128 input")
			}
		}
	}
}

func TestX86PackedStringPairedNativeReadAndDeadOutputStayFullWidth(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range go127PackedStringCompareSpecs() {
			for _, dead := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/dead=%t", arch, row.op, dead), func(t *testing.T) {
					declaration := "func view(p *byte) uint32\n"
					body := move + " p+0(FP),DI\nPXOR X1,X1\nMOVL $0,AX\nMOVL $0,DX\n" + row.op + " $12,1(DI),X1\n"
					if dead {
						body += "MOVL $7,AX\n"
					} else if row.mask {
						body += "MOVL X0,AX\n"
					} else {
						body += "MOVL CX,AX\n"
					}
					body += "MOVL AX,ret+RESULT(FP)"
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					for _, query := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
						if err := query(file.Funcs[0], sigs["view"], arch); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("declaration alone supplied native pointee bytes", err)
						}
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
							if err != nil || strings.Count(ir, "load volatile <16 x i8>") != 1 || !strings.Contains(ir, ", align 1") || strings.Contains(ir, "dereferenceable") {
								t.Fatal("paired full unaligned m128 read was erased/shrunk or lent bounds", err)
							}
							optimized := x86UndefinedTrapOptimizedIR(t, ir)
							if strings.Count(optimized, "load volatile <16 x i8>") != 1 {
								t.Fatal("O2 discarded the original full read, including zero-length/dead-output cases")
							}
						})
					}
				})
			}
		}
	}
}

func TestX86PackedStringStrictWidthsImmediateAndRawResultRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range go127PackedStringCompareSpecs() {
			for _, operand := range []string{"$256,X0,X1", "$-129,X0,X1", "$0.0,X0,X1", "$1,Y0,X1", "$1,X0,Y1", "$1,M0,X1", "$1,X0,X16", "$1,X0,(DI)", "$1,X0,X1,X2"} {
				ins := x86ScalarLaneInstruction(t, row.op+" "+operand)
				state := x86ResultState{}
				if accepted, known := x86ResultPackedStringStep(ins, &state, nil, arch); accepted || !known {
					t.Fatal("malformed vector-width/immediate/result role passed", arch, row.op, operand)
				}
			}
			for _, tail := range []string{"", ".Z"} {
				for _, immediate := range []int{-128, -1, 0, 127, 255} {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s%s $%d,X0,X1", row.op, tail, immediate))
					state := x86ResultState{}
					state.xmm[0], state.xmm[1], state.gp[0], state.gp[2] = 0xffff, 0xffff, 0xf, 0xf
					want := tail == "" && (row.vector || immediate >= 0)
					if accepted, known := x86ResultPackedStringStep(ins, &state, nil, arch); !known || accepted != want {
						t.Fatal("complete Yu8/Yi8 distinction changed", arch, row.op, immediate, tail)
					}
				}
			}
			for _, mutate := range []func(*Instr){
				func(ins *Instr) { ins.x86Encoded = true },
				func(ins *Instr) { ins.x86SourceRaw = &x86SourceRawInstruction{} },
				func(ins *Instr) { ins.x86AddressBits = 32 },
				func(ins *Instr) { ins.x86UnboundAddressOverride = true },
				func(ins *Instr) { ins.x86SegmentPrefix = 1 },
			} {
				ins := x86ScalarLaneInstruction(t, row.op+" $12,X0,X1")
				mutate(&ins)
				state := x86ResultState{}
				state.xmm[0], state.xmm[1], state.gp[0], state.gp[2] = 0xffff, 0xffff, 0xf, 0xf
				before := state.clone()
				if accepted, known := x86ResultPackedStringStepWithRead(ins, &state, nil, arch, true); accepted || !known || !reflect.DeepEqual(before, state) {
					t.Fatal("named transfer lent an encoded/source-entry role")
				}
			}
		}
	}
}

func TestX86PackedStringFullFPAndLoweredMemoryBytesRemainIndependent(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range go127PackedStringCompareSpecs() {
			for _, extent := range []int{0, 1, 8, 15, 16} {
				state := x86ResultState{fp: make([]bool, 16)}
				owned := make([]bool, 16)
				for index := range owned {
					owned[index] = true
					state.fp[index] = index < extent
				}
				state.xmm[1], state.gp[0], state.gp[2] = 0xffff, 0xf, 0xf
				ins := x86ScalarLaneInstruction(t, row.op+" $12,input+0(FP),X1")
				if accepted, known := x86ResultPackedStringStep(ins, &state, owned, arch); !known || accepted != (extent == 16) {
					t.Fatal("m128 became a shortened independent FP read", arch, row.op, extent)
				}
			}
			for _, pointer := range []bool{false, true} {
				state := x86ResultState{}
				state.xmm[1], state.gp[0], state.gp[2], state.pointerGP[7] = 0xffff, 0xf, 0xf, pointer
				ins := x86ScalarLaneInstruction(t, row.op+" $12,(DI),X1")
				before := state.clone()
				if accepted, known := x86ResultPackedStringStepWithRead(ins, &state, nil, arch, true); !known || accepted != pointer {
					t.Fatal("private paired read fabricated an unknown address", arch, row.op, pointer)
				}
				if !pointer && !reflect.DeepEqual(before, state) {
					t.Fatal("failed native address attempt mutated knowledge")
				}
			}
			for _, memory := range []string{"(SP)", "(BP)", "(DI)(SI*1)", "global(SB)"} {
				state := x86ResultState{}
				state.xmm[1], state.gp[0], state.gp[2], state.pointerGP[7] = 0xffff, 0xf, 0xf, true
				ins := x86ScalarLaneInstruction(t, row.op+" $12,"+memory+",X1")
				if accepted, known := x86ResultPackedStringStepWithRead(ins, &state, nil, arch, true); accepted || !known {
					t.Fatal("private memory continuation lent stack/static/segment/uninitialized-index authority", arch, row.op, memory)
				}
			}
			state := x86ResultState{}
			state.xmm[1], state.gp[0], state.gp[2], state.pointerGP[7] = 0xffff, 0xf, 0xf, true
			segmented := x86ScalarLaneInstruction(t, row.op+" $12,(DI),X1")
			segmented.Args[1].Mem.Segment = "FS"
			if accepted, known := x86ResultPackedStringStepWithRead(segmented, &state, nil, arch, true); accepted || !known {
				t.Fatal("paired ordinary read borrowed a segment role")
			}
		}
	}
}
