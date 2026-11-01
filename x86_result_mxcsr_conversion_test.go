package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86MXCSRFullMemoryWidthAndOperandGrammar(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" value+0(FP)")
				width, write, known := X86FPAccessBytes(ins, 0, arch)
				if !known || width != 4 || write != strings.Contains(op, "STMXCSR") {
					t.Fatal("complete MXCSR row lost its exact m32 read/write role", width, write, known)
				}
				for _, row := range []string{op + ".Z value+0(FP)", op + " value+0(FP),X0", op + " X0", op + " $7"} {
					bad := x86ScalarLaneInstruction(t, row)
					if width, _, known := X86FPAccessBytes(bad, 0, arch); known || width != 0 {
						t.Fatal("invalid MXCSR source acquired a memory width", row, width)
					}
				}
			})
		}
	}
}

func TestX86SignedIntegerFloatResultPreservesSparseMergeBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
			if arch == "386" && strings.HasPrefix(op, "CVTSQ") {
				continue
			}
			registerRows := []string{"AX,X0", "AX,X1"}
			if strings.HasPrefix(op, "V") {
				registerRows = []string{"AX,X0,X1", "AX,X1,X1", "CX,X7,X6"}
				if arch == "amd64" {
					registerRows = append(registerRows, "R15,X31,X30", "R15,X31,X31")
				}
			} else if arch == "amd64" {
				registerRows = append(registerRows, "R15,X15")
			} else {
				registerRows = append(registerRows, "CX,X7")
			}
			for _, registers := range registerRows {
				t.Run(arch+"/"+op+"/"+registers, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, op+" "+registers)
					form, known, err := x86SignedIntegerFloatProperties(ins, arch)
					if !known || err != nil {
						t.Fatal(err)
					}
					for missing := -1; missing < form.sourceBits/8; missing++ {
						state := x86ResultState{flags: x86ByteFlagCF, direction: x86ResultDirectionBackward}
						source, _, _ := x86ResultGP(ins.Args[0].Reg, int64(form.sourceBits/8), arch)
						state.gp[source] = 0xff
						state.xmm[0], state.xmm[1] = 0xa531, 0x71c2
						state.vectorUpper[1] = 0x123456780000
						state.callerAddressGP[7], state.callerAddressOrigin[7] = true, 1
						if missing >= 0 {
							state.gp[source] &^= 1 << uint(missing)
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
						if accepted != (missing < 0) {
							t.Fatal("signed conversion ignored an input byte or required unwritten merge bytes", missing, accepted)
						}
						if !accepted {
							if !reflect.DeepEqual(before, state) {
								t.Fatal("rejected signed input mutated numerical state")
							}
							continue
						}
						upper, _ := amd64ParseXReg(ins.Args[form.upper].Reg)
						destination, _ := amd64ParseXReg(ins.Args[form.destination].Reg)
						low := x86CallerVectorByteMask(int64(form.spec.resultBits / 8))
						want := low | before.vectorBytes(upper)&(0xffff&^low)
						if form.spec.legacy {
							want |= before.vectorUpper[destination]
						} else {
							want |= ^uint64(0xffff)
						}
						if state.vectorBytes(destination) != want || state.gp != before.gp || state.pointerGP != before.pointerGP ||
							state.flags != before.flags || state.direction != before.direction {
							t.Fatal("legacy/VEX merge, alias or nonvector state footprint changed", state.vectorBytes(destination), want)
						}
						if after := x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch); after != before.callerAddressGP {
							t.Fatal("signed conversion invented a GP overwrite")
						}
					}
				})
			}
		}
	}
}

func TestX86SignedIntegerFloatUnknownUpperResultThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"CVTSL2SS", "VCVTSI2SSL", "VCVTSI2SSQ"} {
			for _, known := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/upperKnown=%t", arch, op, known), func(t *testing.T) {
					declaration := "func view(input int32) uint64\n"
					args, destination := "AX,X0", "X0"
					if strings.HasPrefix(op, "V") {
						args, destination = "AX,X0,X1", "X1"
					}
					body := "MOVL input+0(FP),AX\n"
					if known {
						body += "PXOR X0,X0\n"
					}
					body += op + " " + args + "\nMOVQ " + destination + ",ret+RESULT(FP)"
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, known)
				})
			}
		}
	}
}

func TestX86SignedIntegerFloatPlainMXCSRReturnRequiresWholeSource(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
			if arch == "386" && strings.HasPrefix(op, "CVTSQ") {
				continue
			}
			for _, known := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/inputKnown=%t", arch, op, known), func(t *testing.T) {
					args := "AX,X0"
					if strings.HasPrefix(op, "V") {
						args += ",X1"
					}
					body := ""
					if known {
						move := "MOVL"
						if arch == "amd64" && strings.Contains(op, "Q") {
							move = "MOVQ"
						}
						body = move + " $7,AX\n"
					}
					// Conversion's observable MXCSR result has no extra GP/X move
					// that could accidentally activate the cached source proof.
					body += op + " " + args + "\nSTMXCSR ret+RESULT(FP)"
					declaration := "func view() uint32\n"
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, known)
				})
			}
		}
	}
}

func TestX86MXCSRPlainAUTOReturnNeedsReachingBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, load := range []string{"LDMXCSR", "VLDMXCSR"} {
			for _, store := range []string{"STMXCSR", "VSTMXCSR"} {
				for _, known := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/known=%t", arch, load, store, known), func(t *testing.T) {
						body := ""
						if known {
							body = "MOVL $0x1f80,saved-4(SP)\n"
						}
						body += load + " saved-4(SP)\n" + store + " ret+RESULT(FP)"
						declaration := "func view() uint32\n"
						source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
						source = strings.Replace(source, ",$0-", ",$8-", 1)
						x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, known)
					})
				}
			}
		}
	}
}

func TestX86SignedIntegerFloatPairedNativeReadRetainsExactDeadWidth(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
			if arch == "386" && strings.HasPrefix(op, "CVTSQ") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				args := "1(DI),X0"
				if strings.HasPrefix(op, "V") {
					args += ",X1"
				}
				declaration := "func view(p *byte) uint32\n"
				// Even dead scalar outputs retain source faults and MXCSR effects.
				body := move + " p+0(FP),DI\n" + op + " " + args + "\nMOVL $7,AX\nMOVL AX,ret+RESULT(FP)"
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				form, _, _ := x86SignedIntegerFloatProperties(x86ScalarLaneInstruction(t, op+" "+args), arch)
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
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sigs["view"], arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone result query borrowed the paired read's memory bytes", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, arch, triple, api)
						load := fmt.Sprintf("load volatile i%d", form.sourceBits)
						if err != nil || strings.Count(ir, load) != 1 || strings.Contains(ir, "dereferenceable") {
							t.Fatal("complete paired signed source read lost its native width", err)
						}
						if optimized := x86UndefinedTrapOptimizedIR(t, ir); strings.Count(optimized, load) != 1 {
							t.Fatal("O2 erased a dead signed source read and its possible fault")
						}
					})
				}
			})
		}
	}
}

func TestX86MXCSRAUTOExtentKeepsCompleteSourceAndBounds(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"} {
			for _, offset := range []int{-12, -8, -4, -3, 0} {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, op, offset), func(t *testing.T) {
					source := fmt.Sprintf("TEXT value(SB),4,$8-0\n%s saved%+d(SP)\nRET\n", op, offset)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					extent, err := x86ResultAUTOExtent(file.Funcs[0], arch)
					if offset == -8 || offset == -4 {
						if err != nil || extent != 8 {
							t.Fatal("actual bounded MXCSR AUTO width remains unknown", extent, err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || extent != 0 {
						t.Fatal("MXCSR native extent crossed the original AUTO frame", extent, err)
					}
				})
			}
		}
	}
}

func TestX86SignedIntegerFloatOriginalFPFixtureWholeThreeAPIs(t *testing.T) {
	declarations, source, _ := x86SignedIntegerFloatFPFixture(t)
	pkg := mustGoPackage(t, "oracle", declarations)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 8 {
		t.Fatal("complete original signed-conversion fixture changed", err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || strings.Count(ir, "define ") != 8 {
				t.Fatal("unchanged complete original FP/MXCSR fixture rejected", err)
			}
		})
	}
}
