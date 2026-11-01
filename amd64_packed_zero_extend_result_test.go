package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86PackedZeroExtendResultConsumers(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, native := range []bool{false, true} {
			t.Run(fmt.Sprint(target.triple, "/native=", native), func(t *testing.T) {
				var source, declarations strings.Builder
				count := 0
				for _, ratio := range x86ZeroExtendTestRatios {
					for _, vector := range []bool{false, true} {
						for _, width := range []int{16, 32, 64} {
							if !vector && width != 16 {
								continue
							}
							for masking := 0; masking < 3; masking++ {
								if !vector && masking != 0 {
									continue
								}
								name := fmt.Sprint("Widen", count)
								count++
								bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
								input := "X0"
								if width*ratio.input/ratio.output > 16 {
									input = "Y0"
								}
								offset, load, declaration := 8, "MOVQ value+0(FP),X0", "value uint64"
								if native {
									input, load, declaration = "(DX)", "MOVQ value+0(FP),DX", "value *[32]byte"
									if target.arch == "386" {
										offset, load = 4, "MOVL value+0(FP),DX"
									}
								}
								row := "PMOVZX" + ratio.suffix
								if vector {
									row = "V" + row
								}
								if masking == 2 {
									row += ".Z"
								}
								row += " " + input + ","
								if masking != 0 {
									row += "K1,"
								}
								row += bank + "1"
								fmt.Fprintf(&declarations, "func %s(%s) uint32\n", name, declaration)
								fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nVZEROALL\n%s\nMOVL $1,AX\nKMOVW AX,K1\n%s\nPEXTRD $0,X1,AX\nMOVL AX,ret+%d(FP)\nRET\n", name, offset+4, load, row, offset)
							}
						}
					}
				}
				if count != 60 || count > 64 {
					t.Fatal("incomplete or oversized result matrix", count)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("widening result lacks its numerical consumer", api, err)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, "widen-result-"+api)
					x86ResultInitializationObject(t, llc, target.triple, x86MulDivRoundOptimize(t, ir), "widen-result-"+api+"-O2")
				}
			})
		}
	}
}

func TestX86PackedZeroExtendNativeResultBoundaries(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			name := prefix + "MOVZX" + ratio.suffix
			t.Run(name, func(t *testing.T) {
				body := "MOVQ p+0(FP),DX\n" + name + " (DX),X1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+8(FP)\nRET"
				_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[8]byte) uint32", body)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone result observer acquired native memory", err)
					}
				}
				ins := x86ScalarLaneInstruction(t, name+" -1(DX)(BX*1),X1")
				state := x86ResultState{flags: x86ByteFlagsAll}
				base, _, _ := x86ResultGP(DX, 8, "amd64")
				index, _, _ := x86ResultGP(BX, 8, "amd64")
				state.pointerGP[base], state.gp[index] = true, 0xff
				state.writeVector(1, 64, 0xa5a5000000000000, false)
				before := state.clone()
				if accepted, known := x86ResultPackedZeroExtendStep(ins, &state, nil, "amd64", true); !accepted || !known {
					t.Fatal("paired native read has no conditional numerical bytes")
				}
				want := uint64(0xa5a500000000ffff)
				if prefix == "VP" {
					want = ^uint64(0)
				}
				if state.vectorBytes(1) != want || state.flags != before.flags || state.gp != before.gp || state.pointerGP != before.pointerGP {
					t.Fatal("native widening changed another state domain")
				}
				for _, mutation := range []string{"decoded", "raw", "raw return", "address", "unbound address", "segment", "unknown base", "unknown index", "pointer index"} {
					changed, rejected := ins, before.clone()
					switch mutation {
					case "decoded":
						changed.x86Encoded = true
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "raw return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					case "address":
						changed.x86AddressBits = 32
					case "unbound address":
						changed.x86UnboundAddressOverride = true
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "unknown base":
						rejected.pointerGP[base] = false
					case "unknown index":
						rejected.gp[index] = 0
					case "pointer index":
						// A reaching pointer import revokes numerical bytes.
						// Only the source-wide shape pass carries their union.
						rejected.pointerGP[index], rejected.gp[index] = true, 0
					}
					expected := rejected.clone()
					if accepted, _ := x86ResultPackedZeroExtendStep(changed, &rejected, nil, "amd64", true); accepted || !reflect.DeepEqual(rejected, expected) {
						t.Fatal("unbound origin/address acquired native result bytes", mutation)
					}
				}
			})
		}
	}
}

func TestX86PackedZeroExtendResultTupleAndMaskBoundaries(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, width := range []int{16, 32, 64} {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			ins := x86ScalarLaneInstruction(t, "VPMOVZX"+ratio.suffix+".Z value+0(FP),K1,"+bank+"1")
			for missing := -1; missing < 32; missing++ {
				for _, maskKnown := range []bool{false, true} {
					state := x86ResultState{fp: make([]bool, 32)}
					owned := make([]bool, 32)
					for index := range owned {
						owned[index], state.fp[index] = true, index != missing
					}
					state.masks[1] = maskKnown
					accepted := x86ResultTransfer(ins, &state, owned, 32, "amd64")
					want := maskKnown && (missing < 0 || missing >= width*ratio.input/ratio.output)
					if accepted != want || accepted && state.vectorBytes(1) != ^uint64(0) || len(ins.x86CallerMemory) != 0 {
						t.Fatal("mask/tuple invented source bytes or caller permission", ratio.suffix, width, missing, maskKnown)
					}
				}
			}
		}
	}
}

func TestX86PackedZeroExtendNativeResultsKeepWholeSourceBoundaries(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			name := prefix + "MOVZX" + ratio.suffix
			t.Run(name, func(t *testing.T) {
				load := name + " (DX),X1\n"
				for mutation, body := range map[string]string{
					"pointer index":       name + " (DX)(DX*1),X1\n",
					"lost pointer":        "MOVL $1,DX\n" + load,
					"missing path":        "MOVL $0,BX\nCMPL BX,$0\nJE after\n" + load + "after:\n",
					"unknown store input": load + "MOVL BX,(DX)\n",
					"input write":         load + "MOVQ $1,p+0(FP)\n",
				} {
					source := "TEXT ·Value(SB),4,$0-12\nMOVQ p+0(FP),DX\n" + body + "PEXTRD $0,X1,AX\nMOVL AX,ret+8(FP)\nRET\n"
					goAssemblerOracleOutput(t, "amd64", source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						if _, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[32]byte) uint32", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("widening result borrowed another source contract", mutation, api, err)
						}
					}
				}
				body := "MOVQ p+0(FP),DX\n" + load + "PEXTRD $0,X1,AX\nMOVL AX,ret0+8(FP)\nRET"
				_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[32]byte) uint32", body)
				for _, origin := range []string{"raw TEXT", "source stack", "fixed local"} {
					fn := file.Funcs[0]
					switch origin {
					case "raw TEXT":
						fn.X86RawText = []byte{0xc3}
					case "source stack":
						fn.x86SourceStack = new(x86SourceStackProof)
					case "fixed local":
						fn.x86FixedLocal = new(x86FixedLocalProof)
					}
					ctx := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: "amd64"}
					if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("widening result bypassed original entry boundary", origin, err)
					}
				}
			})
		}
	}
}

func TestX86PackedZeroExtendDeadNativeReads(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, row := range []string{
			"PMOVZX" + ratio.suffix + " (DX),X1",
			"VPMOVZX" + ratio.suffix + " (DX),Z1",
			"VPMOVZX" + ratio.suffix + ".Z (DX),K1,Z1",
		} {
			t.Run(row, func(t *testing.T) {
				source := "TEXT ·Read(SB),4,$0-16\nMOVQ p+0(FP),DX\nMOVQ mask+8(FP),AX\nKMOVQ AX,K1\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Read(p *[32]byte,mask uint64)\n", "amd64", "x86_64-unknown-linux-gnu", "Go")
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if !strings.Contains(text, "load volatile") || strings.Contains(row, ".Z") && !strings.Contains(text, "br i1") {
						t.Fatal("dead widening discarded native reads or masked fault suppression")
					}
				}
			})
		}
	}
}
