package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var x86LegacyScalarNativeStoreRows = []struct {
	op    string
	bytes int
}{{"MOVSS", 4}, {"MOVSD", 8}}

func TestX86LegacyScalarNativeStoreOriginalFixturesRetained(t *testing.T) {
	source, err := os.ReadFile("amd64_legacy_scalar_move_alias_runtime_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"x86LegacyScalarAliasForms":                                "bf44781dcd3cdf3a33b7c01c35e2c6463e140604b3b4216c12e74b17ca31b3ca",
		"x86LegacyScalarAliasAssembly":                             "aab68b371f34605e1c4a221e2bab6388b2a5606c5b7ff636ba501da2e65dec9a",
		"x86LegacyScalarAliasActualGoOracle":                       "ef6fd09f452d6c2a4f7ca471866c373d7e1871a8d776bd6b67d20b4239881633",
		"TestCrossLinuxRuntimeMatrixX86LegacyScalarMoveAliasViews": "dad2ef85bf3fa14661390d430215840d4237ab310255068578150ba4886d66de",
	} {
		body, err := x86SegmentMOVSourceFunction(source, name)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(body)) != want {
			t.Fatal("original six-kernel ASM/Go/C/observations changed", name, err)
		}
	}
}

func x86LegacyScalarNativeStoreState(arch string, width int) x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	state.pointerGP[3], state.callerAddressGP[3] = true, true
	state.gp[1] = uint8(1)<<uint(x86ResultPointerWord(arch)) - 1
	state.writeVector(1, 64, x86CallerVectorByteMask(int64(width)), false)
	state.writeVector(7, 64, 0x55aa55aa55aa55aa, false)
	state.masks[3] = true
	return state
}

func TestX86LegacyScalarNativeStoreEveryByteAndPreservedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LegacyScalarNativeStoreRows {
			ins := x86ScalarLaneInstruction(t, row.op+" X1,-1(BX)(CX*2)")
			for missing := -1; missing < 64; missing++ {
				t.Run(fmt.Sprintf("%s/%s/missing%d", arch, row.op, missing), func(t *testing.T) {
					state := x86LegacyScalarNativeStoreState(arch, row.bytes)
					if missing >= 0 {
						state.writeVector(1, 64, x86CallerVectorByteMask(int64(row.bytes))&^(uint64(1)<<uint(missing)), false)
					}
					if missing%2 == 0 {
						state.flags = 0 // A store cannot manufacture unavailable FLAGS.
					}
					before := state.clone()
					accepted, known := x86ResultLegacyScalarMoveStep(ins, &state, nil, 0, arch, true)
					want := missing < 0 || missing >= row.bytes
					if !known || accepted != want || !reflect.DeepEqual(state, before) {
						t.Fatal("exact scalar store borrowed a source byte or changed aliases/FLAGS/storage", accepted, known, want)
					}
				})
			}
		}
	}
}

func TestX86LegacyScalarNativeStoreAddressAndOriginBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LegacyScalarNativeStoreRows {
			for _, address := range []string{"(BX)", "-1(BX)(CX*1)", "-1(BX)(CX*2)", "-1(BX)(CX*4)", "-1(BX)(CX*8)"} {
				t.Run(arch+"/"+row.op+"/"+address, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" X1,"+address)
					state := x86LegacyScalarNativeStoreState(arch, row.bytes)
					before := state.clone()
					if accepted, known := x86ResultLegacyScalarMoveStep(ins, &state, nil, 0, arch, true); !accepted || !known || !reflect.DeepEqual(state, before) {
						t.Fatal("original ordinary pointer/index store was not consumed exactly", accepted, known)
					}
				})
			}
			registers := []int{0, 7}
			if arch == "amd64" {
				registers = append(registers, 15)
			}
			for _, register := range registers {
				t.Run(fmt.Sprintf("%s/%s/source-X%d", arch, row.op, register), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s X%d,(BX)", row.op, register))
					state := x86LegacyScalarNativeStoreState(arch, row.bytes)
					state.writeVector(register, 64, x86CallerVectorByteMask(int64(row.bytes)), false)
					before := state.clone()
					if accepted, known := x86ResultLegacyScalarMoveStep(ins, &state, nil, 0, arch, true); !accepted || !known || !reflect.DeepEqual(state, before) {
						t.Fatal("legacy source bank changed native store or alias semantics", register, accepted, known)
					}
				})
			}
			for _, mutation := range []string{"standalone", "pointer", "index", "pointer-index", "encoded", "raw", "raw-return", "address", "unbound-address", "segment", "segment-memory", "symbol", "numerical-read", "FP-parameter"} {
				t.Run(arch+"/"+row.op+"/"+mutation, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.op+" X1,-1(BX)(CX*2)")
					state := x86LegacyScalarNativeStoreState(arch, row.bytes)
					paired := true
					switch mutation {
					case "standalone":
						paired = false
					case "pointer":
						state.pointerGP[3] = false
						state.gp[3] = 0xff // NUM is not an incoming pointer.
					case "index":
						state.gp[1] >>= 1
					case "pointer-index":
						state.pointerGP[1], state.gp[1] = true, 0
					case "encoded":
						ins.x86Encoded = true
					case "raw":
						ins.x86SourceRaw = new(x86SourceRawInstruction)
					case "raw-return":
						ins.x86RawNearReturn = new(x86RawNearReturnForm)
					case "address":
						ins.x86AddressBits = 32
					case "unbound-address":
						ins.x86UnboundAddressOverride = true
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "segment-memory":
						ins.Args[1].Mem.Segment = "FS"
					case "symbol":
						ins.Args[1].Mem.Sym = "foreign(SB)"
					case "numerical-read":
						ins.x86NumericalRead = new(x86NumericalReadCertificate)
					case "FP-parameter":
						ins.Args[1] = Operand{Kind: OpFP, FPOffset: 0}
						state.fp = make([]bool, 16)
					}
					before := state.clone()
					if accepted, _ := x86ResultLegacyScalarMoveStep(ins, &state, make([]bool, 16), 16, arch, paired); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("native scalar store acquired an absent source/address/frame role", mutation)
					}
				})
			}
		}
	}
}

func x86LegacyScalarNativeStoreExactIR(t *testing.T, ir string, count int) {
	t.Helper()
	for _, scalar := range []string{"(?:float|i32)", "(?:double|i64)"} {
		pattern := regexp.MustCompile(`(?m)^\s+store volatile ` + scalar + ` [^\n]*, align 1$`)
		if got := len(pattern.FindAllString(ir, -1)); got != count {
			t.Fatal("scalar native store lost its exact width, unaligned access or volatility", scalar, got, count)
		}
	}
}

func TestX86LegacyScalarNativeStoreOriginalThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var declarations strings.Builder
	for _, form := range x86LegacyScalarAliasForms() {
		fmt.Fprintf(&declarations, "func %s(input,output *byte)\n", form.name)
	}
	for _, target := range x86RawReturnTargets {
		for _, wide := range []int{32, 64} {
			t.Run(fmt.Sprintf("%s/alias%d", target.triple, wide), func(t *testing.T) {
				source := x86LegacyScalarAliasAssembly(wide, target.arch)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete original six-kernel typed source rejected", err)
						}
						optimized := x86DwordProductIROptimize(t, ir)
						for _, pipeline := range []struct{ name, ir, backend string }{
							{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
						} {
							t.Run(pipeline.name, func(t *testing.T) {
								x86LegacyScalarNativeStoreExactIR(t, pipeline.ir, 3)
								x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.backend)
							})
						}
					})
				}
			})
		}
	}
}

func TestX86LegacyScalarNativeStorePublicInputsAndFramePermissions(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple, move, word := "x86_64-unknown-linux-gnu", "MOVQ", 8
		if arch == "386" {
			triple, move, word = "i386-unknown-linux-gnu", "MOVL", 4
		}
		for _, row := range x86LegacyScalarNativeStoreRows {
			prefix := fmt.Sprintf("TEXT ·Store(SB),4,$0-%d\n%s out+0(FP),BX\n%s input+%d(FP),AX\nMOVL $1,CX\n", 2*word, move, move, word)
			body := row.op + " (AX),X1\nSTC\n" + row.op + " X1,-1(BX)(CX*2)\nSETCS 16(BX)\nRET\n"
			for _, control := range []struct {
				name, source, declaration string
				valid                     bool
			}{
				{"initialized", prefix + body, "func Store(out,input *byte)", true},
				{"numeric-destination", prefix + body, "func Store(out uintptr,input *byte)", false},
				{"missing-pointer", strings.Replace(prefix, move+" out+0(FP),BX\n", "", 1) + body, "func Store(out,input *byte)", false},
				{"partial-source", prefix + strings.Replace(body, row.op+" (AX),X1", "PINSRW $0,CX,X1", 1), "func Store(out,input *byte)", false},
				{"partial-index", strings.Replace(prefix, "MOVL $1,CX", "MOVW $1,CX", 1) + body, "func Store(out,input *byte)", false},
				{"unknown-FLAGS", prefix + strings.Replace(body, "STC\n", "", 1), "func Store(out,input *byte)", false},
				{"FP-parameter", prefix + strings.Replace(body, "X1,-1(BX)(CX*2)", "X1,out+0(FP)", 1), "func Store(out,input *byte)", false},
			} {
				t.Run(arch+"/"+row.op+"/"+control.name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, arch, triple, control.source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, control.source, control.declaration, arch, triple, api)
						if control.valid {
							if err != nil || ir == "" {
								t.Fatal("actual typed scalar store lost incoming pointer/source/FLAGS", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("scalar native store borrowed missing numerical/FLAGS/frame authority", api, err)
						}
					}
				})
			}
		}
	}
}
