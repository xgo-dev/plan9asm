package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent enumeration of Go's scalar memory insertion families. Their
// complete encoder rows/attributes have separate original-Go table oracles.
var x86ScalarLaneNativeOracle = []struct {
	op, extract string
	width       int
}{
	{"PINSRB", "PEXTRB $255", 1},
	{"PINSRW", "PEXTRW $255", 2},
	{"PINSRD", "PEXTRD $255", 4},
	{"PINSRQ", "PEXTRQ $255", 8},
	{"VPINSRB", "VPEXTRB $255", 1},
	{"VPINSRW", "VPEXTRW $255", 2},
	{"VPINSRD", "VPEXTRD $255", 4},
	{"VPINSRQ", "VPEXTRQ $255", 8},
	{"INSERTPS", "PEXTRD $1", 4},
	{"VINSERTPS", "VPEXTRD $1", 4},
}

func x86ScalarLaneNativeFixture(name, arch, op, extract, address string, high bool) (string, string) {
	word, move, typ := 8, "MOVQ", "uint64"
	if arch == "386" {
		word, move, typ = 4, "MOVL", "uint32"
	}
	base, destination := "X0", "X0"
	if strings.HasPrefix(op, "V") {
		destination = "X1"
		if high {
			base, destination = "X16", "X17"
		}
	}
	immediate := 255
	if strings.HasSuffix(op, "PS") {
		immediate = 0xd0 // Memory ignores source selector; insert into lane one.
	}
	row := fmt.Sprintf("%s $%d,%s,%s", op, immediate, address, base)
	if strings.HasPrefix(op, "V") {
		row += "," + destination
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DX\nMOVL $1,BX\n%s\n%s,%s,AX\n%s AX,ret+%d(FP)\nRET\n",
		name, 2*word, move, row, extract, destination, move, word)
	return source, fmt.Sprintf("func %s(p *[8]byte) %s\n", name, typ)
}

func TestX86ScalarLaneNativeResultsThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86ScalarLaneNativeOracle {
				if target.arch == "386" && (row.width == 8 || strings.HasPrefix(row.op, "V")) {
					asm, _ := x86ScalarLaneNativeFixture("Rejected", target.arch, row.op, row.extract, "(DX)", false)
					goAssemblerOracleOutput(t, target.arch, asm, "", false)
					continue // Actual Go rejection, not a skipped supported target.
				}
				for _, address := range []string{"(DX)", "-1(DX)(BX*1)"} {
					for _, high := range []bool{false, true} {
						if high && !strings.HasPrefix(row.op, "V") {
							continue
						}
						asm, decl := x86ScalarLaneNativeFixture(fmt.Sprintf("F%d", count), target.arch, row.op, row.extract, address, high)
						source.WriteString(asm)
						declarations.WriteString(decl)
						count++
					}
				}
			}
			want := 30
			if target.arch == "386" {
				want = 8
			}
			if count != want {
				t.Fatal("incomplete native insertion matrix", count, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("native scalar-lane read lost its conditional result:", err)
					}
					if strings.Count(ir, "load volatile i") != count {
						t.Fatal("missing paired native scalar reads")
					}
					compileLLVMToObject(t, llc, target.triple, "scalar-lane-native.ll", "scalar-lane-native.o", ir)
				})
			}
		})
	}
}

func TestX86ScalarLaneNativeResultsKeepStandaloneAndUnknownBoundaries(t *testing.T) {
	for _, row := range x86ScalarLaneNativeOracle {
		t.Run(row.op, func(t *testing.T) {
			source, decl := x86ScalarLaneNativeFixture("Value", "amd64", row.op, row.extract, "(DX)", false)
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", strings.TrimSpace(decl),
				strings.ReplaceAll(strings.SplitN(source, "\n", 2)[1], "ret+8(FP)", "ret0+8(FP)"))
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("standalone observer acquired native memory", err)
				}
			}
			for name, address := range map[string]string{
				"unknown base": "(DI)", "unknown index": "(DX)(SI*1)",
				"pointer index": "(DX)(DX*1)", "virtual frame": "(SP)",
				"unbound symbol": "·external(SB)",
			} {
				t.Run(name, func(t *testing.T) {
					bad, declaration := x86ScalarLaneNativeFixture("Value", "amd64", row.op, row.extract, address, false)
					goAssemblerOracleOutput(t, "amd64", bad, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						if _, err := x86ScalarFPBitViewAPI(t, bad, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unknown address acquired result bytes", api, err)
						}
					}
				})
			}
		})
	}
}

func TestX86ScalarLaneNativeResultBytesAndOrigins(t *testing.T) {
	for _, row := range x86ScalarLaneNativeOracle {
		t.Run(row.op, func(t *testing.T) {
			source, _ := x86ScalarLaneNativeFixture("Value", "amd64", row.op, row.extract, "-1(DX)(BX*1)", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[3]
			state := x86ResultState{flags: x86ByteFlagsAll}
			base, _, _ := x86ResultGP(DX, 8, "amd64")
			index, _, _ := x86ResultGP(BX, 8, "amd64")
			state.pointerGP[base], state.gp[index] = true, 0xff
			state.writeVector(0, 64, 0x0123456789ab0080, false)
			state.writeVector(1, 64, 0xfedcba9876540000, false)
			before := state.clone()
			ok, known := x86ResultScalarLaneStepWithRead(ins, &state, nil, 0, "amd64", true)
			destination, offset := 0, 16-row.width
			if strings.HasSuffix(row.op, "PS") {
				offset = 4
			}
			lane := ((uint64(1) << uint(row.width)) - 1) << uint(offset)
			want := uint64(0x80) | lane
			if strings.HasPrefix(row.op, "V") {
				destination = 1
				want |= ^uint64(0xffff)
			} else {
				want |= uint64(0x0123456789ab0000)
			}
			if !ok || !known || state.vectorBytes(destination) != want || state.flags != before.flags ||
				state.gp != before.gp || state.pointerGP != before.pointerGP {
				t.Fatalf("native insertion changed unrelated defined bytes: accepted=%t known=%t got=%x want=%x", ok, known, state.vectorBytes(destination), want)
			}
			for _, mutation := range []string{"decoded", "raw", "raw return", "address", "unbound address", "segment"} {
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
				}
				if accepted, _ := x86ResultScalarLaneStepWithRead(changed, &rejected, nil, 0, "amd64", true); accepted || !reflect.DeepEqual(rejected, before) {
					t.Fatal("unbound instruction origin acquired native result bytes", mutation)
				}
			}
		})
	}
}

func TestX86ScalarLaneNativeResultsKeepWholeSourceBoundaries(t *testing.T) {
	for _, row := range x86ScalarLaneNativeOracle {
		t.Run(row.op, func(t *testing.T) {
			source, decl := x86ScalarLaneNativeFixture("Value", "amd64", row.op, row.extract, "(DX)", false)
			destination := "X0"
			if strings.HasPrefix(row.op, "V") {
				destination = "X1"
			}
			extract := row.extract + "," + destination + ",AX"
			missing := strings.Replace(source, row.op+" $", "CMPL BX,$0\nJE after\n"+row.op+" $", 1)
			missing = strings.Replace(missing, extract, "after:\n"+extract, 1)
			for name, bad := range map[string]string{
				"unknown lane":         strings.Replace(source, extract, "PEXTRD $0,"+destination+",AX", 1),
				"lost pointer":         strings.Replace(source, row.op+" $", "MOVL $1,DX\n"+row.op+" $", 1),
				"missing path":         missing,
				"unknown native store": strings.Replace(source, extract, row.extract+","+destination+",(DI)\n"+extract, 1),
				"incoming write":       strings.Replace(source, extract, "MOVQ $42,p+0(FP)\n"+extract, 1),
			} {
				t.Run(name, func(t *testing.T) {
					goAssemblerOracleOutput(t, "amd64", bad, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						if _, err := x86ScalarFPBitViewAPI(t, bad, decl, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("native insertion widened another source contract", api, err)
						}
					}
				})
			}
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", strings.TrimSpace(decl),
				strings.ReplaceAll(strings.SplitN(source, "\n", 2)[1], "ret+8(FP)", "ret0+8(FP)"))
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
					t.Fatal("native insertion bypassed original entry boundary", origin, err)
				}
			}
		})
	}
}
