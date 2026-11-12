package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86PureGPUnknownCase struct {
	body     string
	width    int64
	flags    uint8
	zeroFrom int64
}

// Independent closed family inventory: no production opcode/spec iteration.
func x86PureGPUnknownCases(arch string) []x86PureGPUnknownCase {
	var cases []x86PureGPUnknownCase
	add := func(body string, width int64, flags uint8) {
		cases = append(cases, x86PureGPUnknownCase{body: body, width: width, flags: flags})
	}
	for _, width := range []struct {
		suffix string
		bytes  int64
	}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
		if arch == "386" && width.bytes == 8 {
			continue
		}
		for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR", "INC", "DEC", "NEG", "NOT", "BTC", "BTR", "BTS"} {
			if width.bytes == 1 && strings.HasPrefix(stem, "BT") {
				continue
			}
			flags := uint8(x86ByteFlagsAll)
			if stem == "INC" || stem == "DEC" {
				flags &^= x86ByteFlagCF
			}
			if stem == "NOT" {
				flags = 0
			}
			if strings.HasPrefix(stem, "BT") {
				flags &^= x86ByteFlagZF
			}
			if stem == "INC" || stem == "DEC" || stem == "NEG" || stem == "NOT" {
				add(stem+width.suffix+" DX", width.bytes, flags)
			} else {
				for _, source := range []string{"BX", "$7"} {
					add(stem+width.suffix+" "+source+",DX", width.bytes, flags)
				}
			}
		}
		for _, stem := range []string{"RCL", "RCR", "ROL", "ROR", "SHL", "SHR", "SAR"} {
			flags := uint8(x86ByteFlagsAll)
			if strings.HasPrefix(stem, "R") {
				flags = x86ByteFlagCF | x86ByteFlagOF
			}
			for _, count := range []string{"$1", "CX"} {
				add(stem+width.suffix+" "+count+",DX", width.bytes, flags)
			}
		}
		if width.bytes == 1 {
			continue
		}
		for _, stem := range []string{"SHL", "SHR"} {
			add(stem+width.suffix+" $1,BX,DX", width.bytes, x86ByteFlagsAll)
			if width.bytes > 2 {
				add(stem+width.suffix+" CX,BX,DX", width.bytes, x86ByteFlagsAll)
			}
		}
		for _, operands := range []string{"BX,DX", "$7,DX"} {
			add("IMUL"+width.suffix+" "+operands, width.bytes, x86ByteFlagsAll)
		}
		add("IMUL3"+width.suffix+" $7,BX,DX", width.bytes, x86ByteFlagsAll)
		for _, condition := range []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"} {
			add("CMOV"+width.suffix+condition+" BX,DX", width.bytes, 0)
		}
	}
	for _, suffix := range []string{"L", "Q"} {
		width := int64(4)
		if suffix == "Q" && arch == "amd64" {
			width = 8
		}
		for _, stem := range []string{"SARX", "SHLX", "SHRX"} {
			add(stem+suffix+" CX,BX,DX", width, 0)
		}
		add("RORX"+suffix+" $1,BX,DX", width, 0)
	}
	for _, extension := range []struct {
		op           string
		source, dest int64
		zero         bool
		mode64       bool
	}{
		{"MOVBWSX", 1, 2, false, false}, {"MOVBWZX", 1, 2, true, false},
		{"MOVBLSX", 1, 4, false, false}, {"MOVBLZX", 1, 4, true, false},
		{"MOVBQSX", 1, 8, false, true}, {"MOVBQZX", 1, 8, true, true},
		{"MOVWLSX", 2, 4, false, false}, {"MOVWLZX", 2, 4, true, false},
		{"MOVWQSX", 2, 8, false, true}, {"MOVWQZX", 2, 8, true, true},
		{"MOVLQSX", 4, 8, false, true}, {"MOVLQZX", 4, 8, true, false},
		{"MOVSWW", 2, 2, false, false}, {"MOVZWW", 2, 2, true, false},
	} {
		if arch == "386" && extension.mode64 {
			continue
		}
		if arch == "386" && extension.op == "MOVLQZX" {
			extension.dest = 4
		}
		add(extension.op+" BX,DX", extension.dest, 0)
		if extension.zero {
			cases[len(cases)-1].zeroFrom = extension.source
		}
	}
	return cases
}

func x86PureGPUnknownInstruction(t *testing.T, body string) Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestX86LoweredPureGPUnknownCompleteFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86PureGPUnknownCases(arch) {
			t.Run(arch+"/"+row.body, func(t *testing.T) {
				ins := x86PureGPUnknownInstruction(t, row.body)
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.gp[0] = 0xff
				before := state.clone()
				strict := state.clone()
				if x86ScalarFPResultTransfer(ins, &strict, nil, 0, arch) {
					t.Fatal("strict transfer unexpectedly accepts undefined input")
				}
				if !x86LoweredPureGPUnknownTransfer(ins, &state, arch) {
					t.Fatal("pure GP unknown value prevented an independent result")
				}
				want := uint8(0)
				if row.width == 4 {
					want = 0xf0
				}
				if row.zeroFrom > 0 {
					for b := row.zeroFrom; b < row.width; b++ {
						want |= 1 << uint(b)
					}
				}
				before.gp[2], before.flags = want, x86ByteFlagsAll&^row.flags
				if !reflect.DeepEqual(state, before) {
					t.Fatalf("availability differs: got GP=%x flags=%x, want GP=%x flags=%x", state.gp, state.flags, before.gp, before.flags)
				}
			})
		}
	}
}

func x86PureGPUnknownTransferForTest(ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
	next := state.clone()
	if x86ScalarFPResultTransfer(ins, &next, owned, offset, arch) {
		*state = next
		return true
	}
	return x86LoweredPureGPUnknownTransfer(ins, state, arch)
}

func TestX86LoweredPureGPUnknownObservableBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for name, tail := range map[string]string{
			"dead":               "MOVL $37,AX\nMOVL AX,ret0+0(FP)\nRET",
			"result":             "MOVL DX,ret0+0(FP)\nRET",
			"branch":             "JE other\nMOVL $1,AX\nJMP done\nother:\nMOVL $2,AX\ndone:\nMOVL AX,ret0+0(FP)\nRET",
			"address":            "MOVL (DX),AX\nMOVL AX,ret0+0(FP)\nRET",
			"store":              "MOVL DX,(AX)\nMOVL $37,ret0+0(FP)\nRET",
			"scalar SIMD result": "MOVL DX,X0\nMOVSS X0,ret0+0(FP)\nRET",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint32", "ADDL $64,DX\n"+tail)
				check := func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
					return x86PureGPUnknownTransferForTest(ins, state, owned, offset, arch)
				}
				err := checkX86ABI0ResultInitializationAtSource(file.Funcs[0], sig, arch, check, true)
				if name == "dead" {
					if err != nil {
						t.Fatal(err)
					}
				} else if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("observable undefined input accepted: %v", err)
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("public checker changed: %v", err)
				}
			})
		}
	}
}

func TestX86LoweredPureGPUnknownRejectsOtherEffects(t *testing.T) {
	for _, body := range []string{"DIVL BX", "IDIVL BX", "IMULL BX", "MULL BX", "MOVL BX,DX", "ADDL (BX),DX", "ADDL x+0(FP),DX", "ADDL BX,(DX)", "ADDL $1,SP", "ADDL $1,BP", "ADDSS X0,X1", "PAND X0,X1", "CALL ·other(SB)", "ADDL $MISSING,DX", "ADDL $1.0,DX", "SHLW CX,BX,DX"} {
		t.Run(body, func(t *testing.T) {
			state := x86ResultState{}
			before := state.clone()
			if x86LoweredPureGPUnknownTransfer(x86PureGPUnknownInstruction(t, body), &state, "amd64") {
				t.Fatal("non-pure/unsupported effect acquired fallback")
			}
			if !reflect.DeepEqual(state, before) {
				t.Fatal("rejected effect mutated availability")
			}
		})
	}
}

func TestX86LoweredPureGPUnknownPartialBytesFlagsAndPointers(t *testing.T) {
	for _, row := range []struct {
		body                     string
		bx, dx, cx               uint8
		flags, wantDX, wantFlags uint8
	}{
		{"ADDB BL,DH", 0xfe, 0xff, 0xff, x86ByteFlagsAll, 0xfd, 0},
		{"ADDW BX,DX", 0xfd, 0xff, 0xff, x86ByteFlagsAll, 0xfd, 0},
		{"ADDL BX,DX", 0xfe, 0xff, 0xff, x86ByteFlagsAll, 0xf0, 0},
		{"ADDQ BX,DX", 0x7f, 0xff, 0xff, x86ByteFlagsAll, 0x7f, 0},
		{"INCW DX", 0xff, 0xfd, 0xff, x86ByteFlagsAll, 0xfd, x86ByteFlagCF},
		{"NOTW DX", 0xff, 0xfd, 0xff, x86ByteFlagsAll, 0xfd, x86ByteFlagsAll},
		{"SHLL $0,DX", 0xff, 0xfd, 0xff, x86ByteFlagsAll, 0xfd, x86ByteFlagsAll},
		{"BTSL BX,DX", 0xfe, 0xff, 0xff, x86ByteFlagsAll, 0xf0, x86ByteFlagZF},
		{"SHLL CX,DX", 0xff, 0xff, 0xfe, x86ByteFlagsAll, 0xf0, 0},
		{"ROLL CX,DX", 0xff, 0xff, 0xfe, x86ByteFlagsAll, 0xf0, x86ByteFlagsAll &^ (x86ByteFlagCF | x86ByteFlagOF)},
		{"SHLXL CX,BX,DX", 0xff, 0xff, 0xfe, x86ByteFlagsAll, 0xf0, x86ByteFlagsAll},
		{"ADCL $7,DX", 0xff, 0xff, 0xff, x86ByteFlagsAll &^ x86ByteFlagCF, 0xf0, 0},
		{"CMOVLEQ BX,DX", 0xff, 0xff, 0xff, x86ByteFlagsAll &^ x86ByteFlagZF, 0xf0, x86ByteFlagsAll &^ x86ByteFlagZF},
		{"MOVBLZX BH,DX", 0xfd, 0xff, 0xff, x86ByteFlagsAll, 0xfe, x86ByteFlagsAll},
		{"MOVWQZX BX,DX", 0xfd, 0xff, 0xff, x86ByteFlagsAll, 0xfd, x86ByteFlagsAll},
		{"MOVWQSX BX,DX", 0xfd, 0xff, 0xff, x86ByteFlagsAll, 0x01, x86ByteFlagsAll},
		{"MOVWQSX BX,DX", 0xfe, 0xff, 0xff, x86ByteFlagsAll, 0xfe, x86ByteFlagsAll},
	} {
		t.Run(row.body, func(t *testing.T) {
			state := x86ResultState{flags: row.flags}
			state.gp[1], state.gp[2], state.gp[3] = row.cx, row.dx, row.bx
			before := state.clone()
			if !x86LoweredPureGPUnknownTransfer(x86PureGPUnknownInstruction(t, row.body), &state, "amd64") {
				t.Fatal("unknown dependency was rejected")
			}
			before.gp[2], before.flags = row.wantDX, row.wantFlags
			if !reflect.DeepEqual(state, before) {
				t.Fatalf("got GP=%x flags=%x; want GP=%x flags=%x", state.gp, state.flags, before.gp, before.flags)
			}
		})
	}
	for _, body := range []string{"ADDL BX,DX", "MOVWQZX BX,DX", "CMOVLEQ BX,DX", "SHLXL CX,BX,DX"} {
		for _, pointer := range []int{2, 3} {
			ins := x86PureGPUnknownInstruction(t, body)
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.pointerGP[pointer] = true
			before := state.clone()
			accepted := x86LoweredPureGPUnknownTransfer(ins, &state, "amd64")
			writeOnly := pointer == 2 && (strings.HasPrefix(body, "MOV") || strings.HasPrefix(body, "SHLX"))
			if accepted != writeOnly {
				t.Fatalf("%s pointer%d accepted=%t", body, pointer, accepted)
			}
			if !accepted && !reflect.DeepEqual(state, before) {
				t.Fatal("rejected pointer changed state")
			}
			if accepted && state.pointerGP[pointer] {
				t.Fatal("written pointer identity survived")
			}
		}
	}
	for _, mutation := range []string{"known", "raw", "origin", "address", "segment", "foreign"} {
		ins := x86PureGPUnknownInstruction(t, "ADDL BX,DX")
		state, arch := x86ResultState{}, "amd64"
		switch mutation {
		case "known":
			state.gp[2], state.gp[3] = 0xff, 0xff
		case "raw":
			ins.x86Encoded = true
		case "origin":
			ins.x86SourceRaw = &x86SourceRawInstruction{}
		case "address":
			ins.x86AddressBits = 32
		case "segment":
			ins.x86SegmentPrefix = 0x64
		case "foreign":
			arch = "arm64"
		}
		before := state.clone()
		if x86LoweredPureGPUnknownTransfer(ins, &state, arch) || !reflect.DeepEqual(state, before) {
			t.Fatal("invalid fallback", mutation)
		}
	}
}

func TestX86LoweredPureGPUnknownOriginalGoAndFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for i, row := range x86PureGPUnknownCases(target.arch) {
				name := fmt.Sprintf("view%d", i)
				// A scalar FP bit view activates the actual lowering-only result
				// check, while the dead GP computation remains unobservable.
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVL $1,AX\nCMPL AX,AX\n%s\nMOVSS x+0(FP),X0\nMOVSS X0,ret+8(FP)\nRET\n", name, row.body)
				fmt.Fprintf(&declarations, "func %s(x uint64) uint32\n", name)
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "pure-gp.ll", "pure-gp.o", ir)
				})
			}
		})
	}
}

func TestX86LoweredPureGPUnknownRequiredBytesAndFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86PureGPUnknownCases(arch) {
			ins := x86PureGPUnknownInstruction(t, row.body)
			effect, known, err := x86TypedGPByteEffect(ins.Op, ins, arch)
			if !known || err != nil {
				t.Fatal(row.body, known, err)
			}
			complete := x86ResultState{flags: x86ByteFlagsAll}
			for index := range complete.gp {
				complete.gp[index] = 0xff
			}
			for _, operand := range effect.operands {
				if !operand.read || operand.operand.Kind != OpReg {
					continue
				}
				index, mask, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
				if !valid {
					t.Fatal("invalid typed GP role", row.body, operand)
				}
				for bit := uint8(1); bit != 0; bit <<= 1 {
					if mask&bit == 0 {
						continue
					}
					state := complete.clone()
					state.gp[index] &^= bit
					strict := state.clone()
					if x86ScalarFPResultTransfer(ins, &strict, nil, 0, arch) ||
						!x86LoweredPureGPUnknownTransfer(ins, &state, arch) {
						t.Fatalf("%s/%s missing register%d byte%x did not propagate", arch, row.body, index, bit)
					}
					if state.gp[2] == 0xff {
						t.Fatalf("%s/%s unknown input became a fully initialized result", arch, row.body)
					}
				}
			}
			for flag := uint8(1); flag <= x86ByteFlagOF; flag <<= 1 {
				if effect.flagsRead&flag == 0 {
					continue
				}
				state := complete.clone()
				state.flags &^= flag
				if !x86LoweredPureGPUnknownTransfer(ins, &state, arch) || state.gp[2] == 0xff {
					t.Fatalf("%s/%s unknown flag%x did not propagate", arch, row.body, flag)
				}
			}
		}
	}
}

func TestX86LoweredPureGPUnknownObservableThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for name, body := range map[string]string{
			"branch":  "JE done\nMOVL $1,AX\ndone:",
			"address": "MOVL (DX),AX",
			"store":   "MOVL DX,(AX)",
			"result":  "MOVL DX,X0",
		} {
			t.Run(target.triple+"/"+name, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$0-12\nMOVSS x+0(FP),X0\nADDL $64,DX\n" + body + "\nMOVSS X0,ret+8(FP)\nRET\n"
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view(x uint64) uint32\n", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s observable unknown bits accepted: %v", api, err)
					}
				}
			})
		}
	}
}
