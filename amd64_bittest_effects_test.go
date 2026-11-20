package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86BitTestTypedByteAndFlagEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BitTestOracleNames(arch) {
			width := int64(map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]])
			writes := len(op) != 3
			for _, index := range []string{"$1", "CX"} {
				ins := x86PureGPUnknownInstruction(t, op+" "+index+",AX")
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 || effect.dynamicMemory ||
					effect.flagsDefined != x86ByteFlagCF || effect.flagsRead != 0 ||
					effect.flagsKilled != x86ByteFlagsAll&^(x86ByteFlagCF|x86ByteFlagZF) ||
					!effect.operands[1].read || effect.operands[1].write != writes {
					t.Fatalf("incomplete %s/%s byte/flag effects: %+v %v", arch, ins.Raw, effect, err)
				}
				for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
					state := x86ResultState{flags: flags}
					state.gp[0], state.gp[1] = 0xff, 0xff
					if !x86ResultTransfer(ins, &state, nil, 0, arch) || state.flags != flags&x86ByteFlagZF|x86ByteFlagCF {
						t.Fatalf("%s/%s invented incoming flag state %x: %x", arch, ins.Raw, flags, state.flags)
					}
				}
				for missingOperand := 0; missingOperand < 2; missingOperand++ {
					for missingByte := int64(-1); missingByte < width; missingByte++ {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0], state.gp[1] = uint8(1<<uint(width)-1), uint8(1<<uint(width)-1)
						missing := missingByte >= 0 && (missingOperand == 1 || index != "$1")
						if missing {
							register := 1 - missingOperand
							state.gp[register] &^= 1 << uint(missingByte)
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
						if accepted == missing {
							t.Fatalf("%s/%s missing operand=%d byte=%d admitted=%v", arch, ins.Raw, missingOperand, missingByte, accepted)
						}
						if accepted {
							want := before.gp[0]
							if writes && width == 4 {
								want |= 0xf0
							}
							if state.gp[0] != want || state.gp[1] != before.gp[1] || state.flags != x86ByteFlagCF|x86ByteFlagZF {
								t.Fatalf("%s/%s changed unwritten bytes or preserved undefined flags: %+v", arch, ins.Raw, state)
							}
						}
					}
				}
				memory := x86PureGPUnknownInstruction(t, op+" "+index+",(DX)")
				effect, known, err = x86TypedInstructionByteEffect(memory.Op, memory, arch)
				if !known || err != nil || effect.dynamicMemory != (index == "CX") {
					t.Fatal("memory bit string was mistaken for a fixed register word", memory, effect, err)
				}
			}
		}
	}
}

func TestX86BitTestFlagsAndMemoryDoNotAcquireAuthority(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86BitTestOracleNames(target.arch) {
			for _, condition := range []struct {
				branch string
				valid  bool
			}{{"JCS", true}, {"JE", true}, {"JOS", false}, {"JMI", false}, {"JPS", false}} {
				source := "TEXT ·value(SB),4,$0-4\nMOVL $1,AX\nCMPL AX,AX\n" + op + " $0,AX\n" +
					condition.branch + " equal\nMOVL $7,AX\nMOVL AX,X0\nJMP done\nequal:\nPXOR X0,X0\ndone:\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					_, err := x86ScalarFPBitViewAPI(t, source, "func value() uint32", target.arch, target.triple, api)
					if condition.valid && err != nil || !condition.valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s/%s/%s/%s flag initialization differs: %v", target.triple, op, condition.branch, api, err)
					}
				}
			}
			for _, memory := range []string{"unbound(SB)", "(DX)", "8(DX)(FS*1)", "8(DX)(GS*1)"} {
				source := "TEXT ·value(SB),4,$0-4\n" + op + " $0," + memory + "\nPXOR X0,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func value() uint32", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("new native/source read authority: %s/%s/%s/%s: %v", target.triple, op, memory, api, err)
					}
				}
			}
		}
	}
}

func TestX86BitTestSegmentContinuationObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, op := range x86BitTestOracleNames(target.arch) {
				for _, segment := range []string{"FS", "GS"} {
					for _, index := range []string{"$0", "CX"} {
						memory := "8(" + segment + ")"
						ins := x86PureGPUnknownInstruction(t, op+" "+index+","+memory)
						state := x86ResultState{}
						state.gp[1] = 0xff
						if x86ResultTransfer(ins, &state, nil, 0, target.arch) {
							t.Fatal("standalone observer borrowed paired native segment continuation", ins.Raw)
						}

						// Preserve the original bare-segment program. Only the
						// register-index counterpart adds its required input.
						name := fmt.Sprintf("segment%d", count)
						count++
						setup := ""
						if index == "CX" {
							setup = "MOVL $1,CX\n"
						}
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\n%s%s %s,%s\nPXOR X0,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+0(FP)\nRET\n",
							name, setup, op, index, memory)
						fmt.Fprintf(&declarations, "func %s() uint32\n", name)
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					if strings.Count(text, "load volatile") != count ||
						strings.Count(text, "store volatile") != count*3/4 ||
						!strings.Contains(text, "addrspace(256)") || !strings.Contains(text, "addrspace(257)") {
						t.Fatal("dead segment bit operations lost their exact paired accesses", api)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86BitTestFPCompleteByteSpans(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		var validSource, declarations strings.Builder
		count := 0
		for _, op := range x86BitTestOracleNames(target.arch) {
			width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
			for _, declaration := range []string{"func value(x uint64)", "func value(x [8]byte)", "func value(x float64)"} {
				for offset := -1; offset <= 8; offset++ {
					valid := offset >= 0 && offset+width <= 8
					source := fmt.Sprintf("TEXT ·value(SB),4,$0-8\n%s $-1,x%+d(FP)\nRET\n", op, offset)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if valid && err != nil || !valid && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("%s/%s/%s/%s/%d byte boundary: %v", target.triple, op, declaration, api, offset, err)
						}
						if valid && x86CMOVFPHasNumericConversion(ir) {
							t.Fatal("raw FP bits were numerically converted")
						}
					}
				}
			}
			for _, declaration := range []string{"func value(x *uint64)", "func value(x uint8,y uint64)", "func value() uint64"} {
				source := fmt.Sprintf("TEXT ·value(SB),4,$0-16\n%s $0,x+0(FP)\nRET\n", op)
				if _, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, "text"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("hole/pointer/uninitialized result acquired FP bytes: %s/%s/%s: %v", target.triple, op, declaration, err)
				}
			}
			name := fmt.Sprintf("span%d", count)
			fmt.Fprintf(&validSource, "TEXT ·%s(SB),4,$0-8\n%s $1,x+0(FP)\nRET\n", name, op)
			fmt.Fprintf(&declarations, "func %s(x [8]byte)\n", name)
			count++
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, validSource.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, validSource.String(), declarations.String(), target.arch, target.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "bit-test-fp.ll", "bit-test-fp.o", ir)
		}
	}
}
