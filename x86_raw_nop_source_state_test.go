package plan9asm

import (
	"fmt"
	"testing"
)

func x86RawNOPSourceStateInstruction(t *testing.T, arch string, code []byte) Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
	if err != nil {
		t.Fatal(err)
	}
	fn, err := decodeX86RawDirectives(file.Funcs[0], arch)
	if err != nil {
		t.Fatal(err)
	}
	for _, ins := range fn.Instrs {
		if ins.x86SourceRaw != nil {
			return ins
		}
	}
	t.Fatal("missing actual original/normalized raw handoff")
	return Instr{}
}

func TestX86RawNOPCompleteSourceStateRetention(t *testing.T) {
	for _, mode := range []int{32, 64} {
		arch := "amd64"
		if mode == 32 {
			arch = "386"
		}
		for _, code := range x86RawNOPWitnesses(mode) {
			t.Run(fmt.Sprintf("mode%d/%x", mode, code), func(t *testing.T) {
				ins := x86RawNOPSourceStateInstruction(t, arch, code)
				for _, direction := range []x86ResultDirection{0, 1, 2, 3} {
					if got := x86ResultDirectionAfter(ins, direction); got != direction {
						t.Fatal("inert raw NOP lost or invented DF", direction, got)
					}
				}
				for _, count := range []x86ResultStringCount{x86StringCountUnknown, x86StringCountZero, x86StringCountNonzero} {
					if got := x86ResultStringCountAfter(ins, count, count, arch); got != count {
						t.Fatal("inert raw NOP lost or invented the unchanged CX fact", count, got)
					}
				}
				for _, predicate := range []x86ResultPredicate{{}, {kind: x86ResultNonzeroComparisonBytes, register: 3, width: 32}} {
					if got := x86ResultPredicateAfter(ins, predicate, arch); got != predicate {
						t.Fatal("inert raw NOP changed an existing relation", predicate, got)
					}
				}
				for _, before := range [][16]bool{{}, {3: true, 7: true}} {
					if got := x86ResultCallerAddressesAfter(ins, before, nil, arch); got != before {
						t.Fatal("inert raw NOP lost or invented an existing GP identity", before, got)
					}
				}
			})
		}
	}
}

func TestX86RawNOPPrivateStackAndIDRetention(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		width := "Q"
		if arch == "386" {
			width = "L"
		}
		for _, live := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/live=%t", arch, live), func(t *testing.T) {
				body := x86RawDisplacementDirectives([]byte{0x0f, 0x1f, 0xc0})
				if live {
					body = "PUSH" + width + " $7\n" + body + "POP" + width + " AX\n"
				}
				file, err := Parse(ArchAMD64, "TEXT value(SB),4,$0-0\n"+body+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				fn, err := decodeX86RawDirectives(file.Funcs[0], arch)
				if err != nil {
					t.Fatal(err)
				}
				for _, initialized := range []bool{false, true} {
					state := x86ResultState{valueStack: &x86ResultValueStack{id: initialized}}
					if initialized {
						state.direction, state.flags = x86ResultDirectionEither, x86ByteFlagsAll
					}
					err = checkX86ResultSourceFlow(fn, state, nil, 0, arch,
						func(_ int, ins Instr, state *x86ResultState, owned []bool, offset int64, arch string) bool {
							return x86ResultTransfer(ins, state, owned, offset, arch)
						}, func(after x86ResultState, _ int) error {
							if after.valueStack.id != initialized || after.direction != state.direction || after.flags != state.flags {
								return fmt.Errorf("inert padding changed private status: before=%+v after=%+v", state, after)
							}
							return nil
						})
					if err != nil {
						t.Fatal("sealed padding changed independent private numerical transport", initialized, err)
					}
				}
			})
		}
	}
}

func TestX86RawNOPStateRetentionRequiresExactHandoff(t *testing.T) {
	original := x86RawNOPSourceStateInstruction(t, "amd64", []byte{0x0f, 0x1f, 0xc0})
	for _, mutation := range []string{
		"original opcode", "original operands", "normalized opcode", "normalized operands",
		"encoded", "raw return", "address size", "unbound address", "segment",
	} {
		t.Run(mutation, func(t *testing.T) {
			ins := original
			origin := *ins.x86SourceRaw
			ins.x86SourceRaw = &origin
			switch mutation {
			case "original opcode":
				origin.op = "PAUSE"
			case "original operands":
				origin.args = []Operand{{Kind: OpReg, Reg: AX}}
			case "normalized opcode":
				ins.Op = "PAUSE"
			case "normalized operands":
				ins.Args = []Operand{{Kind: OpReg, Reg: AX}}
			case "encoded":
				ins.x86Encoded = true
			case "raw return":
				ins.x86RawNearReturn = new(x86RawNearReturnForm)
			case "address size":
				ins.x86AddressBits = 32
			case "unbound address":
				ins.x86UnboundAddressOverride = true
			case "segment":
				ins.x86SegmentPrefix = 0x64
			}
			if got := x86ResultDirectionAfter(ins, x86ResultDirectionForward); got != x86ResultDirectionUnknown {
				t.Fatal("changed physical effect retained DF", got)
			}
			if got := x86ResultStringCountAfter(ins, x86StringCountZero, x86StringCountZero, "amd64"); got != x86StringCountUnknown {
				t.Fatal("changed physical effect retained a CX fact", got)
			}
			predicate := x86ResultPredicate{kind: x86ResultNonzeroComparisonBytes, register: 3, width: 32}
			if got := x86ResultPredicateAfter(ins, predicate, "amd64"); got != (x86ResultPredicate{}) {
				t.Fatal("changed physical effect retained a relation", got)
			}
			if got := x86ResultCallerAddressesAfter(ins, [16]bool{3: true}, nil, "amd64"); got != ([16]bool{}) {
				t.Fatal("changed physical effect retained GP identities", got)
			}
			state := x86ResultState{valueStack: &x86ResultValueStack{bytes: make([]uint8, 8)}}
			if x86ResultValueStackContinuation(ins, &state, "amd64") {
				t.Fatal("changed physical effect entered live private storage")
			}
		})
	}
}

func TestX86RawNOPOriginalStatusSourceObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86OrderingHintTargets {
		bits := 64
		if target.arch == "386" {
			bits = 32
		}
		declarations, source, _, _ := x86RawNOPRuntimeFixture(bits)
		t.Run(target.triple, func(t *testing.T) {
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86OrderingHintTranslateAPI(t, api, source, declarations, target.arch, target.triple)
				if err != nil {
					t.Fatal("unchanged raw-NOP GP/FLAGS/MXCSR/canary source", api, err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
	t.Log("unchanged original state fixture: Go and LLVM objects, not native x86 execution")
}
