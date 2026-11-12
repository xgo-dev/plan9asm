package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestX86TimestampVoidCannotBorrowUnwrittenImplicitRegisters(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, word, triple := "MOVL", 4, "i386-unknown-linux-gnu"
		if arch == "amd64" {
			move, word, triple = "MOVQ", 8, "x86_64-unknown-linux-gnu"
		}
		for _, row := range []struct {
			op, source string
			valid      bool
		}{
			{"RDTSC", "AX", true}, {"RDTSC", "DX", true}, {"RDTSC", "CX", false},
			{"RDTSCP", "AX", true}, {"RDTSCP", "DX", true}, {"RDTSCP", "CX", true},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.op+"/"+row.source+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Clock(SB),4,$0-%d\n%s p+0(FP),DI\n%s\nMOVL %s,(DI)\nRET\n",
						word, move, row.op, row.source)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Clock(p *uint32)", arch, triple, api)
					if row.valid {
						if err != nil || ir == "" {
							t.Fatal("actual timestamp output lost its native store continuation", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("RDTSC invented RDTSCP's CX output in a Void function", err)
					}
				})
			}
		}
	}
}

func TestX86TimestampNumericalEffectsUseCompleteImplicitOutputSpec(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{"RDTSC", "RDTSCP"} {
			t.Run(arch+"/"+string(op), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, string(op))
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				for index := range state.pointerGP {
					state.pointerGP[index], state.callerAddressGP[index] = true, true
				}
				before := state.clone()
				if !x86ResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatal("whole native timestamp outputs have no numerical effect")
				}
				want := before.clone()
				outputs := []int{0, 2} // AX, DX; RDTSCP additionally defines CX.
				if op == "RDTSCP" {
					outputs = append(outputs, 1)
				}
				addresses := before.callerAddressGP
				for _, index := range outputs {
					want.gp[index], want.pointerGP[index], addresses[index] = 0xff, false, false
				}
				if !reflect.DeepEqual(state, want) {
					t.Fatal("timestamp invented or killed unrelated numerical/status/domain facts")
				}
				if after := x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch); after != addresses {
					t.Fatal("timestamp GP write footprint lost an unrelated pointer or retained an overwritten one")
				}
			})
		}
	}
}

func TestX86TimestampInitializedScalarResultsThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"RDTSC", "RDTSCP"} {
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				declaration, result, tail := "uint64", 8, ""
				if op == "RDTSCP" {
					declaration, result, tail = "(uint64,uint32)", 12, "MOVL CX,aux+8(FP)\n"
				}
				source := fmt.Sprintf("TEXT ·Clock(SB),4,$0-%d\n%s\nMOVL AX,stamp+0(FP)\nMOVL DX,stamp+4(FP)\n%sRET\n", result, op, tail)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Clock() "+declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("actual native implicit dword results lost their typed output bytes", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86TimestampRawCompositionRetainsExactOriginalRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range []Op{"RDTSC", "RDTSCP"} {
			code := []byte{0x0f, 0x31}
			if opcode == "RDTSCP" {
				code = []byte{0x0f, 0x01, 0xf9}
			}
			x86RegisterQueryRawCompositionRoles(t, arch, opcode, code, "")
		}
	}
}

// The same original/normalized identity boundary protects timestamps and CPU
// queries; each caller supplies independent bytes and required input setup.
func x86RegisterQueryRawCompositionRoles(t *testing.T, arch string, opcode Op, code []byte, initialization string) {
	t.Helper()
	move, word := "MOVL", 4
	if arch == "amd64" {
		move, word = "MOVQ", 8
	}
	body := fmt.Sprintf("%s p+0(FP),DI\n%sMOVL AX,ret+%d(FP)\nSTMXCSR (DI)\nRET",
		move, initialization+x86RawDisplacementDirectives(code), word)
	_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *uint32) uint32", body)
	normalized, err := decodeX86RawDirectives(file.Funcs[0], arch)
	if err != nil {
		t.Fatal(err)
	}
	position := -1
	for index, ins := range normalized.Instrs {
		if ins.x86SourceRaw != nil {
			if ins.Op != opcode || position != -1 {
				t.Fatal("original timestamp did not decode to exactly one instruction")
			}
			position = index
		}
	}
	if position < 0 {
		t.Fatal("missing exact raw timestamp handoff")
	}
	for _, mutation := range []string{"unchanged", "original-opcode", "original-operands", "normalized-opcode",
		"normalized-operands", "encoded", "address-size", "unbound-address", "segment-prefix",
		"raw-return", "raw-TEXT", "source-stack", "fixed-local"} {
		t.Run(arch+"/"+string(opcode)+"/"+mutation, func(t *testing.T) {
			fn := normalized
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			ins := &fn.Instrs[position]
			origin := *ins.x86SourceRaw
			ins.x86SourceRaw = &origin
			switch mutation {
			case "original-opcode":
				origin.op = "NOP"
			case "original-operands":
				origin.args = []Operand{{Kind: OpReg, Reg: AX}}
			case "normalized-opcode":
				ins.Op = "NOP"
			case "normalized-operands":
				ins.Args = []Operand{{Kind: OpReg, Reg: AX}}
			case "encoded":
				ins.x86Encoded = true
			case "address-size":
				ins.x86AddressBits = 32
			case "unbound-address":
				ins.x86UnboundAddressOverride = true
			case "segment-prefix":
				ins.x86SegmentPrefix = 0x64
			case "raw-return":
				ins.x86RawNearReturn = new(x86RawNearReturnForm)
			case "raw-TEXT":
				fn.X86RawText = code
			case "source-stack":
				fn.x86SourceStack = new(x86SourceStackProof)
			case "fixed-local":
				fn.x86FixedLocal = new(x86FixedLocalProof)
			}
			consumer := &amd64Ctx{fpScalarSource: fn, sig: sig, fpSourceSig: sig, goarch: arch}
			err := consumer.checkLoweredScalarFPResultInitialization()
			if mutation == "unchanged" {
				if err != nil {
					t.Fatal("complete matching register query lost its paired native continuation", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("raw register query granted a mismatched source/entry/storage role", err)
			}
		})
	}
}
