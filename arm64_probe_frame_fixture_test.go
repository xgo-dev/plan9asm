package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func requireARM64ProbeGoObject(t *testing.T, source string) {
	t.Helper()
	// These primitive fixture forms are an actual object oracle in both
	// supported Go versions, not a version-specific optab inventory skip.
	if len(arm64ImmediateOriginalGoBytes(t, source, "linux")) == 0 {
		t.Fatal("actual Go probe fixture object contains no instruction bytes")
	}
}

func TestARM64ScalarAUTOProbeRetainsConcreteForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, op := range arm64MemoryScratchAuditMoves {
		for _, address := range []string{"slot(SP)", "slot+4(SP)", "slot+255(SP)", "slot+256(SP)"} {
			for _, store := range []bool{false, true} {
				instruction := fmt.Sprintf("%s %s,R21", op, address)
				if store {
					instruction = fmt.Sprintf("%s R21,%s", op, address)
				}
				t.Run(instruction, func(t *testing.T) {
					// This is our own compile-only source, not the frame of any
					// function from which an isolated instruction was extracted.
					source := arm64InstructionProbeTEXT + instruction + "\nB (ZR)\n"
					requireARM64ProbeGoObject(t, source)
					file, err := Parse(ArchARM64, source)
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					before := ins
					before.Args = append([]Operand(nil), ins.Args...)
					if err := ProbeInstruction(ArchARM64, "arm64", ins); err != nil {
						t.Errorf("explicit compile-only AUTO fixture rejected: %v", err)
					}
					if err := ProbeInstructionSequence(ArchARM64, "arm64", []Instr{ins}); err != nil {
						t.Errorf("sequence AUTO fixture rejected: %v", err)
					}
					if !reflect.DeepEqual(ins, before) || ins.arm64Encoded {
						t.Fatal("probe mutated operands or invented physical encoding identity")
					}
					fn, err := arm64InstructionProbeFunc([]Instr{ins})
					if err != nil {
						t.Fatal(err)
					}
					if fn.FrameSize != 0 || fn.ArgSize != 0 || !arm64SourceFrameFlagsKnown(fn) ||
						arm64SourceGoFrame(fn).present || fn.Instrs[0].Raw+"\n" != arm64InstructionProbeTEXT {
						t.Fatal("isolated fixture borrowed a frame instead of its exact zero/NOFRAME source")
					}
					fn.Instrs = append(fn.Instrs, file.Funcs[0].Instrs[2])
					for _, triple := range arm64TypedNativeTargets {
						ir, err := Translate(&File{Arch: ArchARM64, Funcs: []Func{fn}}, Options{
							Goarch: "arm64", TargetTriple: triple,
							Sigs: map[string]FuncSig{fn.Sym: {Name: fn.Sym, Ret: Void}},
						})
						if err != nil {
							t.Fatalf("%s concrete fixture: %v", triple, err)
						}
						if !strings.Contains(ir, `asm sideeffect "br $0", "r,~{memory}"(i64 0)`+"\n  unreachable") {
							t.Fatal("compile-only fixture replaced its actual faulting exit with a return claim")
						}
						compileLLVMToObject(t, llc, triple, "probe.ll", "probe.o", ir)
					}
				})
			}
		}
	}
}

func TestARM64ScalarAUTOProbeDoesNotAuthorizeForeignFrames(t *testing.T) {
	for _, header := range []string{
		"TEXT foreign(SB),4,$32-0",
		"TEXT foreign(SB),UNKNOWN_FLAGS,$32-0",
		"TEXT foreign(SB),516,$0-0",
		"TEXT foreign(SB),4,$2147483640-0",
	} {
		t.Run(header, func(t *testing.T) {
			file, err := Parse(ArchARM64, header+"\nMOVD slot(SP),R21\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if err := ProbeInstructionSequence(ArchARM64, "arm64", file.Funcs[0].Instrs); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("foreign TEXT replaced the isolated fixture: %v", err)
			}
		})
	}
	for _, op := range arm64MemoryScratchAuditMoves {
		ins := arm64ImmediateTestInstruction(t, op+" slot(SP),R21")
		for _, size := range []int64{0, 32, 1 << 30} {
			file := &File{Arch: ArchARM64, Funcs: []Func{{Sym: "foreign", FrameSize: size, Instrs: []Instr{ins, {Op: OpRET, Raw: "RET"}}}}}
			_, err := Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"foreign": {Name: "foreign", Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s frame size %d alone acquired source identity: %v", op, size, err)
			}
		}
	}
}

func TestARM64ScalarAUTOProbeRetainsContextAndInvalidOperands(t *testing.T) {
	for _, op := range arm64MemoryScratchAuditMoves {
		bits, _ := arm64ScalarMemoryBits(Op(op))
		if bits == 0 {
			t.Fatalf("missing scalar memory width for %s", op)
		}
		// This first out-of-range scaled displacement is accepted by Go,
		// but old and current encoders leave different values in R27.
		// The isolated fixture must not invent which native scratch it has.
		scratchContext := fmt.Sprintf("%s slot+%d(SP),R21", op, 4096*bits/8)
		requireARM64ProbeGoObject(t, arm64InstructionProbeTEXT+scratchContext+"\nB (ZR)\n")
		for _, test := range []struct {
			text    string
			context bool
		}{
			{op + " UNKNOWN(RSP),R21", true},
			{scratchContext, true},
			{op + " slot+9223372036854775807(SP),R21", false},
			{op + " input+0(FP),R21", true},
			{op + " R21,output+0(FP)", true},
		} {
			t.Run(test.text, func(t *testing.T) {
				ins := arm64ImmediateTestInstruction(t, test.text)
				if err := ProbeInstruction(ArchARM64, "arm64", ins); err == nil || test.context && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unbound/overflowing isolated frame did not retain its rejection: %v", err)
				}
				if err := ProbeInstructionSequence(ArchARM64, "arm64", []Instr{ins}); err == nil {
					t.Fatal("sequence fixture fabricated unresolved frame storage")
				}
			})
		}
		for _, text := range []string{
			op + ".P slot(SP),R21",
			op + " R21,slot(SP)(R2)",
		} {
			t.Run(text, func(t *testing.T) {
				ins := arm64ImmediateTestInstruction(t, text)
				if err := ProbeInstructionSequence(ArchARM64, "arm64", []Instr{ins}); err == nil {
					t.Fatal("probe erased a Go-invalid AUTO writeback/indexed role")
				}
			})
		}
	}
	for _, body := range []string{
		"MOVD $0(RSP),R0\nBL (R0)\n",
		"ADD R2,RSP,RSP\nMOVD slot(SP),R21\n",
	} {
		file, err := Parse(ArchARM64, "TEXT foreign(SB),516,$0-0\n"+body+"B (ZR)\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := ProbeInstructionSequence(ArchARM64, "arm64", file.Funcs[0].Instrs[1:len(file.Funcs[0].Instrs)-1]); err == nil {
			t.Fatalf("probe acquired a native-call or unbounded SP contract:\n%s", body)
		}
	}
	// A frame-address escape still cannot retain a saved caller link, even
	// though the separate compile-only data fixture has a real TEXT header.
	source := "TEXT escaped(SB),4,$32-0\nCALL sink(SB)\nMOVD $0(RSP),R0\nMOVD R0,(R1)\nMOVD R21,slot(SP)\nRET\nTEXT sink(SB),4,$0-0\nRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
		"escaped": {Name: "escaped", Ret: Void}, "sink": {Name: "sink", Ret: Void},
	}})
	if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "caller") {
		t.Fatalf("normal translation lost its escaping caller-frame guard: %v", err)
	}
}
