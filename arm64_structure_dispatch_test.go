package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func arm64StructureDispatchInstruction(t *testing.T, syntax string) Instr {
	t.Helper()
	file, err := Parse(ArchARM64, "TEXT dispatch(SB),$0-0\n"+syntax+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func arm64StructureDispatchIR(t *testing.T, op Op, post bool, input, canonical Instr, vectorDispatcher bool) string {
	t.Helper()
	snapshot := input
	snapshot.Args = append([]Operand(nil), input.Args...)
	for index := range snapshot.Args {
		snapshot.Args[index].RegList = append([]Reg(nil), input.Args[index].RegList...)
	}
	c, output := newARM64CtxWithFuncForTest(t, Func{Instrs: []Instr{canonical}}, FuncSig{Ret: Void}, nil)
	var ok, terminated bool
	var err error
	if vectorDispatcher {
		ok, terminated, err = c.lowerVec(op, post, input)
	} else {
		ok, terminated, err = c.lowerARM64StructureLoadStore(op, post, input)
	}
	if !ok || terminated || err != nil {
		t.Fatalf("%s legacy=%v vector=%v: handled=%v terminated=%v err=%v", canonical.Raw, input.Op == "", vectorDispatcher, ok, terminated, err)
	}
	if !reflect.DeepEqual(input, snapshot) {
		t.Fatal("semantic lowering changed the caller's original instruction")
	}
	return output.String()
}

func TestARM64StructureDispatchLegacyAndCanonicalAgree(t *testing.T) {
	// The independent Go table enumerator spans every whole/replicate form.
	for _, tc := range arm64RawStructureCases() {
		canonical := arm64StructureDispatchInstruction(t, tc.syntax)
		legacy := canonical
		legacy.Op = ""
		want := arm64StructureDispatchIR(t, Op(tc.op), tc.post != 0, canonical, canonical, false)
		for _, vector := range []bool{false, true} {
			for _, input := range []Instr{canonical, legacy} {
				got := arm64StructureDispatchIR(t, Op(tc.op), tc.post != 0, input, canonical, vector)
				if got != want {
					t.Fatalf("semantic dispatch differs for %s, empty-op=%v vector=%v", tc.syntax, input.Op == "", vector)
				}
			}
		}
	}
	for _, syntax := range []string{
		"VLD1 (R0),V0.B[15]", "VLD1.P 2(R0),V0.H[7]",
		"VST1 V0.S[3],(R0)", "VST1.P V0.D[1],(R0)(R1)",
	} {
		canonical := arm64StructureDispatchInstruction(t, syntax)
		legacy := canonical
		legacy.Op = ""
		op := arm64ControlOp(canonical)
		post := canonical.Op != op
		want := arm64StructureDispatchIR(t, op, post, canonical, canonical, false)
		if got := arm64StructureDispatchIR(t, op, post, legacy, canonical, true); got != want {
			t.Fatalf("empty-op lane semantics differs for %s", syntax)
		}
	}
}

func TestARM64StructureDispatchConflictHasNoIRSideEffects(t *testing.T) {
	for _, tc := range []struct {
		op     Op
		post   bool
		syntax string
	}{
		{"VLD1", false, "VLD2 (R0),[V0.S4,V1.S4]"},
		{"VST2", false, "VST1 [V0.S4,V1.S4],(R0)"},
		{"VLD1R", false, "VLD1 (R0),[V0.S4]"},
		{"VLD1", true, "VLD1 (R0),[V0.S4]"},
		{"VST1", false, "VST1.P [V0.S4],16(R0)"},
		{"ADD", false, "VLD1 (R0),[V0.S4]"},
		{"VMOV", false, "VLD1 (R0),[V0.S4]"},
		{"VLD1", false, "VMOV V0.B16,V1.B16"},
		{"VLD1", false, "VLD1.W 16(R0),[V0.S4]"},
		{"VLD1.P", true, "VLD1.P 16(R0),[V0.S4]"},
	} {
		ins := arm64StructureDispatchInstruction(t, tc.syntax)
		for _, vector := range []bool{false, true} {
			snapshot := ins
			snapshot.Args = append([]Operand(nil), ins.Args...)
			for index := range snapshot.Args {
				snapshot.Args[index].RegList = append([]Reg(nil), ins.Args[index].RegList...)
			}
			c, output := newARM64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			before := output.String()
			var ok, terminated bool
			var err error
			if vector {
				ok, terminated, err = c.lowerVec(tc.op, tc.post, ins)
			} else {
				ok, terminated, err = c.lowerARM64StructureLoadStore(tc.op, tc.post, ins)
			}
			if !ok || terminated || err == nil {
				t.Errorf("op=%s post=%v source=%s vector=%v: (%v,%v,%v), want handled conflict", tc.op, tc.post, ins.Op, vector, ok, terminated, err)
			}
			if output.String() != before {
				t.Errorf("conflicting %s/%s emitted partial IR", tc.op, ins.Op)
			}
			if !reflect.DeepEqual(ins, snapshot) {
				t.Error("conflicting dispatch changed the caller's original instruction")
			}
		}
	}
}

func TestARM64StructureDispatchUnrelatedSourceIsUnhandled(t *testing.T) {
	ins := arm64StructureDispatchInstruction(t, "ADD $1,R0,R1")
	for _, legacy := range []bool{false, true} {
		input := ins
		if legacy {
			input.Op = ""
		}
		c, output := newARM64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
		before := output.String()
		ok, terminated, err := c.lowerARM64StructureLoadStore("ADD", false, input)
		if ok || terminated || err != nil || output.String() != before {
			t.Fatalf("unrelated source legacy=%v: (%v,%v,%v), want unhandled without IR effects", legacy, ok, terminated, err)
		}
	}
}

func TestARM64StructureDispatchOldLaneHelpersMatchGo(t *testing.T) {
	for _, tc := range []struct {
		memory string
		lane   string
		width  int
	}{
		{"R21", "V4.B[3]", 1},
		{"R20", "V3.D[1]", 8},
		{"R20", "V4.S[1]", 4},
		{"R20", "V5.H[3]", 2},
	} {
		// Preserve the invalid original first-party helper source. Go case
		// 97 requires one element's actual width for immediate lane .P.
		original := fmt.Sprintf("VLD1.P (%s),%s", tc.memory, tc.lane)
		corrected := fmt.Sprintf("VLD1.P %d(%s),%s", tc.width, tc.memory, tc.lane)
		for _, syntax := range []string{original, corrected} {
			valid := syntax == corrected
			requireARM64GoAssemblerResult(t, "TEXT laneHelper(SB),516,$0-0\n"+syntax+"\nUNDEF\n", valid)
			ins := arm64StructureDispatchInstruction(t, syntax)
			c, output := newARM64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			before := output.String()
			ok, terminated, err := c.lowerVec("VLD1", true, ins)
			if !ok || terminated || (err == nil) != valid {
				t.Fatalf("%s: (%v,%v,%v), want Go-valid=%v", syntax, ok, terminated, err, valid)
			}
			if !valid && output.String() != before {
				t.Fatalf("Go-rejected %s emitted partial IR", syntax)
			}
		}
	}
}

func TestARM64StructureDispatchRawReplicateProducer(t *testing.T) {
	for count := 1; count <= 4; count++ {
		for size := 0; size <= 3; size++ {
			for _, q := range []bool{false, true} {
				for _, rm := range []int{-1, 31, 7} {
					post := rm >= 0
					encodedRM := rm
					if !post {
						encodedRM = 0
					}
					word := encodeARM64RawLDnRForTest(count, size, q, post, encodedRM, 3, 30)
					form, valid := decodeARM64RawLDnR(word)
					if !valid {
						t.Fatalf("independent replicate encoding %#08x rejected", word)
					}
					arrangement := arm64VectorArrangementName(form.arrangement)
					memory, suffix := "(R3)", ""
					if post {
						suffix = ".P"
						if rm == 31 {
							memory = fmt.Sprintf("%d(R3)", count*(8<<size)/8)
						} else {
							memory += "(R7)"
						}
					}
					op := Op(fmt.Sprintf("VLD%dR", count))
					canonical := arm64StructureDispatchInstruction(t, string(op)+suffix+" "+memory+","+arm64TestVectorList(30, count, arrangement))
					want := arm64StructureDispatchIR(t, op, post, canonical, canonical, false)
					c, output := newARM64CtxWithFuncForTest(t, Func{Instrs: []Instr{canonical}}, FuncSig{Ret: Void}, nil)
					if err := c.lowerRawLDnR(form); err != nil {
						t.Fatal(err)
					}
					if output.String() != want {
						t.Fatalf("raw replicate producer %#08x differs from canonical typed form", word)
					}
				}
			}
		}
	}
}
