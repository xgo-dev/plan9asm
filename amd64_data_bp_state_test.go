package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestAMD64SourceDefinedDataBPExactNativeWidthsAndAliases(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	var source, declarations strings.Builder
	for index, row := range []struct{ move, rotate, register string }{
		{"MOVB", "ROLB", "AL"}, {"MOVW", "ROLW", "AX"},
		{"MOVL", "ROLL", "AX"}, {"MOVQ", "ROLQ", "AX"},
		{"MOVD", "ROLQ", "AX"}, {"MOVDQ2Q", "ROLQ", "AX"},
	} {
		name := fmt.Sprintf("Value%d", index)
		body := fmt.Sprintf("%s (BP),%s\n%s $7,%s\n%s %s,8(BP)",
			row.move, row.register, row.rotate, row.register, row.move, row.register)
		source.WriteString(strings.Replace(amd64DataBPSource(8, "MOVQ p+0(FP),BP", body), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *[16]byte)\n", name)
	}
	for _, triple := range []string{
		"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete data BP move widths/source aliases lost their typed input", err)
					}
					for _, width := range []int{8, 16, 32, 64} {
						want := 1
						if width == 64 {
							want = 3
						}
						if strings.Count(ir, fmt.Sprintf("load volatile i%d,", width)) != want ||
							strings.Count(ir, fmt.Sprintf("store volatile i%d ", width)) != want {
							t.Fatal("native BP input/output must retain every exact-width original access", width)
						}
					}
					for _, body := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
						compileLLVMToObject(t, llc, triple, "data-bp.ll", "data-bp.o", body)
					}
				})
			}
		})
	}
}

func TestAMD64SourceDefinedDataBPUsesExistingPointerCloneJoinAndAtomicity(t *testing.T) {
	var initial x86ResultState
	initial.pointerFP = map[int64]bool{0: true}
	initial.gp[1], initial.canonicalGP[1] = 0xff, 1
	initial.flags, initial.direction = x86ByteFlagCF, x86ResultDirectionBackward
	state := initial.clone()
	imported := x86ScalarLaneInstruction(t, "MOVQ p+0(FP),BP")
	if accepted, known := x86ResultDataBPStep(imported, &state, nil, 0); !accepted || !known {
		t.Fatal("complete typed import did not define the existing BP opaque-pointer slot")
	}
	want := initial.clone()
	want.pointerGP[5] = true
	if !reflect.DeepEqual(state, want) || state.gp[5] != 0 || state.callerAddressGP[5] {
		t.Fatal("a data BP import fabricated NUM, caller-address or unrelated state")
	}

	clone := state.clone()
	clone.pointerGP[5] = false
	if !state.pointerGP[5] || state.intersect(clone).pointerGP[5] {
		t.Fatal("a clone/join retained an absent incoming BP pointer identity")
	}
	if !state.intersect(state.clone()).pointerGP[5] {
		t.Fatal("equal complete pointer paths lost their existing must-fact")
	}
	for _, spelling := range []string{
		"MOVQ BP,BX", "MOVQ BX,BP", "MOVL (BP),AX", "MOVL AX,8(BP)",
	} {
		t.Run("initialized/"+spelling, func(t *testing.T) {
			before := state.clone()
			before.pointerGP[3], before.gp[0] = true, 0xff
			if accepted, known := x86ResultDataBPStep(x86ScalarLaneInstruction(t, spelling), &before, nil, 0); !accepted || !known {
				t.Fatal("an actual initialized pointer/data input was lost", accepted, known)
			}
			if before.flags != state.flags || before.direction != state.direction || before.gp[5] != 0 || before.callerAddressGP[5] {
				t.Fatal("data BP transfer created pointer bits or changed FLAGS/DF")
			}
		})
	}
	for _, spelling := range []string{
		"MOVQ BP,BX", "MOVQ BX,BP", "MOVL (BP),AX", "MOVL AX,8(BP)", "MOVL (BP)(CX*1),AX",
	} {
		t.Run("missing/"+spelling, func(t *testing.T) {
			before := initial.clone()
			before.gp[1] = 0
			frozen := before.clone()
			if accepted, known := x86ResultDataBPStep(x86ScalarLaneInstruction(t, spelling), &before, nil, 0); accepted || !known || !reflect.DeepEqual(before, frozen) {
				t.Fatal("a rejected transfer manufactured input facts or partially mutated state", accepted, known)
			}
		})
	}
	for byteIndex := 0; byteIndex < 8; byteIndex++ {
		t.Run(fmt.Sprintf("index-byte/%d", byteIndex), func(t *testing.T) {
			before := state.clone()
			before.gp[1] = 0xff &^ (1 << byteIndex)
			frozen := before.clone()
			instruction := x86ScalarLaneInstruction(t, "MOVL (BP)(CX*1),AX")
			if accepted, known := x86ResultDataBPStep(instruction, &before, nil, 0); accepted || !known || !reflect.DeepEqual(before, frozen) {
				t.Fatal("an actual incoming BP pointer substituted for a missing numerical index byte")
			}
		})
	}
}

func TestAMD64SourceDefinedDataBPScopeDoesNotBorrowOtherOwners(t *testing.T) {
	source := amd64DataBPSource(8, "MOVQ p+0(FP),BP", "MOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)")
	_, file, signature, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[4]uint32)",
		"MOVQ p+0(FP),BP\nMOVL (BP),AX\nROLL $7,AX\nMOVL AX,12(BP)\nRET")
	parsed, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	file.Funcs[0] = parsed.Funcs[0]
	if !x86DataBPSourceScope(file.Funcs[0], signature, "amd64") {
		t.Fatal("the independent initialized complete named source lost its data-register view")
	}
	for _, mutation := range []string{
		"mode32", "frameless", "changed-frame", "changed-args", "NOFRAME", "NEEDCTXT", "CALL", "raw-origin",
		"raw-entry", "source-stack", "fixed-local", "continuation", "register-entry", "FP-address", "SP", "private-PUSH",
		"changed-source-raw", "changed-source-operands",
	} {
		t.Run(mutation, func(t *testing.T) {
			fn, sig, arch := file.Funcs[0], signature, "amd64"
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			switch mutation {
			case "mode32":
				arch = "386"
			case "frameless":
				fn.FrameSize = 0
			case "changed-frame":
				fn.FrameSize += 8
			case "changed-args":
				fn.ArgSize += 8
			case "NOFRAME":
				fn.Instrs[0].Raw = "TEXT ·Value(SB),516,$8-8"
			case "NEEDCTXT":
				fn.Instrs[0].Raw = "TEXT ·Value(SB),68,$8-8"
			case "CALL":
				fn.Instrs[2] = x86ScalarLaneInstruction(t, "CALL foreign(SB)")
			case "raw-origin":
				fn.Instrs[2].x86Encoded = true
			case "raw-entry":
				fn.X86RawText = []byte{0xc3}
			case "source-stack":
				fn.x86SourceStack = new(x86SourceStackProof)
			case "fixed-local":
				fn.x86FixedLocal = new(x86FixedLocalProof)
			case "continuation":
				fn.x86ContinuationFlow = new(x86ContinuationFlow)
			case "register-entry":
				sig.ArgRegs = []Reg{AX}
			case "FP-address":
				fn.Instrs[2] = x86ScalarLaneInstruction(t, "LEAQ p+0(FP),AX")
			case "SP":
				fn.Instrs[2] = x86ScalarLaneInstruction(t, "MOVQ SP,AX")
			case "private-PUSH":
				fn.Instrs[2] = x86ScalarLaneInstruction(t, "PUSHQ AX")
			case "changed-source-raw":
				fn.Instrs[1].Raw = "MOVQ unknown+0(FP),AX"
			case "changed-source-operands":
				fn.Instrs[1].Args = append([]Operand(nil), fn.Instrs[1].Args...)
				fn.Instrs[1].Args[1].Reg = BX
			}
			if x86DataBPSourceScope(fn, sig, arch) {
				t.Fatal("the bounded data-register source view borrowed another physical/source owner")
			}
		})
	}
	for _, address := range []string{
		"LEAW p+0(FP),AX", "LEAL p+0(FP),AX", "LEAQ p+0(FP),AX",
		"MOVQ $p+0(FP),AX", "MOVD $p+0(FP),AX", "MOVDQ2Q $p+0(FP),AX",
	} {
		t.Run("complete-FP-address-family/"+address, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			fn.Instrs[2] = x86ScalarLaneInstruction(t, address)
			if x86DataBPSourceScope(fn, signature, "amd64") {
				t.Fatal("the complete LEA width/address-MOV alias family acquired a data BP source role")
			}
		})
	}
}
