package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent complete Go yscond name inventory, not the implementation map.
var x86NativeSetOracle = strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS")

func TestX86NativeConditionalSetExactFlagsAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86NativeSetOracle {
			t.Run(arch+"/"+op, func(t *testing.T) {
				var required uint8
				switch op {
				case "SETCC", "SETCS":
					required = x86ByteFlagCF
				case "SETEQ", "SETNE":
					required = x86ByteFlagZF
				case "SETGE", "SETLT":
					required = x86ByteFlagSF | x86ByteFlagOF
				case "SETGT", "SETLE":
					required = x86ByteFlagZF | x86ByteFlagSF | x86ByteFlagOF
				case "SETHI", "SETLS":
					required = x86ByteFlagCF | x86ByteFlagZF
				case "SETMI", "SETPL":
					required = x86ByteFlagSF
				case "SETOC", "SETOS":
					required = x86ByteFlagOF
				case "SETPC", "SETPS":
					required = x86ByteFlagPF
				}
				ins := x86ScalarLaneInstruction(t, op+" 3(AX)(CX*2)")
				for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
					for _, pointer := range []bool{false, true} {
						state := x86ResultState{flags: flags}
						state.pointerGP[0], state.gp[1], state.masks[7] = pointer, 0xff, true
						before := state.clone()
						accepted, known := x86LoweredNativeConditionalSet(ins, &state, arch)
						if !known || accepted != (pointer && flags&required == required) || !reflect.DeepEqual(state, before) {
							t.Fatal("SETcc invented FLAGS/address or changed numerical state", flags, pointer, accepted, known)
						}
					}
				}
			})
		}
	}
}

func x86NativeSetFixture(arch string) (string, string, []string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	var names []string
	for _, op := range x86NativeSetOracle {
		name := "Native" + op
		names = append(names, name)
		fmt.Fprintf(&declarations, "func %s(p *[8]byte,x,y uint32)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL x+%d(FP),BX\n"+
			"MOVL y+%d(FP),CX\nCMPL BX,CX\n%s 3(AX)\nRET\n", name, word+8, move, word, word+4, op)
	}
	return source.String(), declarations.String(), names
}

func TestX86NativeConditionalSetCompleteFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, names := x86NativeSetFixture(target.arch)
			if len(names) != 16 {
				t.Fatal("complete yscond denominator changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized native SETcc rejected", api, err)
				}
				x86CompactExpandRequireAllDefinitions(t, ir, names)
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					if strings.Count(text, "store volatile i8 ") != len(names) {
						t.Fatal("SETcc lost an observable exact-byte write", api)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86NativeConditionalSetCannotInventFlagsOrAddress(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		source, declarations, _ := x86NativeSetFixture(arch)
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for name, changed := range map[string]string{
			"unknown-flags": strings.ReplaceAll(source, "CMPL BX,CX\n", ""),
			"unknown-base":  strings.ReplaceAll(source, "p+0(FP),AX", "p+0(FP),DI"),
			"numeric-base":  strings.ReplaceAll(source, "CMPL BX,CX", "MOVL $42,AX\nCMPL BX,CX"),
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, changed, declarations, arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("native SETcc invented a source flag or pointer", api, err)
					}
				}
			})
		}
	}
}

// Complete original format-only SETcc fixtures have no initialized FLAGS or
// native addresses. Public translation must reject that missing context.
// This separately labeled emitter unit retains every original instruction and
// its logical byte result; its objects are never an executable source proof.
func x86ConditionalSetOriginalEmitterUnit(t *testing.T, file *File, arch, triple string) string {
	t.Helper()
	if len(file.Funcs) != 1 || len(file.Data) != 0 || len(file.Globl) != 0 {
		t.Fatal("SETcc emitter unit requires one complete original TEXT")
	}
	fn := file.Funcs[0]
	if fn.FrameSize != 0 || fn.ArgSize != 1 {
		t.Fatal("SETcc emitter unit lost its original logical byte layout")
	}
	sig := FuncSig{Name: "SETEmitterOnly", Ret: I8,
		Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I8, Index: 0, Field: -1}}}}
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\n", triple)
	emitAMD64Prelude(&ir, arch, file)
	emitExternSBGlobals(&ir, file, func(name string) string { return name }, nil)
	ir.WriteString("define i8 @SETEmitterOnly() {\n")
	consumer := newX86Ctx(&ir, fn, sig, func(name string) string { return name }, nil, arch, triple, false)
	if err := consumer.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	emitted, returns := 0, 0
	for ordinal, instruction := range fn.Instrs {
		switch instruction.Op {
		case OpTEXT:
			if ordinal != 0 {
				t.Fatal("emitter unit lost original TEXT order")
			}
		case OpRET:
			if ordinal != len(fn.Instrs)-1 || len(instruction.Args) != 0 {
				t.Fatal("emitter unit cannot omit original continuations")
			}
			value, err := consumer.loadFPResult(sig.Frame.Results[0])
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&ir, "  ret i8 %s\n", value)
			returns++
		default:
			known, terminated, err := consumer.lowerConditionalSet(instruction.Op, instruction)
			if !known || terminated || err != nil {
				t.Fatal("original SETcc row was not emitted", ordinal, instruction.Raw, err)
			}
			emitted++
		}
	}
	if emitted != len(fn.Instrs)-2 || returns != 1 || consumer.fpScalarChecked {
		t.Fatal("emitter unit dropped original source or borrowed a source proof")
	}
	ir.WriteString("}\n")
	t.Logf("emitter-only LLVM object: all %d original SETcc rows; no public translation or execution claim", emitted)
	return ir.String()
}
