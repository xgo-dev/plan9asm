package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func requireX86OutgoingCandidateGoSource(t *testing.T, source string) {
	t.Helper()
	requireX86GoAssemblerResult(t, "amd64", source, true)
	t.Logf("original Go assembler accepted source sha256=%x", sha256.Sum256([]byte(source)))
}

func x86OutgoingCandidateFixture(t *testing.T, parameters, load string, calls []string) (*File, Options, string) {
	t.Helper()
	declarations := "package outgoing\nfunc Caller(" + parameters + ") float64\n" +
		"func First(a uint8) float64\nfunc Callee(" + parameters + ") float64\n"
	pkg := mustGoPackage(t, "outgoing", declarations)
	options := Options{Goarch: "amd64", Sigs: make(map[string]FuncSig),
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "outgoing.", 1) }}
	for _, name := range []string{"Caller", "First", "Callee"} {
		declaration := pkg.Types.Scope().Lookup(name).(*types.Func)
		sig, err := DeriveGoFuncABI0Signature("outgoing."+name, declaration, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[sig.Name] = sig
	}
	caller := options.Sigs["outgoing.Caller"]
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Caller(SB),4,$64-%d\n", caller.Frame.Results[0].Offset+8)
	for _, name := range calls {
		callee := options.Sigs["outgoing."+name]
		for index, slot := range callee.Frame.Params {
			input := caller.Frame.Params[index]
			move, register := "MOVQ", "AX"
			switch slot.Type {
			case I8:
				move = "MOVB"
			case I16:
				move = "MOVW"
			case I32:
				move = "MOVL"
			case "float":
				move, register = "MOVSS", "X0"
			case "double":
				move, register = "MOVSD", "X0"
			}
			read := move
			if index == 0 && load != "" {
				read = load
			}
			inputName := input.Name
			if inputName == "" {
				inputName = fmt.Sprintf("arg%d", index)
			}
			fmt.Fprintf(&source, "%s %s+%d(FP),%s\n%s %s,%d(SP)\n",
				read, inputName, input.Offset, register, move, register, slot.Offset)
		}
		fmt.Fprintf(&source, "CALL ·%s(SB)\nMOVSD %d(SP),X1\nMOVSD X1,ret+%d(FP)\n",
			name, callee.Frame.Results[0].Offset, caller.Frame.Results[0].Offset)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	return file, options, source.String()
}

func TestGoAMD64FixedLocalOutgoingABI0ForwardCandidates(t *testing.T) {
	for _, parameters := range []string{
		"a uint8", "a uint16", "a uint32", "a uint64", "a float32", "a float64",
		"a uint8,b uint64", "a struct { X uint8; Y uint64 }",
		"a []byte", "a [3]uint64", "a struct { X [2]uint16; Y struct { Z uint64 } }",
	} {
		for _, rounds := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d", parameters, rounds), func(t *testing.T) {
				calls := []string{"Callee"}
				if rounds == 2 {
					calls = append(calls, "Callee")
				}
				file, options, source := x86OutgoingCandidateFixture(t, parameters, "", calls)
				requireX86OutgoingCandidateGoSource(t, source)
				t.Logf("original untyped source candidate=%t", GoAMD64FixedLocalFrameBindingNeeded(file, "amd64"))
				if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
					t.Fatal("complete typed outgoing frame was routed to the unrelated native-frame factory")
				}
			})
		}
	}
	t.Run("different callee layouts", func(t *testing.T) {
		file, options, source := x86OutgoingCandidateFixture(t, "a uint8,b uint64", "MOVBLZX", []string{"First", "Callee"})
		requireX86OutgoingCandidateGoSource(t, source)
		if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
			t.Fatal("independent typed call rounds lost their actual parameter/result offsets")
		}
	})
	t.Run("multiple callers", func(t *testing.T) {
		_, options, source := x86OutgoingCandidateFixture(t, "a uint64", "", []string{"Callee"})
		sig := options.Sigs["outgoing.Caller"]
		sig.Name = "outgoing.Other"
		options.Sigs[sig.Name] = sig
		second := strings.Replace(source, "·Caller", "·Other", 1)
		complete := source + second
		requireX86OutgoingCandidateGoSource(t, complete)
		file, err := Parse(ArchAMD64, complete)
		if err != nil {
			t.Fatal(err)
		}
		if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
			t.Fatal("a second complete typed caller changed the source role")
		}
		file, err = Parse(ArchAMD64, source+strings.Replace(second, "RET\n", "MOVQ AX,48(SP)\nRET\n", 1))
		if err != nil {
			t.Fatal(err)
		}
		if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
			t.Fatal("one valid caller hid another function's private access")
		}
	})
}

func TestGoAMD64FixedLocalOutgoingABI0ForwardGuards(t *testing.T) {
	for _, test := range []struct {
		name, old, replacement string
	}{
		{"padding store", "CALL ·Callee(SB)", "MOVB AX,1(SP)\nCALL ·Callee(SB)"},
		{"private store", "CALL ·Callee(SB)", "MOVQ AX,48(SP)\nCALL ·Callee(SB)"},
		{"extra vector access", "CALL ·Callee(SB)", "PADDL 32(SP),X0\nCALL ·Callee(SB)"},
		{"overlapping source slots", "MOVQ AX,8(SP)", "MOVQ AX,0(SP)"},
		{"wrong width", "MOVQ AX,8(SP)", "MOVL AX,8(SP)"},
		{"wrong register", "MOVQ AX,8(SP)", "MOVQ BX,8(SP)"},
		{"missing input", "MOVQ AX,8(SP)\n", ""},
		{"old result", "MOVSD 16(SP),X1", "MOVSD 8(SP),X1"},
		{"SP escape", "CALL ·Callee(SB)", "MOVQ SP,R11\nCALL ·Callee(SB)"},
		{"SP write", "CALL ·Callee(SB)", "ADDQ $16,SP\nCALL ·Callee(SB)"},
		{"BP alias", "MOVQ AX,8(SP)", "MOVQ AX,-56(BP)"},
		{"indexed access", "MOVQ AX,8(SP)", "MOVQ AX,8(SP)(CX*1)"},
		{"flags across call", "CALL ·Callee(SB)", "CMPQ AX,AX\nCALL ·Callee(SB)\nSETCS CL"},
		{"branch", "CALL ·Callee(SB)", "JMP next\nnext:\nCALL ·Callee(SB)"},
		{"indirect", "CALL ·Callee(SB)", "CALL AX"},
		{"internal ABI", "CALL ·Callee(SB)", "CALL ·Callee<ABIInternal>(SB)"},
		{"missing callee", "CALL ·Callee(SB)", "CALL ·Missing(SB)"},
		{"frame overflow", "$64-24", "$16-24"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, options, source := x86OutgoingCandidateFixture(t, "a uint8,b uint64", "MOVBLZX", []string{"First", "Callee"})
			if !strings.Contains(source, test.old) {
				t.Fatalf("negative control did not mutate its source: %q", test.old)
			}
			source = strings.Replace(source, test.old, test.replacement, 1)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") || !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
				t.Fatal("unclosed frame or call silently bypassed its original candidate")
			}
		})
	}
	for _, change := range []string{"zero options", "duplicate options", "custom caller", "custom callee", "overlapping callee", "missing slot"} {
		t.Run(change, func(t *testing.T) {
			file, options, _ := x86OutgoingCandidateFixture(t, "a uint8,b uint64", "MOVBLZX", []string{"Callee"})
			provided := []Options{options}
			switch change {
			case "zero options":
				provided = []Options{{}}
			case "duplicate options":
				provided = append(provided, options)
			case "custom caller", "custom callee":
				name := "outgoing.Callee"
				if change == "custom caller" {
					name = "outgoing.Caller"
				}
				sig := options.Sigs[name]
				sig.ArgRegs = []Reg{AX, BX}
				options.Sigs[name] = sig
			case "overlapping callee":
				sig := options.Sigs["outgoing.Callee"]
				sig.Frame.Params[1].Offset = 0
				options.Sigs[sig.Name] = sig
			case "missing slot":
				sig := options.Sigs["outgoing.Callee"]
				sig.Frame.Params = sig.Frame.Params[:1]
				options.Sigs[sig.Name] = sig
			}
			if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", provided...) {
				t.Fatal("ambiguous or nonordinary declarations disabled the native-frame candidate")
			}
		})
	}
}

func TestGoAMD64FixedLocalOutgoingExtensionFamily(t *testing.T) {
	for _, opcode := range []Op{
		"MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX", "MOVBQSX", "MOVBQZX",
		"MOVWLSX", "MOVWLZX", "MOVWQSX", "MOVWQZX", "MOVLQSX", "MOVLQZX", "MOVSWW", "MOVZWW",
	} {
		t.Run(string(opcode), func(t *testing.T) {
			spec := amd64ScalarExtensionMoveSpecs[opcode]
			parameters := fmt.Sprintf("a uint%d", spec.sourceBits)
			file, options, source := x86OutgoingCandidateFixture(t, parameters, string(opcode), []string{"Callee"})
			requireX86OutgoingCandidateGoSource(t, source)
			if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
				t.Fatal("shared widening move did not preserve its exact outgoing low bytes")
			}
		})
	}
}

func TestGoAMD64FixedLocalOutgoingCompleteSlotGuards(t *testing.T) {
	t.Run("missing aggregate field", func(t *testing.T) {
		_, options, source := x86OutgoingCandidateFixture(t, "a struct { X uint8; Y uint64 }", "", []string{"Callee"})
		for _, name := range []string{"Caller", "Callee"} {
			sig := options.Sigs["outgoing."+name]
			sig.Frame.Params = sig.Frame.Params[:1]
			options.Sigs[sig.Name] = sig
		}
		const missing = "MOVQ arg1+8(FP),AX\nMOVQ AX,8(SP)\n"
		if !strings.Contains(source, missing) {
			t.Fatal("aggregate negative did not remove its second field")
		}
		source = strings.Replace(source, missing, "", 1)
		requireX86OutgoingCandidateGoSource(t, source)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
			t.Fatal("one aggregate leaf was mistaken for its complete argument")
		}
	})
	t.Run("duplicate result destination", func(t *testing.T) {
		options, source := x86OutgoingMultipleResultsFixture(t, 8, 8)
		requireX86OutgoingCandidateGoSource(t, source)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
			t.Fatal("two stores to one result were mistaken for complete result forwarding")
		}
	})
}

func x86OutgoingMultipleResultsFixture(t *testing.T, firstOffset, secondOffset int) (Options, string) {
	t.Helper()
	_, options, source := x86OutgoingCandidateFixture(t, "a uint64", "", []string{"Callee"})
	for _, name := range []string{"Caller", "Callee"} {
		sig := options.Sigs["outgoing."+name]
		sig.Ret = "{ double, double }"
		second := sig.Frame.Results[0]
		second.Index, second.Offset = 1, 16
		sig.Frame.Results = append(sig.Frame.Results, second)
		options.Sigs[sig.Name] = sig
	}
	source = strings.Replace(source, "$64-16", "$64-24", 1)
	source = strings.Replace(source, "ret+8(FP)", fmt.Sprintf("ret+%d(FP)", firstOffset), 1)
	source = strings.Replace(source, "RET\n", fmt.Sprintf("MOVSD 16(SP),X1\nMOVSD X1,ret+%d(FP)\nRET\n", secondOffset), 1)
	return options, source
}

func TestGoAMD64FixedLocalOutgoingMultipleResults(t *testing.T) {
	for _, offsets := range [][2]int{{8, 16}, {16, 8}} {
		t.Run(fmt.Sprint(offsets), func(t *testing.T) {
			options, source := x86OutgoingMultipleResultsFixture(t, offsets[0], offsets[1])
			requireX86OutgoingCandidateGoSource(t, source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if GoAMD64FixedLocalFrameBindingNeeded(file, "amd64", options) {
				t.Fatal("complete distinct result destinations lost their ordinary call route")
			}
		})
	}
}

func TestGoAMD64FixedLocalOutgoingLayoutBoundaries(t *testing.T) {
	for _, typ := range []LLVMType{"{}", "[0 x i64]", "%unknown"} {
		t.Run(string(typ), func(t *testing.T) {
			if x86ABI0ForwardLayout(FuncSig{Args: []LLVMType{typ}, Ret: Void}, 8) {
				t.Fatal("unsupported empty or named type acquired a complete frame role")
			}
		})
	}
	for _, typ := range []LLVMType{"[2 x i64]", "[18446744073709551615 x i64]"} {
		t.Run(string(typ), func(t *testing.T) {
			sig := FuncSig{Args: []LLVMType{typ}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Type: I64, Index: 0, Field: 0}}}}
			if x86ABI0ForwardLayout(sig, 8) {
				t.Fatal("one array element was mistaken for the complete bounded inventory")
			}
		})
	}
}
