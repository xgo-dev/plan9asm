package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86MixedBoolResultSource(t *testing.T, arch, other string, boolFirst bool) (string, string) {
	t.Helper()
	results := other + ",bool"
	if boolFirst {
		results = "bool," + other
	}
	declaration := "func Value() (" + results + ")"
	_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
	var body strings.Builder
	body.WriteString("MOVL $2,AX\n")
	for index, slot := range sig.Frame.Results {
		if slot.Type == I1 {
			fmt.Fprintf(&body, "MOVB AX,ret%d+%d(FP)\n", index, slot.Offset)
			continue
		}
		width := x86FrameScalarBytes(slot.Type, arch)
		if width == 8 && arch == "386" {
			fmt.Fprintf(&body, "MOVL $0,ret%d+%d(FP)\nMOVL $0,ret%d+%d(FP)\n", index, slot.Offset, index, slot.Offset+4)
		} else {
			move := map[int64]string{1: "MOVB", 2: "MOVW", 4: "MOVL", 8: "MOVQ"}[width]
			if move == "" {
				t.Fatal("actual mixed result field is no longer scalar")
			}
			fmt.Fprintf(&body, "%s $0,ret%d+%d(FP)\n", move, index, slot.Offset)
		}
	}
	_, _, _, source := x86ResultInitializationFixture(t, arch, declaration, body.String()+"RET")
	return source, declaration
}

func TestX86MixedBoolResultCompleteScalarPartnersThreeAPIs(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, other := range []string{"uint8", "uint16", "uint32", "uint64", "float32", "float64"} {
			for _, boolFirst := range []bool{false, true} {
				source, declaration := x86MixedBoolResultSource(t, target.arch, other, boolFirst)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/bool-first=%t/%s", target.triple, other, boolFirst, api), func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\n"+declaration+"\n", target.arch, target.triple)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("mixed bool initialized raw2 became canonical without a result role: output=%t error=%v", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestX86MixedBoolResultRoleCannotDropDeclaredOrModeledBool(t *testing.T) {
	boolean := []FrameSlot{{Type: I1}}
	integer := []FrameSlot{{Type: I32}}
	for _, test := range []struct {
		name              string
		ret               LLVMType
		declared, modeled []FrameSlot
		needs             bool
	}{
		{"scalar-register", I1, nil, nil, false},
		{"scalar-frame", I1, boolean, boolean, false},
		{"void-existing-role", Void, boolean, boolean, false},
		{"integer", I32, integer, integer, false},
		{"integer-not-i1-prefix", "{ i16, i128 }", nil, nil, false},
		{"aggregate-missing-layout", "{ i1, i32 }", nil, nil, true},
		{"aggregate-masked-layout", "{ i1, i32 }", integer, integer, true},
		{"nested-bool", "{ i32, [2 x i1] }", nil, nil, true},
		{"declared-bool", I32, boolean, integer, true},
		{"modeled-bool", I32, integer, boolean, true},
		{"scalar-dropped-model", I1, boolean, nil, true},
		{"scalar-dropped-declaration", I1, nil, boolean, true},
		{"scalar-wrong-layout", I1, integer, integer, true},
		{"scalar-multiple-fields", I1, append(append([]FrameSlot(nil), boolean...), integer...), boolean, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sig := FuncSig{Ret: test.ret, Frame: FrameLayout{Results: test.declared}}
			if got := x86MixedBoolResultNeedsCanonicalRole(sig, test.modeled); got != test.needs {
				t.Fatalf("canonical role needed=%t, want %t", got, test.needs)
			}
		})
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch+"/copied-proof-pointer", func(t *testing.T) {
			slots := []FrameSlot{{Type: I1}, {Type: I32, Offset: 4}}
			c := amd64Ctx{goarch: arch, sig: FuncSig{Ret: "{ i1, i32 }", Frame: FrameLayout{Results: slots}}, fpResults: slots}
			c.fpScalarSource.x86FixedLocal = &x86FixedLocalProof{}
			if err := c.validateMixedBoolResultRole(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("copied fixed-local pointer granted canonical fields: %v", err)
			}
		})
	}
}

func TestX86MixedBoolResultOrdinaryCanonicalThreeAPIs(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, boolFirst := range []bool{false, true} {
			declaration := "func Value(n uint32, x bool) (uint32, bool)"
			input, boolean, number := 4, 12, 8
			if boolFirst {
				declaration = "func Value(x bool, n uint32) (bool, uint32)"
				input, boolean, number = 0, 8, 12
			}
			copyBool := fmt.Sprintf("MOVB x+%d(FP),AX\nMOVB AX,ret+%d(FP)\n", input, boolean)
			storeBool := func(value int) string {
				return fmt.Sprintf("MOVB $%d,ret+%d(FP)\n", value, boolean)
			}
			storeNumber := fmt.Sprintf("MOVL $7,ret+%d(FP)\n", number)
			roundtrip := storeBool(2) + fmt.Sprintf("MOVL $0,AX\nMOVB ret+%d(FP),AX\nMOVL AX,ret+%d(FP)\n", boolean, number)
			for _, row := range []struct {
				name, body string
				accept     bool
			}{
				{"typed-entry-copy", copyBool + storeNumber + "RET", true},
				{"constant-zero", storeBool(0) + storeNumber + "RET", true},
				{"constant-one", storeBool(1) + storeNumber + "RET", true},
				{"physical-byte-roundtrip", roundtrip + storeBool(1) + "RET", true},
				{"canonical-join", "MOVL $1,AX\nCMPL AX,$0\nJE other\n" + storeBool(0) + "JMP end\nother:\n" + copyBool + "end:\n" + storeNumber + "RET", true},
				{"raw-two", storeBool(2) + storeNumber + "RET", false},
				{"unknown-byte", fmt.Sprintf("MOVB DX,ret+%d(FP)\n", boolean) + storeNumber + "RET", false},
				{"numeric-input-is-not-bool", fmt.Sprintf("MOVL n+%d(FP),AX\nMOVB AX,ret+%d(FP)\n", 4-input, boolean) + storeNumber + "RET", false},
				{"noncanonical-join", "MOVL $1,AX\nCMPL AX,$0\nJE other\n" + storeBool(2) + "JMP end\nother:\n" + copyBool + "end:\n" + storeNumber + "RET", false},
				{"missing-number", copyBool + "RET", false},
				{"partial-number", copyBool + fmt.Sprintf("MOVB $7,ret+%d(FP)\nRET", number), false},
				{"overwritten-canonical", copyBool + storeBool(2) + storeNumber + "RET", false},
				{"dead-unknown-effect", copyBool + storeNumber + "JMP end\nCALL ·unknown(SB)\nend:\nRET", false},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/bool-first=%t/%s/%s", target.triple, boolFirst, row.name, api), func(t *testing.T) {
						_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, row.body)
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\n"+declaration+"\n", target.arch, target.triple)
						if row.accept {
							if err != nil || ir == "" {
								t.Fatalf("canonical typed tuple rejected: output=%t error=%v", ir != "", err)
							}
							if row.name == "physical-byte-roundtrip" && !strings.Contains(ir, " = zext i8 ") {
								t.Fatal("intermediate bool byte was normalized before its numerical observation")
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("unproved tuple accepted: output=%t error=%v", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestX86MixedBoolResultOrdinaryCanonicalRoleBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			name   string
			mutate func(*Func, *FuncSig)
		}{
			{"native-frame", func(fn *Func, _ *FuncSig) { fn.FrameSize = 4 }},
			{"wrong-extent", func(fn *Func, _ *FuncSig) { fn.ArgSize++ }},
			{"register-entry", func(fn *Func, _ *FuncSig) { fn.Sym += "<ABIInternal>" }},
			{"custom-registers", func(_ *Func, sig *FuncSig) { sig.ArgRegs = []Reg{"AX"} }},
			{"borrowed-bool", func(_ *Func, sig *FuncSig) { sig.x86BorrowedBoolTail = true }},
			{"raw-text", func(fn *Func, _ *FuncSig) { fn.X86RawText = []byte{0xc3} }},
			{"source-stack", func(fn *Func, _ *FuncSig) { fn.x86SourceStack = &x86SourceStackProof{} }},
			{"fixed-local", func(fn *Func, _ *FuncSig) { fn.x86FixedLocal = &x86FixedLocalProof{} }},
			{"coalesced-flow", func(fn *Func, _ *FuncSig) { fn.x86ContinuationFlow = &x86ContinuationFlow{} }},
			{"wrong-result-type", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Type = I8 }},
			{"wrong-result-index", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Index = 1 }},
			{"nested-result", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Fields = []int{0} }},
			{"overlapping-results", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Offset = sig.Frame.Results[0].Offset }},
			{"untyped-bool-entry", func(_ *Func, sig *FuncSig) { sig.Args[0] = I8 }},
			{"overlapping-parameters", func(_ *Func, sig *FuncSig) { sig.Frame.Params[1].Offset = 0 }},
			{"unrepresented-argument", func(_ *Func, sig *FuncSig) { sig.Args = append(sig.Args, I32) }},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				_, file, sig, _ := x86ResultInitializationFixture(t, arch,
					"func Value(x bool, n uint32) (bool, uint32)",
					"MOVB x+0(FP),AX\nMOVB AX,ret+8(FP)\nMOVL $7,ret+12(FP)\nRET")
				fn := file.Funcs[0]
				row.mutate(&fn, &sig)
				c := &amd64Ctx{goarch: arch, sig: sig, fpResults: sig.Frame.Results, fpScalarSource: fn}
				if err := c.validateMixedBoolResultRole(); !errors.Is(err, ErrProbeNeedsContext) || c.fpMixedBoolBytes {
					t.Fatalf("incomplete tuple acquired canonical physical-byte storage: %v", err)
				}
			})
		}
	}
}
