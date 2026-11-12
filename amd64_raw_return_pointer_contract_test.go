package plan9asm

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are compile-only contract counterexamples, not programs that mutate a
// live return address. Go acceptance proves source grammar, never alias safety.
func x86RawReturnPointerAPIs(t *testing.T, source string, opt Options, wantContext bool) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, api := range []string{"text", "module", "owned-module", "annotated"} {
		var callErr error
		switch api {
		case "text":
			_, callErr = Translate(file, opt)
		case "module":
			module, err := TranslateModule(file, opt)
			if err == nil {
				module.Dispose()
			}
			callErr = err
		default:
			ctx := llvm.NewContext()
			options := opt
			options.AnnotateSource = api == "annotated"
			module, err := TranslateModuleInContext(ctx, file, options)
			if err == nil {
				module.Dispose()
			}
			ctx.Dispose()
			callErr = err
		}
		if wantContext && !errors.Is(callErr, ErrProbeNeedsContext) {
			t.Errorf("%s did not reject an unproved native continuation: %v", api, callErr)
		}
		if !wantContext && callErr != nil {
			t.Errorf("%s rejected a bounded FP/static leaf: %v", api, callErr)
		}
	}
}

func TestX86RawReturnPointerMemoryNeedsContinuationContract(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", 8
		if target.arch == "386" {
			move, word = "MOVL", 4
		}
		instructions := []string{
			"MOVB $0,(AX)", "MOVW $0,1(AX)", "MOVL $0,4(AX)",
			"MOVB (AX),AL", "ADDL $1,(AX)", "XCHGL AX,(AX)",
			"MOVOU X0,(AX)", "SETEQ (AX)", "BTSL $1,(AX)",
			"VMASKMOVPS X0,X1,(AX)", "VMASKMOVPD X0,X1,(AX)",
			"VPMASKMOVD X0,X1,(AX)", "VPMASKMOVQ X0,X1,(AX)",
			"VMOVDQU32 X0,K1,(AX)",
			move + " AX,BX\nMOVB $0,(BX)",
			move + " $saved<>(SB),AX\nMOVB $0,(AX)",
			"MOVB $0,saved<>(SB)(AX*1)",
			"MOVB $0,0(AX)(CX*2)",
		}
		if target.arch == "amd64" {
			instructions = append(instructions, "MOVQ $0,8(AX)")
		}
		for _, instruction := range instructions {
			t.Run(target.triple+"/"+instruction, func(t *testing.T) {
				source := fmt.Sprintf("GLOBL saved<>(SB),8,$32\nTEXT Raw(SB),4,$0-%d\n%s p+0(FP),AX\n%s\nBYTE $0xc3\nRET\n", word, move, instruction)
				// Go permits indexed static-base addressing in 386, but rejects
				// this spelling in amd64. Keep the latter as a defensive parsed
				// source negative, not a positive Go format witness.
				goAccepted := target.arch == "386" || instruction != "MOVB $0,saved<>(SB)(AX*1)"
				requireX86GoAssemblerResult(t, target.arch, source, goAccepted)
				sig := FuncSig{Name: "Raw", Args: []LLVMType{Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
				x86RawReturnPointerAPIs(t, source, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"Raw": sig}}, true)
			})
		}
	}
}

func TestX86RawReturnImplicitMemoryNeedsContinuationContract(t *testing.T) {
	instructions := []string{"XLAT", "MASKMOVQ M0,M1", "MASKMOVOU X0,X1", "MASKMOVDQU X0,X1", "VMASKMOVDQU X0,X1"}
	for op := range x86StringSpecs {
		instructions = append(instructions, string(op))
	}
	for _, op := range []string{"INSB", "INSW", "INSL", "OUTSB", "OUTSW", "OUTSL"} {
		instructions = append(instructions, op)
	}
	sort.Strings(instructions)
	for _, target := range x86RawReturnTargets {
		for _, instruction := range instructions {
			if target.arch == "386" && strings.HasSuffix(instruction, "Q") && !strings.HasPrefix(instruction, "MASK") {
				continue // Go's 32-bit string table has no Q-width forms.
			}
			t.Run(target.triple+"/"+instruction, func(t *testing.T) {
				source := "TEXT Raw(SB),4,$0-0\n" + instruction + "\nBYTE $0xc3\nRET\n"
				requireX86GoAssemblerResult(t, target.arch, source, true)
				x86RawReturnPointerAPIs(t, source, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Ret: Void}}}, true)
			})
		}
	}
}

func TestX86RawReturnFPRequiresBoundTypedSlot(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		for _, frame := range []FrameLayout{
			{}, {Params: []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}}},
		} {
			offset := 0
			if len(frame.Params) != 0 {
				offset = 100
			}
			source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s x+%d(FP),AX\nBYTE $0xc3\nRET\n", word, move, offset)
			requireX86GoAssemblerResult(t, target.arch, source, true)
			x86RawReturnPointerAPIs(t, source, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Args: []LLVMType{typ}, Ret: typ, Frame: frame}}}, true)
		}
		source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s AX,ret+%d(FP)\nBYTE $0xc3\nRET\n", 2*word, move, word)
		requireX86GoAssemblerResult(t, target.arch, source, true)
		x86RawReturnPointerAPIs(t, source, Options{Goarch: target.arch, TargetTriple: target.triple,
			Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Args: []LLVMType{typ}, Ret: typ,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: int64(word), Type: typ, Index: 1, Field: -1}}}}}}, true)
	}
}

func TestX86RawReturnMemoryRangeAndUnknownShapeNeedContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		for _, test := range []struct {
			name, instruction string
			slot              FrameSlot
		}{
			{"fp-too-narrow", move + " x+0(FP),AX", FrameSlot{Type: I8, Index: 0, Field: -1}},
			{"fp-unrecognized-type", move + " x+0(FP),AX", FrameSlot{Type: "i128", Index: 0, Field: -1}},
			{"fp-unbound-index", move + " x+0(FP),AX", FrameSlot{Type: typ, Index: 1, Field: -1}},
			{"static-before-region", "MOVL AX,saved<>-1(SB)", FrameSlot{Type: typ, Index: 0, Field: -1}},
			{"static-after-region", "MOVL AX,saved<>+32(SB)", FrameSlot{Type: typ, Index: 0, Field: -1}},
			{"static-cross-end", "MOVL AX,saved<>+30(SB)", FrameSlot{Type: typ, Index: 0, Field: -1}},
			{"static-no-object-contract", "MOVL AX,unknown(SB)", FrameSlot{Type: typ, Index: 0, Field: -1}},
		} {
			t.Run(target.triple+"/"+test.name, func(t *testing.T) {
				source := fmt.Sprintf("GLOBL saved<>(SB),8,$32\nTEXT Raw(SB),4,$0-%d\n%s\nBYTE $0xc3\nRET\n", word, test.instruction)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				x86RawReturnPointerAPIs(t, source, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Args: []LLVMType{typ}, Ret: typ,
						Frame: FrameLayout{Params: []FrameSlot{test.slot}}}}}, true)
			})
		}
	}
}

func TestX86RawReturnBoundFPAndStaticObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		for _, encoding := range []string{"BYTE $0xc3", "BYTE $0xc2\nWORD $0"} {
			for _, pointer := range []bool{false, true} {
				valueType := typ
				if pointer {
					valueType = Ptr
				}
				source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s x+0(FP),AX\n%s AX,ret+%d(FP)\n%s\nRET\n", 2*word, move, move, word, encoding)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				sig := FuncSig{Name: "Raw", Args: []LLVMType{valueType}, Ret: valueType,
					Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: valueType, Index: 0, Field: -1}},
						Results: []FrameSlot{{Offset: int64(word), Type: valueType, Index: 0, Field: -1}}}}
				opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Raw": sig}}
				x86RawReturnPointerAPIs(t, source, opt, false)
				ir, err := Translate(mustParseX86RawReturn(t, source), opt)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "fp-return.ll", "fp-return.o", ir)
			}
			source := "GLOBL saved<>(SB),8,$32\nTEXT Raw(SB),4,$0-0\nMOVL $17,AX\nMOVL AX,saved<>+4(SB)\nMOVL saved<>+4(SB),AX\n" + encoding + "\nRET\n"
			requireX86GoAssemblerResult(t, target.arch, source, true)
			opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Ret: I32}}}
			x86RawReturnPointerAPIs(t, source, opt, false)
			ir, err := Translate(mustParseX86RawReturn(t, source), opt)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "static-return.ll", "static-return.o", ir)
		}
	}
}

func TestX86RawReturnPrepartitionRetainsFinalFrameValidation(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s x+0(FP),AX\nBYTE $0xc3\nRET\n", word, move)
		file, err := NormalizeRawFileForTranslation(mustParseX86RawReturn(t, source), target.arch)
		if err != nil {
			t.Fatal("pure preparation must not discard the future typed frame:", err)
		}
		opt := Options{Goarch: target.arch, TargetTriple: target.triple,
			Sigs: map[string]FuncSig{"Raw": {Name: "Raw", Args: []LLVMType{typ}, Ret: typ}}}
		ctx := llvm.NewContext()
		module, err := TranslateModuleInContext(ctx, file, opt)
		if err == nil {
			module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("prepartition preparation erased the final missing-frame contract:", err)
		}
		sig := opt.Sigs["Raw"]
		sig.Frame.Params = []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}}
		opt.Sigs["Raw"] = sig
		ctx = llvm.NewContext()
		module, err = TranslateModuleInContext(ctx, file, opt)
		if err == nil {
			module.Dispose()
		}
		ctx.Dispose()
		if err != nil {
			t.Fatal("existing consumer's bound signature was not consumed:", err)
		}
	}
}

func TestX86RawReturnActualGoDeclarationContract(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", 8
		if target.arch == "386" {
			move, word = "MOVL", 4
		}
		for _, test := range []struct {
			name, declaration, body string
			argSize                 int
			context                 bool
		}{
			{"pointer-store", "func Raw(*byte)", move + " p+0(FP),AX\nMOVB $0,(AX)", word, true},
			{"unknown-fp", "func Raw(uintptr) uintptr", move + " p+100(FP),AX", 2 * word, true},
			{"typed-pointer-transport", "func Raw(*byte) *byte", fmt.Sprintf("%s p+0(FP),AX\n%s AX,ret+%d(FP)", move, move, word), 2 * word, false},
			{"typed-static-global", "func Raw() uint32", "MOVL $17,AX\nMOVL AX,saved<>+4(SB)\nMOVL saved<>+4(SB),AX\nMOVL AX,ret+0(FP)", 4, false},
		} {
			t.Run(target.triple+"/"+test.name, func(t *testing.T) {
				source := fmt.Sprintf("GLOBL saved<>(SB),8,$32\nTEXT ·Raw(SB),4,$0-%d\n%s\nBYTE $0xc3\nRET\n", test.argSize, test.body)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				pkg := mustGoPackage(t, "test/rawret", "package rawret\n"+test.declaration+"\n")
				options := GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple,
					ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }}
				tr, err := TranslateGoModule(pkg, []byte(source), options)
				if tr != nil {
					defer tr.Module.Dispose()
				}
				if test.context {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("a Go pointer/declaration invented a return-PC contract:", err)
					}
					return
				}
				if err != nil {
					t.Fatal("actual declaration's bounded typed frame rejected:", err)
				}
				compileLLVMToObject(t, llc, target.triple, "declared-return.ll", "declared-return.o", tr.Module.String())
			})
		}
	}
}

func mustParseX86RawReturn(t *testing.T, source string) *File {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
