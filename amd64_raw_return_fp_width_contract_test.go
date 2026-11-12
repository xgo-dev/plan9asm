package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86RawReturnScalarFrame(word int, typ LLVMType) FuncSig {
	return FuncSig{Name: "Raw", Args: []LLVMType{typ}, Ret: typ,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: int64(word), Type: typ, Index: 0, Field: -1}},
		}}
}

// A byte/word write to a wider FP slot must preserve the untouched bytes.
// The bounded raw-return contract does not establish that partial-width
// lowering, even when the access is inside the declared scalar's bounds.
// These original returning sources are never executed or rewritten as passes.
func TestX86RawReturnPartialFPAccessNeedsContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		partialMoves := []string{"MOVB", "MOVW"}
		if word == 8 {
			partialMoves = append(partialMoves, "MOVL")
		}
		for _, partial := range partialMoves {
			for _, access := range []string{
				partial + " $17,x+0(FP)\n" + move + " x+0(FP),AX",
				partial + " x+0(FP),AX",
				fmt.Sprintf("%s $17,ret+%d(FP)", partial, word),
				fmt.Sprintf("%s ret+%d(FP),AX", partial, word),
			} {
				for _, encoding := range []string{"BYTE $0xc3", "BYTE $0xc2\nWORD $0"} {
					t.Run(target.triple+"/"+access+"/"+encoding, func(t *testing.T) {
						source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s\n%s\nRET\n", 2*word, access, encoding)
						requireX86GoAssemblerResult(t, target.arch, source, true)
						opt := Options{Goarch: target.arch, TargetTriple: target.triple,
							Sigs: map[string]FuncSig{"Raw": x86RawReturnScalarFrame(word, typ)}}
						x86RawReturnPointerAPIs(t, source, opt, true)
					})
				}
			}
		}
	}
}

func TestX86RawReturnActualGoDeclarationRejectsPartialFPStore(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word, declaration := "MOVQ", 8, "func Raw(x uint64) uint64"
		if target.arch == "386" {
			move, word, declaration = "MOVL", 4, "func Raw(x uint32) uint32"
		}
		source := fmt.Sprintf("TEXT ·Raw(SB),4,$0-%d\nMOVB $17,x+0(FP)\n%s x+0(FP),AX\n%s AX,ret+%d(FP)\nBYTE $0xc3\nRET\n", 2*word, move, move, word)
		requireX86GoAssemblerResult(t, target.arch, source, true)
		pkg := mustGoPackage(t, "test/rawret", "package rawret\n"+declaration+"\n")
		options := GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple,
			ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }}
		ctx := llvm.NewContext()
		translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), options)
		if translation != nil {
			translation.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s actual declaration authorized an unproved partial FP store: %v", target.triple, err)
		}
	}
}

func TestX86RawReturnFrameSlotMustMatchSignature(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		for _, test := range []struct {
			name   string
			mutate func(*FuncSig)
		}{
			{"overlap-parameter", func(sig *FuncSig) {
				sig.Args = append(sig.Args, I32)
				sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(word / 2), Type: I32, Index: 1, Field: -1})
			}},
			{"overlap-result", func(sig *FuncSig) { sig.Frame.Results[0].Offset = int64(word / 2) }},
			{"parameter-type", func(sig *FuncSig) { sig.Args[0] = I8 }},
			{"parameter-scalar-field", func(sig *FuncSig) { sig.Frame.Params[0].Field = 0 }},
			{"parameter-scalar-path", func(sig *FuncSig) { sig.Frame.Params[0].Fields = []int{0} }},
			{"parameter-field-type", func(sig *FuncSig) {
				sig.Args[0] = LLVMType("{ i8, ptr }")
				sig.Frame.Params[0].Field = 0
			}},
			{"parameter-field-index", func(sig *FuncSig) {
				sig.Args[0] = LLVMType("{ ptr, " + string(typ) + " }")
				sig.Frame.Params[0].Field = 2
			}},
			{"parameter-negative-path", func(sig *FuncSig) {
				sig.Args[0] = LLVMType("{ ptr, " + string(typ) + " }")
				sig.Frame.Params[0].Fields = []int{-1}
			}},
			{"parameter-nested-path", func(sig *FuncSig) {
				sig.Args[0] = LLVMType("{ ptr, " + string(typ) + " }")
				sig.Frame.Params[0].Fields = []int{1, 0}
			}},
			{"result-type", func(sig *FuncSig) { sig.Ret = I8 }},
			{"result-scalar-field", func(sig *FuncSig) { sig.Frame.Results[0].Field = 0 }},
			{"result-scalar-path", func(sig *FuncSig) { sig.Frame.Results[0].Fields = []int{0} }},
			{"result-tuple-type", func(sig *FuncSig) { sig.Ret = "{ i8, ptr }" }},
			{"result-tuple-field", func(sig *FuncSig) {
				sig.Ret = LLVMType("{ " + string(typ) + ", ptr }")
				sig.Frame.Results[0].Field = 1
			}},
		} {
			t.Run(target.triple+"/"+test.name, func(t *testing.T) {
				source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s x+0(FP),AX\n%s AX,ret+%d(FP)\nBYTE $0xc3\nRET\n", 2*word, move, move, word)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				sig := x86RawReturnScalarFrame(word, typ)
				test.mutate(&sig)
				x86RawReturnPointerAPIs(t, source, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"Raw": sig}}, true)
			})
		}
	}
}

func TestX86RawReturnBoundAggregateScalarSlotObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		move, word, typ := "MOVQ", 8, I64
		if target.arch == "386" {
			move, word, typ = "MOVL", 4, I32
		}
		for _, explicitPath := range []bool{false, true} {
			for _, tupleResult := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/path%t/tuple%t", target.triple, explicitPath, tupleResult), func(t *testing.T) {
					source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s x+%d(FP),AX\n%s AX,ret+%d(FP)\nBYTE $0xc3\nRET\n", 3*word, move, word, move, 2*word)
					requireX86GoAssemblerResult(t, target.arch, source, true)
					sig := FuncSig{Name: "Raw", Args: []LLVMType{LLVMType("{ ptr, " + string(typ) + " }")}, Ret: typ,
						Frame: FrameLayout{
							Params:  []FrameSlot{{Offset: int64(word), Type: typ, Index: 0, Field: 1}},
							Results: []FrameSlot{{Offset: int64(2 * word), Type: typ, Index: 0, Field: -1}},
						}}
					if explicitPath {
						sig.Frame.Params[0].Field = -1
						sig.Frame.Params[0].Fields = []int{1}
					}
					if tupleResult {
						sig.Ret = LLVMType("{ ptr, " + string(typ) + " }")
						sig.Frame.Results = []FrameSlot{
							{Offset: int64(2 * word), Type: Ptr, Index: 0, Field: -1},
							{Offset: int64(3 * word), Type: typ, Index: 1, Field: -1},
						}
						source = fmt.Sprintf("TEXT Raw(SB),4,$0-%d\n%s x+%d(FP),AX\n%s $0,ret0+%d(FP)\n%s AX,ret1+%d(FP)\nBYTE $0xc3\nRET\n", 4*word, move, word, move, 2*word, move, 3*word)
						requireX86GoAssemblerResult(t, target.arch, source, true)
					}
					opt := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Raw": sig}}
					x86RawReturnPointerAPIs(t, source, opt, false)
					ir, err := Translate(mustParseX86RawReturn(t, source), opt)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "bound-field.ll", "bound-field.o", ir)
				})
			}
		}
	}
}

// Object evidence only: this independent UD2 harness cannot return to a caller
// and is never executed. It exposes existing generic partial FP lowering; a
// compiled object does not certify preservation of bytes outside the write.
func TestX86PartialFPStoreCompileOnlyEvidence(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, typ := 8, I64
			if target.arch == "386" {
				word, typ = 4, I32
			}
			source := fmt.Sprintf("TEXT Raw(SB),4,$0-%d\nMOVB $17,x+0(FP)\nUD2\nRET\n", 2*word)
			dir := t.TempDir()
			asm, object := filepath.Join(dir, "partial.s"), filepath.Join(dir, "partial.o")
			if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("go", "tool", "asm", "-p", "example.com/partial", "-o", object, asm)
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+target.arch)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Go assembler failed: %v\n%s", err, out)
			}
			out, err := exec.Command("go", "tool", "objdump", "-s", "Raw", object).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "MOVB $0x11") {
				t.Fatalf("Go object did not retain the one-byte write: %v\n%s", err, out)
			}
			t.Logf("actual Go object, not executed:\n%s", out)
			ir, err := Translate(mustParseX86RawReturn(t, source), Options{
				Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"Raw": x86RawReturnScalarFrame(word, typ)},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(ir, "\n") {
				if strings.Contains(line, "17") || strings.Contains(line, "fp_arg") || strings.Contains(line, "zext i8") ||
					strings.Contains(line, "store "+string(typ)+" %") || strings.Contains(line, "classic_frame") {
					t.Log("generic lowering observation (not a semantic pass):", line)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "partial-compile-only.ll", "partial-compile-only.o", ir)
		})
	}
}
