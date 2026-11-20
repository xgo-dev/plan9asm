package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86RawNearReturnCompleteImmediateEncoding(t *testing.T) {
	if form := x86RawNearReturnEncoding([]byte{0xc3}); !form.nativeWidth || form.cleanup != 0 {
		t.Fatalf("C3 has no caller cleanup: %+v", form)
	}
	code := []byte{0xc2, 0, 0}
	for cleanup := 0; cleanup <= 65535; cleanup++ {
		binary.LittleEndian.PutUint16(code[1:], uint16(cleanup))
		form := x86RawNearReturnEncoding(code)
		if !form.nativeWidth || form.cleanup != uint16(cleanup) {
			t.Fatalf("C2 imm16=%d was changed: %+v", cleanup, form)
		}
	}
	for _, code := range [][]byte{nil, {0xc2}, {0xc2, 0}, {0xcb}, {0xca, 0, 0}, {0x66, 0xc3}, {0xf2, 0xc3}, {0xf3, 0xc3}, {0x48, 0xc3}} {
		if x86RawNearReturnEncoding(code).nativeWidth {
			t.Errorf("unproved/truncated near return %x became an ordinary return", code)
		}
	}
}

var x86RawReturnTargets = []struct {
	arch   string
	triple string
}{
	{"386", "i386-unknown-linux-gnu"},
	{"386", "i686-pc-windows-msvc"},
	{"amd64", "x86_64-apple-darwin"},
	{"amd64", "x86_64-unknown-linux-gnu"},
	{"amd64", "x86_64-pc-windows-msvc"},
}

func TestX86RawNearReturnNeedsNativeStackContract(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, cleanup := range []uint16{1, 4, 255, 256, 65535} {
			t.Run(fmt.Sprintf("%s/pop%d", target.triple, cleanup), func(t *testing.T) {
				// Unlike textual RET $n, these are valid Go BYTE/WORD inputs.
				// C2 pops the return PC and then adds imm16 to the caller SP.
				source := fmt.Sprintf("TEXT rawret(SB),4,$0-0\nBYTE $0xc2\nWORD $%d\nRET\n", cleanup)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"rawret": {Name: "rawret", Ret: Void}}}
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("native caller cleanup=%d must remain Context, got %v", cleanup, err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("module API lost native cleanup=%d contract, got %v", cleanup, err)
				}
				if err := ProbeInstructionSequence(ArchAMD64, target.arch, file.Funcs[0].Instrs[1:3]); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("isolated raw cleanup became an ordinary return: %v", err)
				}
			})
		}
	}
}

func TestX86RawNearReturnCannotInventGoEpilogue(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, push, pop := "MOVQ", "PUSHQ", "POPQ"
		if target.arch == "386" {
			move, push, pop = "MOVL", "PUSHL", "POPL"
		}
		for _, source := range []string{
			"TEXT rawret(SB),4,$8-0\nBYTE $0xc3\nRET\n",
			"TEXT rawret(SB),4,$0-0\n" + move + " $0,0(SP)\nBYTE $0xc3\nRET\n",
			"TEXT rawret(SB),4,$0-0\n" + push + " AX\nBYTE $0xc3\n" + pop + " AX\nRET\n",
			"TEXT rawret(SB),4,$0-0\nBYTE $0x66\nBYTE $0xc3\nRET\n",
			"TEXT rawret(SB),4,$0-0\nBYTE $0xf2\nBYTE $0xc3\nRET\n",
			"TEXT rawret(SB),4,$0-0\nBYTE $0xf3\nBYTE $0xc3\nRET\n",
		} {
			requireX86GoAssemblerResult(t, target.arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawret": {Name: "rawret", Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s raw machine return cannot acquire a Go epilogue or normal stack width; got %v\n%s", target.triple, err, source)
			}
		}
	}
}

func x86RawStackObservingFormProbeFile(t *testing.T, arch, symbol string, code []byte) *File {
	t.Helper()
	return x86RawUnprovedReturnFormProbeFile(t, arch, symbol, code)
}

// Retain the original Go encoder object as a negative return-contract test.
// A compile-only operand probe ends in UD2: it cannot promise a caller return
// after observing a physical stack or dereferencing unbound native pointers.
// Every preceding instruction byte is unchanged. These objects prove operand
// lowering, not execution of the original machine-entry function.
func x86RawUnprovedReturnFormProbeFile(t *testing.T, arch, symbol string, code []byte) *File {
	t.Helper()
	if len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatalf("Go form fixture must end in its ordinary encoded RET, got %x", code)
	}
	makeFile := func(bytes []byte) *File {
		var source strings.Builder
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", symbol)
		for _, value := range bytes {
			fmt.Fprintf(&source, "BYTE $%#02x\n", value)
		}
		requireX86GoAssemblerResult(t, arch, source.String(), true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	original := makeFile(code)
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	_, err := Translate(original, Options{Goarch: arch, TargetTriple: triple,
		Sigs: map[string]FuncSig{symbol: {Name: symbol, Ret: Void}}})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("original format fixture must retain its native return-contract failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "source stack/continuation") &&
		!strings.Contains(err.Error(), "bounded typed FP/static memory") {
		t.Fatalf("unrelated Context error is not a native return-contract witness: %v", err)
	}
	probe := append(append([]byte(nil), code[:len(code)-1]...), 0x0f, 0x0b)
	return makeFile(probe)
}

func TestX86RawUnprovedReturnFormProbePreservesInstructions(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		for _, instruction := range []string{"MOVL (AX),CX", "MOVL CX,(AX)"} {
			t.Run(target.triple+"/"+instruction, func(t *testing.T) {
				code := assembleX87ControlBytes(t, target.arch,
					"TEXT form(SB),4,$0-0\n"+instruction+"\nRET\n")
				original := append([]byte(nil), code...)
				file := x86RawUnprovedReturnFormProbeFile(t, target.arch, "form", code)
				if string(code) != string(original) {
					t.Fatal("form probe modified its independent Go encoder input")
				}
				body := file.Funcs[0].Instrs[1:]
				if len(body) != len(code)+1 {
					t.Fatalf("probe directives=%d, want %d", len(body), len(code)+1)
				}
				want := append(append([]byte(nil), code[:len(code)-1]...), 0x0f, 0x0b)
				for index, ins := range body {
					if ins.Op != OpBYTE || len(ins.Args) != 1 ||
						ins.Args[0].Kind != OpImm || ins.Args[0].Imm != int64(want[index]) {
						t.Fatalf("changed operand-form byte %d: %+v, want %#x", index, ins, want[index])
					}
				}
				// Replacing the unproved return with UD2 does not initialize
				// AX/CX or authorize the preceding native load/store. Retain
				// the public Context controls and private operand-format object.
				ir := x86UnboundVoidRawProbeObject(t, file, target.arch, target.triple)
				if !strings.Contains(ir, `asm sideeffect "ud2"`) || !strings.Contains(ir, "unreachable") {
					t.Fatal("compile-only form probe invented an ordinary caller return")
				}
				compileLLVMToObject(t, llc, target.triple, "memory-form.ll", "memory-form.o", ir)
			})
		}
	}
}

func TestX86RawNearReturnZeroCleanupLeafObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		for _, encoding := range []string{"BYTE $0xc3", "BYTE $0xc2\nWORD $0"} {
			t.Run(target.triple+"/"+strings.ReplaceAll(encoding, "\n", ";"), func(t *testing.T) {
				source := "TEXT rawret(SB),4,$0-0\nMOVL $17,AX\n" + encoding + "\nRET\n"
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, Options{
					Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"rawret": {Name: "rawret", Ret: I32}},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer module.Dispose()
				compileLLVMToObject(t, llc, target.triple, "raw-near-ret.ll", "raw-near-ret.o", module.String())
			})
		}
	}
}
