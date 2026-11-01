package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARMFPAddressRequiresBoundStorage(t *testing.T) {
	for _, arch := range []Arch{ArchARM, ArchARM64} {
		for _, op := range []Operand{
			{Kind: OpFPAddr, FPName: "argframe", FPOffset: 0},
			{Kind: OpFPAddr, FPName: "argframe", FPOffset: 99},
			{Kind: OpFPAddr, FPName: "sp", FPOffset: -4},
			{Kind: OpFPAddr, FPName: "SP", FPOffset: -4},
			{Kind: OpFPAddr, FPName: "sp", FPOffset: -8},
			{Kind: OpFPAddr, FPName: "missing", FPOffset: 16},
		} {
			t.Run(string(arch)+"/"+op.String(), func(t *testing.T) {
				var output strings.Builder
				sig := FuncSig{Name: "address", Ret: Void}
				var value string
				var err error
				if arch == ArchARM {
					c := newARMCtx(&output, Func{}, sig, testResolveSym("example"), nil, false)
					value, err = c.evalFPAddr32(op)
				} else {
					c := newARM64Ctx(&output, Func{}, sig, testResolveSym("example"), nil, false)
					value, err = c.evalFPAddr64(op)
				}
				if !errors.Is(err, ErrProbeNeedsContext) || value != "" {
					t.Fatalf("unbound FP address must not become a zero pointer: (%q, %v)", value, err)
				}
				if output.Len() != 0 {
					t.Fatalf("unbound FP address emitted IR: %s", output.String())
				}
			})
		}
	}
}

func TestARMFPAddressDeclaredSlotNeedsBacking(t *testing.T) {
	// A slot declaration alone is not storage. The lowering must have emitted
	// the typed backing before taking its address.
	sig := FuncSig{Name: "address", Args: []LLVMType{I32}, Ret: I32, Frame: FrameLayout{
		Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
		Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
	}}
	for _, arch := range []Arch{ArchARM, ArchARM64} {
		for _, off := range []int64{0, 4} {
			t.Run(fmt.Sprintf("%s/%d", arch, off), func(t *testing.T) {
				var output strings.Builder
				op := Operand{Kind: OpFPAddr, FPName: "declared", FPOffset: off}
				var err error
				if arch == ArchARM {
					c := newARMCtx(&output, Func{}, sig, testResolveSym("example"), nil, false)
					_, err = c.evalFPAddr32(op)
				} else {
					c := newARM64Ctx(&output, Func{}, sig, testResolveSym("example"), nil, false)
					_, err = c.evalFPAddr64(op)
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("a declaration without backing must retain context failure: %v", err)
				}
			})
		}
	}
}

func TestTranslateARMUnboundFPAddressesRetainContext(t *testing.T) {
	for _, arch := range []Arch{ArchARM, ArchARM64} {
		goarch, move, triple := "arm", "MOVW", "armv7-unknown-linux-gnueabihf"
		if arch == ArchARM64 {
			goarch, move, triple = "arm64", "MOVD", "aarch64-unknown-linux-gnu"
		}
		for _, address := range []string{"$argframe(FP)", "$argframe+99(FP)", "$sp-4(FP)", "$sp-8(FP)", "$missing+16(FP)"} {
			t.Run(goarch+"/"+address, func(t *testing.T) {
				// Keep the original caller-SP source, including its TEXT and RET.
				// Go accepts the address spelling; that does not supply LLVM with
				// a caller-owned frame or justify replacing its address with zero.
				source := "TEXT address(SB),NOSPLIT,$8-0\n\t" + move + " " + address + ", R7\n\tRET\n"
				// The existing Go object helper does not include textflag.h;
				// provide its NOSPLIT value without rewriting the parsed source.
				goSource := "#define NOSPLIT 4\n" + source
				if arch == ArchARM {
					requireARMGoAssemblerResult(t, goSource, true)
				} else {
					requireARM64GoAssemblerResult(t, goSource, true)
				}
				file, err := Parse(arch, source)
				if err != nil {
					t.Fatal(err)
				}
				instruction := file.Funcs[0].Instrs[1]
				if err := ProbeInstruction(arch, goarch, instruction); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("single-instruction FP probe lost its frame context: %v", err)
				}
				if err := ProbeInstructionSequence(arch, goarch, []Instr{instruction}); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "bound typed frame storage") {
					t.Errorf("FP address sequence lost its unbound-storage context: %v", err)
				}
				options := Options{Goarch: goarch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"address": {Name: "address", Ret: Void}},
				}
				if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "bound typed frame storage") {
					t.Errorf("full source translation accepted an unbound FP address: %v", err)
				}
				module, err := TranslateModule(file, options)
				if err == nil {
					module.Dispose()
					t.Error("module translation accepted an unbound FP address")
				}
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "bound typed frame storage") {
					t.Fatalf("module translation lost the FP address context: %v", err)
				}
			})
		}
	}
}

func TestTranslateARMFPAddressesTypedStorageLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, arch := range []Arch{ArchARM, ArchARM64} {
		goarch, move, word, typ := "arm", "MOVW", 4, I32
		triples := []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"}
		if arch == ArchARM64 {
			goarch, move, word, typ = "arm64", "MOVD", 8, I64
			triples = []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"}
		}
		// Binding is by the typed offset, not a name-based whitelist: the old
		// argframe/sp spellings must use real backing when a slot is supplied.
		source := fmt.Sprintf(`TEXT address(SB),4,$8-%d
	%s $value+0(FP), R0
	%s $result+%d(FP), R1
	%s $argframe(FP), R2
	%s $sp+%d(FP), R3
	%s $7, R0
	%s R0, result+%d(FP)
	RET
`, 2*word, move, move, word, move, move, word, move, move, word)
		if arch == ArchARM {
			requireARMGoAssemblerResult(t, source, true)
		} else {
			requireARM64GoAssemblerResult(t, source, true)
		}
		file, err := Parse(arch, source)
		if err != nil {
			t.Fatal(err)
		}
		sig := FuncSig{Name: "address", Args: []LLVMType{typ}, Ret: typ, Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: int64(word), Type: typ, Index: 0, Field: -1}},
		}}
		for _, triple := range triples {
			t.Run(triple, func(t *testing.T) {
				ir, err := Translate(file, Options{Goarch: goarch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"address": sig},
				})
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.Count(ir, "ptrtoint ptr %fp_"); got != 4 {
					t.Fatalf("typed FP addresses must use four actual backing addresses, got %d:\n%s", got, ir)
				}
				compileLLVMToObject(t, llc, triple, "typed-fp-address.ll", "typed-fp-address.o", ir)
			})
		}
	}
}
