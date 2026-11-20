package plan9asm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86AddressSensitiveFrameSource(arch, text string) string {
	address := "LEAQ"
	if arch == "386" {
		address = "LEAL"
	}
	return fmt.Sprintf("TEXT refer(SB),4,$0-0\n%s blob(SB),AX\nRET\nTEXT blob(SB),%s\nBYTE $0xc3\n", address, text)
}

func requireX86RawTextContextAPIs(t *testing.T, file *File, opt Options) {
	t.Helper()
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
		if !errors.Is(callErr, ErrProbeNeedsContext) {
			t.Errorf("%s omitted raw TEXT's source prologue/Go-frame contract: %v", api, callErr)
		}
	}
}

func TestX86AddressSensitiveRawTextNeedsSourceFrameContract(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, text := range []string{"4,$8-0", "4,$16-0", "4,$0-8", "32,$0-0"} {
			t.Run(target.triple+"/"+text, func(t *testing.T) {
				source := x86AddressSensitiveFrameSource(target.arch, text)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				requireX86RawTextContextAPIs(t, file, Options{
					Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"refer": {Name: "refer", Ret: Void}, "blob": {Name: "blob", Ret: Void}},
				})
			})
		}
	}
}

func TestX86AddressSensitiveRawTextCannotBypassGoFrameTransport(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, sig := range []FuncSig{
			{Name: "blob", Ret: Void, Args: []LLVMType{I32}, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I32, Field: -1}}}},
			{Name: "blob", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Field: -1}}}},
		} {
			t.Run(target.triple+"/"+string(sig.Ret), func(t *testing.T) {
				source := x86AddressSensitiveFrameSource(target.arch, "4,$0-0")
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				requireX86RawTextContextAPIs(t, file, Options{
					Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"refer": {Name: "refer", Ret: Void}, "blob": sig},
				})
			})
		}
	}
}

func TestX86AddressSensitiveRawText386CannotOmitStackSplit(t *testing.T) {
	// obj6's automatic NOSPLIT leaf promotion is amd64-only. An unflagged
	// 386 TEXT has real TLS/stack-check bytes before the raw source body.
	plain := assembleX87ControlBytes(t, "386", "TEXT blob(SB),$0-0\nBYTE $0xc3\n")
	nosplit := assembleX87ControlBytes(t, "386", "TEXT blob(SB),4,$0-0\nBYTE $0xc3\n")
	if len(nosplit) != 1 || nosplit[0] != 0xc3 || len(plain) <= len(nosplit) {
		t.Fatalf("Go source prologue witness is not independent: plain=%x NOSPLIT=%x", plain, nosplit)
	}
	t.Logf("actual Go 386 source TEXT bytes: unflagged=%x NOSPLIT=%x", plain, nosplit)
	file, err := Parse(ArchAMD64, x86AddressSensitiveFrameSource("386", "$0-0"))
	if err != nil {
		t.Fatal(err)
	}
	requireX86RawTextContextAPIs(t, file, Options{
		Goarch: "386", TargetTriple: "i386-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"refer": {Name: "refer", Ret: Void}, "blob": {Name: "blob", Ret: Void}},
	})
}

func TestX86AddressSensitiveRawTextFramelessBytesRemainExact(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		flags := []string{"4,$0-0", "6,$0-0", "516,$0-0"}
		if target.arch == "amd64" {
			// obj6 promotes this raw-only, zero-frame amd64 leaf to NOSPLIT.
			flags = append(flags, "$0-0")
		}
		for _, text := range flags {
			t.Run(target.triple+"/"+text, func(t *testing.T) {
				original := assembleX87ControlBytes(t, target.arch, "TEXT blob(SB),"+text+"\nBYTE $0xc3\n")
				if len(original) != 1 || original[0] != 0xc3 {
					t.Fatalf("source Go TEXT unexpectedly adds a native prologue: %x", original)
				}
				file, err := Parse(ArchAMD64, x86AddressSensitiveFrameSource(target.arch, text))
				if err != nil {
					t.Fatal(err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, Options{
					Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"refer": {Name: "refer", Ret: Void}, "blob": {Name: "blob", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer module.Dispose()
				compileLLVMToObject(t, llc, target.triple, "frameless-raw-text.ll", "frameless-raw-text.o", module.String())
				assertX86RawTextAssemblyBytes(t, llc, target.triple, module.String(), original)
			})
		}
	}
}
