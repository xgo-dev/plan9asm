package plan9asm

import (
	"errors"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86RawReturnStackAddressAndRegisterViewsNeedContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		instructions := []string{
			move + " $0(SP),AX", move + " $8(BP),AX",
			move + " $0(SP)(CX*1),AX", move + " $8(AX)(BP*1),AX",
		}
		if arch == "amd64" {
			instructions = append(instructions, "MOVB $0,BPB", "MOVB BPB,AL")
		}
		for _, instruction := range instructions {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT probe(SB),4,$0-0\n" + instruction + "\nBYTE $0xc3\nRET\n"
				requireX86GoAssemblerResult(t, arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"probe": {Name: "probe", Ret: Void}}}
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
						t.Errorf("%s actual Go-accepted source stack/view observation bypassed raw-return contract: %v", api, callErr)
					}
				}
			})
		}
	}
}

func TestX86RawReturnNonStackAddressLeafRemainsSupported(t *testing.T) {
	source := "TEXT probe(SB),4,$0-0\nMOVQ $8(AX)(CX*1),BX\nBYTE $0xc3\nRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"probe": {Name: "probe", Ret: Void}}})
		if err != nil {
			t.Fatal("unrelated register-relative address became a failure:", err)
		}
		compileLLVMToObject(t, llc, triple, "non-stack.ll", "non-stack.o", ir)
	}
}
