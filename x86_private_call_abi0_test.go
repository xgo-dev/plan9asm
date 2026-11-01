package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A real bounded ABI0 declaration owns its own FP arguments. It must remain
// a call, rather than borrowing the caller's register continuation contract.
func x86PrivateABI0CallFixture(arch string) (string, FuncSig) {
	word, typ, lea := 8, I64, "LEAQ"
	if arch == "386" {
		word, typ, lea = 4, I32, "LEAL"
	}
	source := fmt.Sprintf(`TEXT ·Call(SB),4,$0-0
 CALL helper<>(SB)
 RET
TEXT helper<>(SB),4,$0-%d
 %s arg+0(FP),AX
 RET
`, word, lea)
	return source, FuncSig{Name: "helper", Args: []LLVMType{typ}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: typ, Index: 0, Field: -1}}}}
}

func TestX86PrivateCallPreservesBoundedOrdinaryABI0(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, mixed := range []bool{false, true} {
			source, sig := x86PrivateABI0CallFixture(arch)
			declaration := "func Call()\n"
			if mixed {
				other, decl := x86PrivateCallSource(arch, "CALL register<>(SB)", "TEXT register<>(SB),4,$0-0\n ADDQ BX,AX\n RET\n")
				source += other
				declaration += decl
			}
			goAssemblerOracleOutput(t, arch, source, "", true)
			pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/mixed_%t/%s", arch, mixed, api), func(t *testing.T) {
					ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, arch, triple, api,
						func(name string) (FuncSig, bool) { return sig, name == sig.Name })
					if err != nil {
						t.Fatal("bounded ordinary ABI0 helper rejected:", err)
					}
					for _, want := range []string{"define void @helper(", "call void @helper("} {
						if !strings.Contains(ir, want) {
							t.Fatalf("ordinary helper lost its independent ABI: missing %q\n%s", want, ir)
						}
					}
					if mixed && (strings.Count(ir, "define ") != 3 || strings.Contains(ir, "@register(")) {
						t.Fatal("register continuation acquired an independent ABI", ir)
					}
					x86ResultInitializationObject(t, llc, triple, ir, api)
				})
			}
		}
	}
}

func TestX86PrivateCallOrdinaryABI0DoesNotGrantContinuationRoles(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(*string, *FuncSig)
	}{
		{"no_signature", func(_ *string, sig *FuncSig) { sig.Name = "unrelated" }},
		{"omitted_extent", func(src *string, _ *FuncSig) { *src = strings.Replace(*src, "$0-8", "$0", 1) }},
		{"short_extent", func(src *string, _ *FuncSig) { *src = strings.Replace(*src, "$0-8", "$0-4", 1) }},
		{"no_frame_roles", func(_ *string, sig *FuncSig) { sig.Frame.Params = nil }},
		{"wrong_parameter", func(_ *string, sig *FuncSig) { sig.Frame.Params[0].Index = 1 }},
		{"custom_register", func(_ *string, sig *FuncSig) { sig.ArgRegs = []Reg{"AX"} }},
		{"private_tail", func(src *string, _ *FuncSig) { *src = strings.Replace(*src, "CALL helper", "JMP helper", 1) }},
		{"mixed_unsafe_graph", func(src *string, _ *FuncSig) {
			*src += "TEXT ·Other(SB),4,$0-0\n CALL raw<>(SB)\n RET\nTEXT raw<>(SB),4,$0-8\n LEAQ arg+0(FP),AX\n RET\n"
		}},
		{"mixed_call_roles", func(src *string, _ *FuncSig) {
			*src = strings.Replace(*src, "CALL helper<>(SB)", "CALL helper<>(SB)\n CALL raw<>(SB)", 1)
			*src += "TEXT raw<>(SB),4,$0-0\n RET\n"
		}},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source, sig := x86PrivateABI0CallFixture("amd64")
				row.edit(&source, &sig)
				pkg := mustGoPackage(t, "bitview", "package bitview\nfunc Call()\nfunc Other()")
				ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api,
					func(name string) (FuncSig, bool) { return sig, name == sig.Name })
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("independent ABI did not retain its boundary: err=%v\n%s", err, ir)
				}
			})
		}
	}
}
