package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// Independent names/widths, not iteration over the implementation map.
var fixedLocalPackedMoveOracle = []struct {
	name string
	evex bool
}{
	{"VMOVDQA", false}, {"VMOVDQU", false},
	{"VMOVAPD", true}, {"VMOVAPS", true},
	{"VMOVUPD", true}, {"VMOVUPS", true},
	{"VMOVDQA32", true}, {"VMOVDQA64", true},
	{"VMOVDQU8", true}, {"VMOVDQU16", true},
	{"VMOVDQU32", true}, {"VMOVDQU64", true},
}

func fixedLocalPackedAssembly(operation string) string {
	var source strings.Builder
	source.WriteString("TEXT ·Value(SB),4,$256-16\nMOVQ a+0(FP),AX\n")
	source.WriteString("MOVQ SP,BP\nADDQ $64,BP\nANDQ $-64,BP\n")
	for offset := 64; offset < 192; offset += 8 {
		fmt.Fprintf(&source, "MOVQ AX,%d(BP)\n", offset)
	}
	source.WriteString(operation + "\n")
	source.WriteString("MOVQ 128(BP),AX\nMOVQ AX,ret+8(FP)\nRET\n")
	return source.String()
}

func fixedLocalPackedFixture(t *testing.T, operation string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	assembly := fixedLocalPackedAssembly(operation)
	pkg, request := goAMD64FrameTypedFixture(t, "func Value(a uint64) uint64", assembly)
	sig, err := DeriveGoFuncABI0Signature(pkg.Path+".Value", pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, request, file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
		Sigs:       map[string]FuncSig{sig.Name: sig},
	}
}

func TestGoAMD64FixedLocalPackedMoveTypedFamilyProof(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, row := range fixedLocalPackedMoveOracle {
		for _, bank := range []string{"X", "Y", "Z"} {
			if bank == "Z" && !row.evex {
				continue
			}
			for _, masked := range []bool{false, true} {
				if masked && !row.evex {
					continue
				}
				name := fmt.Sprintf("%s/%s/masked=%v", row.name, bank, masked)
				load, copy, store := "64(BP),"+bank+"0", bank+"0,"+bank+"1", bank+"1,128(BP)"
				prefix := ""
				if masked {
					prefix = "KMOVQ AX,K1\n"
					// Defined merge input and destination memory are independent.
					prefix += fmt.Sprintf("%s 64(BP),%s0\n%s 64(BP),%s1\n", row.name, bank, row.name, bank)
					load, copy, store = "64(BP),K1,"+bank+"0", bank+"0,K1,"+bank+"1", bank+"1,K1,128(BP)"
				}
				operation := prefix + fmt.Sprintf("%s %s\n%s %s\n%s %s", row.name, load, row.name, copy, row.name, store)
				assembly := fixedLocalPackedAssembly(operation)
				original.WriteString(strings.Replace(assembly, "·Value", fmt.Sprintf("·Value%d", count), 1))
				count++
				t.Run(name, func(t *testing.T) {
					pkg, _, file, options := fixedLocalPackedFixture(t, operation)
					if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") ||
						GoAMD64FixedLocalFrameBindingNeeded(file, "386") {
						t.Error("physical private-frame transport needs its original backing regardless of alignment")
					}
					if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); err != nil {
						t.Fatalf("initialized pure numeric packed-frame proof: %v", err)
					}
				})
			}
		}
	}
	if count != 64 {
		t.Fatalf("independent full family fixture count changed: %d", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalPackedMoveActualOriginalObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		for _, operation := range []string{
			"VMOVDQA 64(BP),Y0\nVMOVDQA Y0,128(BP)",
			"VMOVDQA64 64(BP),Z31\nVMOVDQA64 Z31,128(BP)",
		} {
			t.Run(target.name+"/"+strings.Fields(operation)[0], func(t *testing.T) {
				pkg, request, file, options := fixedLocalPackedFixture(t, operation)
				request.Target, options.TargetTriple = target.name, target.triple
				source := requireGoAMD64FrameCapture(t, pkg, request)
				observed := source.functions[pkg.Path+".Value"]
				if observed.locals != 264 || observed.args != 16 || len(observed.code) == 0 {
					t.Fatal("missing original automatic frame/object witness")
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				bound, err := source.BindFixedLocal(ctx, pkg, file, options)
				if err != nil {
					t.Fatal(err)
				}
				fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
					if err != nil || !strings.Contains(ir, "fixed_local_native") || !strings.Contains(ir, "asm sideeffect") {
						t.Fatalf("actual local certificate was not consumed: %v", err)
					}
					compileLLVMToObject(t, llc, target.triple, "packed-frame.ll", "packed-frame.o", ir)
				})
			})
		}
	}
}

func TestGoAMD64FixedLocalBPPrivateOriginOnly(t *testing.T) {
	operation := "MOVOU 64(BP),X0\nPADDQ 64(BP),X0\nMOVOU X0,128(BP)"
	pkg, _, file, options := fixedLocalPackedFixture(t, operation)
	sig := options.Sigs[pkg.Path+".Value"]
	if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
		t.Fatalf("BP private affine source: %v", err)
	}
	for name, assembly := range map[string]string{
		"numeric BP": strings.Replace(fixedLocalPackedAssembly(operation), "MOVQ SP,BP", "MOVQ AX,BP", 1),
		"unknown BP": strings.Replace(fixedLocalPackedAssembly(operation), "MOVQ SP,BP", "MOVQ DX,BP", 1),
		"narrow BP":  strings.Replace(fixedLocalPackedAssembly(operation), "MOVQ SP,BP", "MOVL SP,BP", 1),
		"escaped BP": strings.Replace(fixedLocalPackedAssembly(operation), "MOVQ AX,ret+8(FP)", "MOVQ BP,ret+8(FP)", 1),
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(changed.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown/numeric/escaping BP obtained local authority: %v", err)
			}
		})
	}
}
