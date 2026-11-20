package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86DirectTailResultRegionFixture(arch, typ, suffix string, width int) (string, string) {
	lea := "LEAQ"
	if arch == "386" {
		lea = "LEAL"
	}
	store := fmt.Sprintf("MOV%s $7,(DI)\nMOV%s $9,%d(DI)", suffix, suffix, width)
	if width == 8 {
		// The original mode32 MOVQ memory/X form remains eight bytes.
		store = "MOVL $7,AX\nMOVL AX,X0\nMOVQ X0,(DI)\n" +
			"MOVL $9,AX\nMOVL AX,X0\nMOVQ X0,8(DI)"
	}
	source := fmt.Sprintf("TEXT ·First(SB),4,$0-%d\n%s first+0(FP),DI\nJMP body<>(SB)\n"+
		"TEXT body<>(SB),4,$0-0\n%s\nRET\n", 2*width, lea, store)
	return source, "func First() (first,second " + typ + ")\n"
}

func TestX86DirectTailContiguousResultRegionThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, width := range []struct {
			typ, suffix string
			bytes       int
		}{{"uint8", "B", 1}, {"uint16", "W", 2}, {"uint32", "L", 4}, {"uint64", "Q", 8}} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+width.typ+"/"+api, func(t *testing.T) {
					source, declaration := x86DirectTailResultRegionFixture(target.arch, width.typ, width.suffix, width.bytes)
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete numerical result fields lack their actual shared backing", err)
					}
					if target.arch == "amd64" && !strings.Contains(ir, "alloca ["+fmt.Sprint(2*width.bytes)+" x i8]") {
						t.Fatal("cross-field result alias did not receive actual contiguous backing")
					}
					optimized := x86UndefinedTrapOptimizedIR(t, ir)
					typ := fmt.Sprintf("i%d", 8*width.bytes)
					if strings.Contains(optimized, ", "+typ+" 0, 1") {
						t.Fatal("second result used its zero return-register fallback instead of regional backing")
					}
				})
			}
		}
	}
}

func TestX86DirectTailResultRegionPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	var source, declarations, wrappers, checks strings.Builder
	for _, row := range []struct {
		typ, suffix string
		width       int
	}{{"uint8", "B", 1}, {"uint16", "W", 2}, {"uint32", "L", 4}, {"uint64", "Q", 8}} {
		name := fmt.Sprintf("Region%d", row.width)
		body, declaration := x86DirectTailResultRegionFixture("amd64", row.typ, row.suffix, row.width)
		body = strings.ReplaceAll(strings.ReplaceAll(body, "First", name), "body<>", "body"+name+"<>")
		source.WriteString(body)
		declarations.WriteString(strings.ReplaceAll(declaration, "First", name))
		typ := fmt.Sprintf("i%d", 8*row.width)
		for index := 0; index < 2; index++ {
			shim := fmt.Sprintf("%sField%d", name, index)
			fmt.Fprintf(&wrappers, "define i64 @%s() {\n %%pair = call { %s, %s } @%s()\n %%field = extractvalue { %s, %s } %%pair, %d\n",
				shim, typ, typ, name, typ, typ, index)
			if row.width < 8 {
				fmt.Fprintf(&wrappers, " %%wide = zext %s %%field to i64\n ret i64 %%wide\n}\n", typ)
			} else {
				wrappers.WriteString(" ret i64 %field\n}\n")
			}
			fmt.Fprintf(&checks, "extern uint64_t %s(void);\n", shim)
		}
	}
	// These are virtual numerical/storage semantics on the actual host LLVM
	// target, not native x86/Go execution or a C aggregate-return ABI claim.
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + checks.String() + "int main(void) {\n"
	for _, width := range []int{1, 2, 4, 8} {
		main += fmt.Sprintf("if (Region%dField0()!=7 || Region%dField1()!=9) { fprintf(stderr, \"result region%d values\\n\"); return 1; }\n", width, width, width)
	}
	main += "return 0;\n}\n"
	for _, optimized := range []bool{false, true} {
		input := ir + wrappers.String()
		if optimized {
			input = x86UndefinedTrapOptimizedIR(t, input)
		}
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR_O2=%t/backendO%d", optimized, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang},
					"result-region-portable", triple, input, main, nil, level)
			})
		}
	}
}

func TestX86DirectTailResultRegionFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete result-region objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var assembly, declarations strings.Builder
			for _, row := range []struct {
				typ, suffix string
				width       int
			}{{"uint8", "B", 1}, {"uint16", "W", 2}, {"uint32", "L", 4}, {"uint64", "Q", 8}} {
				name := fmt.Sprintf("Region%d", row.width)
				source, declaration := x86DirectTailResultRegionFixture(target.arch, row.typ, row.suffix, row.width)
				assembly.WriteString(strings.ReplaceAll(strings.ReplaceAll(source, "First", name), "body<>", "body"+name+"<>"))
				declarations.WriteString(strings.ReplaceAll(declaration, "First", name))
			}
			// Four roots and four private helpers are the complete width family.
			if strings.Count(assembly.String(), "TEXT ") != 8 {
				t.Fatal("original result-region source inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != 4 {
						t.Fatal("complete numerical result-region source failed", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}

func TestX86DirectTailResultRegionDoesNotInventOwnedBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct{ name, from, to string }{
			{"missing-first", "MOVL $7,(DI)", "NOP"},
			{"missing-second", "MOVL $9,4(DI)", "NOP"},
			{"partial-second", "MOVL $9,4(DI)", "MOVB $9,4(DI)"},
			{"read-before-write", "MOVL $7,(DI)", "MOVL 4(DI),AX\nMOVL $7,(DI)"},
			{"past-region", "MOVL $9,4(DI)", "MOVL $9,8(DI)"},
			{"before-region", "MOVL $9,4(DI)", "MOVL $9,-4(DI)"},
			{"dynamic-index", "MOVL $9,4(DI)", "MOVL $0,CX\nMOVL $9,(DI)(CX*4)"},
			{"source-extent", "$0-8", "$0-1"},
			{"address-escape", "MOVL $9,4(DI)", "MOVL DI,(BX)\nMOVL $9,4(DI)"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					source, declaration := x86DirectTailResultRegionFixture(arch, "uint32", "L", 4)
					if strings.Count(source, row.from) != 1 {
						t.Fatal("mutation not bound to one complete source role")
					}
					source = strings.Replace(source, row.from, row.to, 1)
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("region acquired missing storage/effects: %v", err)
					}
				})
			}
		}
	}
}

func TestX86DirectTailResultRegionLayoutIsNotAuthority(t *testing.T) {
	makeRole := func() (Func, FuncSig) {
		return Func{x86DirectTailRoot: &x86DirectTailRoot{}}, FuncSig{
			Ret: "{ i32, i32 }",
			Frame: FrameLayout{Results: []FrameSlot{
				{Offset: 8, Type: I32, Index: 0, Field: -1},
				{Offset: 12, Type: I32, Index: 1, Field: -1},
			}},
		}
	}
	for _, row := range []struct {
		name   string
		change func(*Func, *FuncSig)
	}{
		{"no-graph", func(fn *Func, _ *FuncSig) { fn.x86DirectTailRoot = nil }},
		{"pointer", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Type = Ptr }},
		{"bool", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Type = I1 }},
		{"floating", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Type = "float" }},
		{"index", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Index = 0 }},
		{"field", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Field = 0 }},
		{"field-path", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Fields = []int{0} }},
		{"gap", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Offset++ }},
		{"overlap", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Offset-- }},
		{"negative", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Offset = -4 }},
		{"overflow", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Offset = 4096 }},
		{"return-type", func(_ *Func, sig *FuncSig) { sig.Ret = "{ i16, i64 }" }},
		{"unaligned-relative-field", func(_ *Func, sig *FuncSig) {
			sig.Ret = "{ i8, i64 }"
			sig.Frame.Results[0].Type, sig.Frame.Results[0].Offset = I8, 0
			sig.Frame.Results[1].Type, sig.Frame.Results[1].Offset = I64, 1
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig := makeRole()
			row.change(&fn, &sig)
			if _, valid := x86DirectTailResultRegion(fn, sig, "amd64"); valid {
				t.Fatal("a different layout borrowed a contiguous result region")
			}
		})
	}
	fn, sig := makeRole()
	region, valid := x86DirectTailResultRegion(fn, sig, "amd64")
	if !valid || region.start != 8 || region.end != 16 {
		t.Fatal("exact two-field numerical layout lost its nonzero start")
	}
	// A layout and a copied private graph pointer alone cannot create backing.
	// Production must first consume the complete live source-byte proof.
	var output strings.Builder
	context := newX86Ctx(&output, fn, sig, func(s string) string { return s }, nil,
		"amd64", "x86_64-unknown-linux-gnu", false)
	if err := context.emitEntryAllocas(); !errors.Is(err, ErrProbeNeedsContext) || strings.Contains(output.String(), "%fp_result_region =") {
		t.Fatalf("unproved shape allocated result backing: %v", err)
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/no-FP/"+api, func(t *testing.T) {
				// Even a fully numerical register state is not a write to the
				// declared results. No FP instruction triggers a narrower guard.
				source := "TEXT ·First(SB),4,$0-8\nJMP body<>(SB)\n" +
					"TEXT body<>(SB),4,$0-0\nMOVL $7,AX\nMOVL $9,BX\nRET\n"
				if ir, err := x86ScalarFPBitViewAPI(t, source, "func First() (a,b uint32)\n", arch, testTargetTriple("linux", arch), api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("register fallback invented logical result writes: %v", err)
				}
			})
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("386/invalid-X8/"+api, func(t *testing.T) {
			source, declaration := x86DirectTailResultRegionFixture("386", "uint32", "L", 4)
			source = strings.Replace(source, "MOVL $7,(DI)", "MOVL $7,AX\nMOVL AX,X8\nMOVL X8,(DI)", 1)
			if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", testTargetTriple("linux", "386"), api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("region borrowed a mode64-only vector bank: %v", err)
			}
		})
	}
}

func TestX86DirectTailResultRegionRootsAndKeepFuncStayIndependent(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		lea := "LEAQ"
		if arch == "386" {
			lea = "LEAL"
		}
		for _, variant := range []struct {
			api  string
			keep bool
		}{{"text", false}, {"module", false}, {"Go", false}, {"Go", true}} {
			api, keep := variant.api, variant.keep
			for _, missing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/keep%t/missing%t/%s", arch, keep, missing, api), func(t *testing.T) {
					declaration := "func First() (a,b uint32)\nfunc Second(prefix uint64) (a,b uint32)\n"
					header := 16
					if missing {
						declaration = strings.Replace(declaration, "Second(prefix uint64) (a,b uint32)", "Second(prefix uint64) (a,b,c uint32)", 1)
						header = 20
					}
					source := fmt.Sprintf("TEXT ·First(SB),4,$0-8\n%s a+0(FP),DI\nJMP shared<>(SB)\n"+
						"TEXT ·Second(SB),4,$0-%d\n%s a+8(FP),DI\nJMP shared<>(SB)\n"+
						"TEXT shared<>(SB),4,$0-0\nMOVL $7,(DI)\nMOVL $9,4(DI)\nRET\n", lea, header, lea)
					pkg := mustGoPackage(t, "regions", "package regions\n"+declaration)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					var filter func(string, string) bool
					if keep {
						filter = func(original, _ string) bool { return original == "·First" }
					}
					options := Options{Goarch: arch, TargetTriple: testTargetTriple("linux", arch), Sigs: sigs, ResolveSym: resolve}
					context := llvm.NewContext()
					defer context.Dispose()
					var ir string
					switch api {
					case "text":
						ir, err = Translate(file, options)
					case "module":
						var module llvm.Module
						module, err = TranslateModuleInContext(context, file, options)
						if !module.IsNil() {
							defer module.Dispose()
							ir = module.String()
						}
					case "Go":
						module, moduleErr := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
							GOARCH: arch, TargetTriple: options.TargetTriple, ResolveSym: resolve, KeepFunc: filter,
						})
						err = moduleErr
						if module != nil && !module.Module.IsNil() {
							defer module.Module.Dispose()
							ir = module.Module.String()
						}
					}
					if missing {
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("one root/filter borrowed another result extent: %v", err)
						}
					} else if err != nil || strings.Count(ir, "define ") != 2-x86FloatAddSubBoolInt(keep) {
						t.Fatalf("independent shared-helper roots lost their own storage: %v", err)
					}
				})
			}
		}
	}
}
