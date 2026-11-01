package plan9asm

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86ResultInitializationFixture(t *testing.T, arch, declaration, body string) (GoPackage, *File, FuncSig, string) {
	t.Helper()
	pkg := mustGoPackage(t, "example.invalid/resultinit", "package resultinit\n"+declaration+"\n")
	sig, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	var args int64
	for _, slot := range sig.Frame.Results {
		if end := slot.Offset + x86FrameScalarBytes(slot.Type, arch); end > args {
			args = end
		}
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n", args, body)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, file, sig, source
}

func TestX86ABI0ResultInitializationOriginalGoAndFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		for _, kind := range []struct{ typ, move, register string }{
			{"uint8", "MOVB", "AX"}, {"uint16", "MOVW", "AX"}, {"uint32", "MOVL", "AX"},
			{"float32", "MOVSS", "X0"}, {"float64", "MOVSD", "X0"},
		} {
			t.Run(target.triple+"/"+kind.typ, func(t *testing.T) {
				word := 8
				if target.arch == "386" {
					word = 4
				}
				result := word
				if kind.typ == "float64" {
					result = 8
				}
				body := fmt.Sprintf("%s x+0(FP),%s\n%s %s,ret0+%d(FP)\nRET", kind.move, kind.register, kind.move, kind.register, result)
				pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x "+kind.typ+") "+kind.typ, body)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig},
					ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
				text, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, text, "text")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, module.String(), "module")
				translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple,
					ResolveSym: options.ResolveSym})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, translated.Module.String(), "typed-go")
			})
		}
	}
}

func x86ResultInitializationObject(t *testing.T, llc, triple, ir, name string) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, name+".ll"), filepath.Join(dir, name+".o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	data, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, llc, "-O0", "-mtriple="+triple, "-filetype=obj", input, "-o", output))
	if err != nil {
		t.Fatalf("LLVM22 result alias object failed: %v\n%s", err, data)
	}
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatalf("LLVM22 result alias object absent: %v", err)
	}
}

func TestX86ABI0ResultInitializationAllPathAndByteBoundaries(t *testing.T) {
	for name, body := range map[string]string{
		"split stores":                  "MOVL $1,ret0+0(FP)\nMOVL $2,ret0+4(FP)\nRET",
		"all branches":                  "MOVL $1,AX\nCMPL AX,$0\nJE other\nMOVQ $1,ret0+0(FP)\nJMP end\nother:\nMOVQ $2,ret0+0(FP)\nend:\nRET",
		"loop initialized before entry": "MOVQ $1,ret0+0(FP)\nMOVL $3,AX\nloop:\nSUBL $1,AX\nCMPL AX,$0\nJNE loop\nRET",
		"L zero extends GP":             "MOVL $1,AX\nMOVQ AX,ret0+0(FP)\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatal(err)
			}
		})
	}
	for missing := 0; missing < 8; missing++ {
		var body strings.Builder
		for offset := 0; offset < 8; offset++ {
			if offset != missing {
				fmt.Fprintf(&body, "MOVB $1,ret0+%d(FP)\n", offset)
			}
		}
		body.WriteString("RET")
		_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", body.String())
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err == nil {
			t.Fatalf("missing result byte %d was accepted", missing)
		}
	}
	for name, body := range map[string]string{
		"bare": "RET", "read result first": "MOVQ ret0+0(FP),AX\nMOVQ AX,ret0+0(FP)\nRET",
		"late unknown overwrite": "MOVQ $1,ret0+0(FP)\nMOVQ AX,ret0+0(FP)\nRET",
		"partial GP":             "MOVB $1,AX\nMOVQ AX,ret0+0(FP)\nRET",
		"partial W GP":           "MOVW $1,AX\nMOVQ AX,ret0+0(FP)\nRET",
		"join revocation":        "MOVL $1,AX\nCMPL AX,$0\nJE other\nMOVQ $1,ret0+0(FP)\nJMP end\nother:\nNOP\nend:\nRET",
		"loop entry missing":     "MOVL $1,AX\nJMP condition\nbody:\nMOVQ $1,ret0+0(FP)\ncondition:\nCMPL AX,$0\nJNE body\nRET",
		"call":                   "MOVQ $1,ret0+0(FP)\nCALL ·other(SB)\nRET",
		"physical store":         "MOVQ $1,ret0+0(FP)\nMOVQ $2,(AX)\nRET",
		"escape":                 "LEAQ ret0+0(FP),AX\nMOVQ $1,ret0+0(FP)\nRET",
		"raw":                    "MOVQ $1,ret0+0(FP)\nBYTE $0x90\nRET",
		"dead unknown call":      "MOVQ $1,ret0+0(FP)\nJMP end\nCALL ·other(SB)\nend:\nRET",
		"dead unresolved branch": "MOVQ $1,ret0+0(FP)\nJMP end\nJMP nowhere\nend:\nRET",
		"dead physical escape":   "MOVQ $1,ret0+0(FP)\nJMP end\nLEAQ ret0+0(FP),AX\nend:\nRET",
		"tail":                   "MOVQ $1,ret0+0(FP)\nJMP ·other(SB)",
		"wrong offset":           "MOVQ $1,ret0+1(FP)\nRET",
		"unknown flags":          "JE end\nMOVQ $1,ret0+0(FP)\nend:\nRET",
	} {
		t.Run(name, func(t *testing.T) {
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err == nil {
				t.Fatal("unknown/partial/mixed CFG result acquired initialization")
			}
		})
	}
}

func TestX86ABI0ResultInitializationImmutableInputsAndUnsupportedRoles(t *testing.T) {
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint64", "MOVQ $1,ret0+0(FP)\nRET")
	before := fmt.Sprintf("%#v %#v", file.Funcs[0], sig)
	if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
		t.Fatal(err)
	}
	if after := fmt.Sprintf("%#v %#v", file.Funcs[0], sig); after != before {
		t.Fatal("result checker changed its original source or signature")
	}
	for name, mutate := range map[string]func(*Func, *FuncSig){
		"ABIInternal":       func(f *Func, _ *FuncSig) { f.Sym += "<ABIInternal>" },
		"incoming register": func(_ *Func, s *FuncSig) { s.ArgRegs = []Reg{AX} },
		"pointer result":    func(_ *Func, s *FuncSig) { s.Ret, s.Frame.Results[0].Type = Ptr, Ptr },
		"changed layout":    func(_ *Func, s *FuncSig) { s.Frame.Results[0].Offset = 1 },
		"changed width":     func(_ *Func, s *FuncSig) { s.Ret, s.Frame.Results[0].Type = I32, I32 },
		"aggregate field":   func(_ *Func, s *FuncSig) { s.Frame.Results[0].Fields = []int{0} },
		"oversized result":  func(_ *Func, s *FuncSig) { s.Frame.Results[0].Offset = 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			fn, changed := file.Funcs[0], sig
			changed.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
			mutate(&fn, &changed)
			if err := CheckX86ABI0ResultInitialization(fn, changed, "amd64"); err == nil {
				t.Fatal("changed role/layout acquired the original result proof")
			}
		})
	}
	if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "386"); err == nil {
		t.Fatal("mode32 MOVQ acquired a native-width write certificate")
	}
	if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "arm64"); err == nil {
		t.Fatal("another architecture acquired x86 byte effects")
	}
}
