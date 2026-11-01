package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86ADXCompleteFormsSource(goarch string) string {
	var source strings.Builder
	symbol := "adxdata"
	size := 8
	if goarch == "386" {
		symbol = "adxdata386"
		size = 4
	}
	fmt.Fprintf(&source, "DATA %s+0(SB)/%d, $1\n", symbol, size)
	fmt.Fprintf(&source, "GLOBL %s(SB), $%d\n", symbol, size)
	source.WriteString("TEXT adxforms(SB),$0-0\n")
	widths := []string{"L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, stem := range []string{"ADCX", "ADOX"} {
		for _, width := range widths {
			op := stem + width
			fmt.Fprintf(&source, "\t%s AX, BX\n", op)
			fmt.Fprintf(&source, "\t%s 8(BX), CX\n", op)
			fmt.Fprintf(&source, "\t%s %s(SB), DX\n", op, symbol)
			if goarch == "amd64" {
				fmt.Fprintf(&source, "\t%s R11, R12\n", op)
			} else {
				fmt.Fprintf(&source, "\t%s AX, SP\n", op)
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86ADXCompleteGo127FormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			source := x86ADXCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			ll := x86UnboundVoidScalarFormatObject(t, source, "adxforms", target.goarch, target.triple)
			for _, want := range []string{"add i32", "icmp ult i32", `"target-features"="+adx"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ADX lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ll, "add i64") {
				t.Fatalf("ADX Q-width lowering omitted add i64:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "adx-"+target.name+".ll", "adx-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ADXRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "ADCXQ $1, AX"},
		{goarch: "amd64", instruction: "ADOXL AX, 0(BX)"},
		{goarch: "amd64", instruction: "ADCXL X0, AX"},
		{goarch: "amd64", instruction: "ADOXQ AX, X0"},
		{goarch: "amd64", instruction: "ADCXQ AX"},
		{goarch: "amd64", instruction: "ADOXL.Z AX, BX"},
		{goarch: "386", instruction: "ADCXL R8, AX"},
		{goarch: "386", instruction: "ADOXQ AX, BX"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch:       test.goarch,
				TargetTriple: triple,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ADX yml_rl table", test.instruction)
			}
		})
	}
}

func TestAMD64ADXRuntimeSemanticsAndIndependentFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := x86ADXOriginalRuntimeSource
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	mainC := x86ADXOriginalRuntimeDriver
	rawSource := x86ADXOriginalRawSource(source)
	for _, form := range []struct{ name, source string }{{"text", source}, {"raw", rawSource}} {
		t.Run(form.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, form.source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"adxsemantics": {
						Name: "adxsemantics", Args: []LLVMType{Ptr}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "adx_semantics_"+form.name, triple, ir, mainC, runPrefix)
		})
	}
}
