package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86MOVBECompleteFormsSource(goarch string) string {
	var source strings.Builder
	source.WriteString("DATA movedata+0(SB)/8, $1\n")
	source.WriteString("GLOBL movedata(SB), $8\n")
	source.WriteString("TEXT moveforms(SB),$0-0\n")
	widths := []string{"W", "WW", "L", "LL"}
	if goarch == "amd64" {
		widths = append(widths, "Q", "QQ")
	}
	for _, width := range widths {
		op := "MOVBE" + width
		fmt.Fprintf(&source, "\t%s 8(BX), AX\n", op)
		fmt.Fprintf(&source, "\t%s AX, 16(BX)\n", op)
		fmt.Fprintf(&source, "\t%s movedata(SB), CX\n", op)
		fmt.Fprintf(&source, "\t%s DX, movedata(SB)\n", op)
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\t%s 24(R11), R12\n", op)
			fmt.Fprintf(&source, "\t%s R13, 32(R14)\n", op)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86MOVBECompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86MOVBECompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			ir := x86UnboundVoidScalarFormatObject(t, source, "moveforms", target.goarch, target.triple)
			for _, want := range []string{"@llvm.bswap.i16", "@llvm.bswap.i32", `"target-features"="+movbe"`} {
				if !strings.Contains(ir, want) {
					t.Fatalf("MOVBE lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "@llvm.bswap.i64") {
				t.Fatalf("MOVBEQ lowering omitted i64 byte swap:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "movbe-"+target.name+".ll", "movbe-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86MOVBERejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "MOVBEW AX, BX"},
		{goarch: "amd64", instruction: "MOVBEL 0(AX), 0(BX)"},
		{goarch: "amd64", instruction: "MOVBEQ $1, 0(BX)"},
		{goarch: "amd64", instruction: "MOVBEW AL, 0(BX)"},
		{goarch: "amd64", instruction: "MOVBEL 0(AX), X0"},
		{goarch: "amd64", instruction: "MOVBEQ AX"},
		{goarch: "amd64", instruction: "MOVBEQQ AX"},
		{goarch: "amd64", instruction: "MOVBEL.Z 0(AX), BX"},
		{goarch: "386", instruction: "MOVBEQ 0(AX), BX"},
		{goarch: "386", instruction: "MOVBEQQ 0(AX), BX"},
		{goarch: "386", instruction: "MOVBEL R8, 0(AX)"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's MOVBE ymovbe table", test.instruction)
			}
		})
	}
}

func TestAMD64MOVBERuntimeSemanticsWidthsDirectionsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := x86MOVBERepairedRuntimeSource(t)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"movesemantics": {
				Name: "movesemantics", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := x86MOVBEOriginalRuntimeDriver
	compileAndRunRuntimeTestForTarget(t, llc, clang, "movbe_semantics", triple, ir, mainC, runPrefix)
}
