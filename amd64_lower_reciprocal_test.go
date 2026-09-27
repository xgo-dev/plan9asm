package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedReciprocalCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's legacy yxm table accepts X/m128 -> X, while the VEX
	// _yvptest table accepts both X/m128 -> X and Y/m256 -> Y.
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
			legacyLast := 15
			if target.goarch == "386" {
				legacyLast = 7
			}
			const vexLast = 15
			var source strings.Builder
			source.WriteString("TEXT packedreciprocalforms(SB),$0-0\n")
			for _, op := range []string{"RCPPS", "RSQRTPS"} {
				fmt.Fprintf(&source, "\t%s X1, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 0, X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VRCPPS", "VRSQRTPS"} {
				fmt.Fprintf(&source, "\t%s X1, X%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s Y1, Y%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s 16(AX), Y%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s 0, Y%d\n", op, vexLast)
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedreciprocalforms": {Name: "packedreciprocalforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{"@llvm.x86.sse.rcp.ps", "@llvm.x86.sse.rsqrt.ps", "@llvm.x86.avx.rcp.ps.256", "@llvm.x86.avx.rsqrt.ps.256"} {
				if !strings.Contains(ll, intrinsic) {
					t.Fatalf("translation omitted %s:\n%s", intrinsic, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-reciprocal-"+target.name+".ll", "packed-reciprocal-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedReciprocalRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "RCPPS Y0, X1"},
		{goarch: "amd64", instruction: "RSQRTPS X0, X16"},
		{goarch: "amd64", instruction: "VRCPPS X16, X1"},
		{goarch: "amd64", instruction: "VRCPPS Y0, X1"},
		{goarch: "amd64", instruction: "VRSQRTPS Z0, Z1"},
		{goarch: "amd64", instruction: "VRCPPS.Z X0, X1"},
		{goarch: "amd64", instruction: "VRSQRTPS X0, K1, X1"},
		{goarch: "386", instruction: "RCPPS X0, X8"},
		{goarch: "386", instruction: "VRCPPS X16, X0"},
		{goarch: "386", instruction: "VRCPPS Y16, Y0"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				TargetTriple: triple,
				Goarch:       test.goarch,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's reciprocal tables for %s", test.instruction, test.goarch)
			}
		})
	}
}
