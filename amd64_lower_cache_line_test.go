package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86CacheLineWritebackCompleteGoAssemblerForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "386", triple: "i686-pc-windows-msvc"},
		{goarch: "amd64", triple: "x86_64-apple-darwin"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.goarch+"/"+target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.goarch == "386" {
				word, move = 4, "MOVL"
			}
			source := fmt.Sprintf(`TEXT ·cachelinewriteback(SB),4,$16-%d
%s first+0(FP), AX
%s second+%d(FP), BX
CLFLUSH (AX)
CLFLUSHOPT 8(BX)
CLWB local-4(SP)
`, 2*word, move, move, word)
			if target.goarch == "386" {
				source += "CLWB 12(SP)\n"
			}
			source += "RET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			for _, api := range []string{"text", "module", "Go"} {
				const declaration = "func cachelinewriteback(first, second *byte)"
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.goarch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, mnemonic := range []string{"clflush $0", "clflushopt $0", "clwb $0"} {
					if !strings.Contains(ir, mnemonic) {
						t.Fatalf("%s omitted cache operation %q", api, mnemonic)
					}
				}
				compileLLVMToObject(t, llc, target.triple, "x86-cache-line-writeback.ll", "x86-cache-line-writeback.o", ir)
			}
		})
	}
}

func TestTranslateX86CacheLineWritebackRejectsUnboundAddress(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := testTargetTriple("linux", arch)
		for _, op := range []string{"CLFLUSH", "CLFLUSHOPT", "CLWB"} {
			for _, address := range []string{"(AX)", "tmp+0(SP)", "tmp-17(SP)"} {
				t.Run(arch+"/"+op+"/"+address, func(t *testing.T) {
					source := "TEXT ·check(SB),4,$16-0\n" + op + " " + address + "\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func check()", arch, triple, "text")
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unbound cache address: %v", err)
					}
				})
			}
		}
	}
}

func TestTranslateX86CacheLineWritebackRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, goarch := range []string{"386", "amd64"} {
		triple := "i386-unknown-linux-gnu"
		if goarch == "amd64" {
			triple = "x86_64-unknown-linux-gnu"
		}
		for _, instruction := range []string{
			"CLFLUSH",
			"CLFLUSH AX",
			"CLFLUSH $1",
			"CLFLUSH (AX), (BX)",
			"CLFLUSH.X (AX)",
			"CLFLUSHOPT AX",
			"CLWB AX",
		} {
			t.Run(goarch+"/"+strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
				source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
				requireX86GoAssemblerResult(t, goarch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{
					TargetTriple: triple, Goarch: goarch,
					Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
				if err == nil {
					t.Fatalf("Translate accepted form rejected by Go 1.27: %s", instruction)
				}
			})
		}
	}
}
