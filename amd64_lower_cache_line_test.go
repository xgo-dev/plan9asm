package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86CacheLineWritebackCompleteGoAssemblerForms(t *testing.T) {
	const source = `
TEXT cachelinewriteback(SB),$16-0
	CLFLUSH (AX)
	CLFLUSHOPT 8(BX)
	CLWB local+0(SP)
	RET
`
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
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: target.triple, Goarch: target.goarch,
				Sigs: map[string]FuncSig{"cachelinewriteback": {Name: "cachelinewriteback", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, mnemonic := range []string{"clflush $0", "clflushopt $0", "clwb $0"} {
				if !strings.Contains(ir, mnemonic) {
					t.Fatalf("cache-line lowering omitted %q:\n%s", mnemonic, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "x86-cache-line-writeback.ll", "x86-cache-line-writeback.o", ir)
		})
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
