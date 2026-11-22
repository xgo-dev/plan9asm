package plan9asm

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARMMachineExceptionReturnOfficialForms(t *testing.T) {
	const triple = "armv7-unknown-linux-gnueabihf"
	forms := []string{"RFE", "WORD $0xe8fd8000", "RFE.EQ.NE"}
	for _, condition := range strings.Fields("EQ NE CS HS CC LO MI PL VS VC HI LS GE LT GT LE AL") {
		forms = append(forms, "RFE."+condition)
	}
	var source strings.Builder
	signatures := make(map[string]FuncSig, len(forms))
	words := make(map[string][]uint32, len(forms))
	for index, form := range forms {
		name := fmt.Sprintf("restore%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),516,$0-0\n %s\n", name, form)
		signatures[name] = FuncSig{Name: name, Ret: Void, ARMEntry: &ARMMachineEntry{
			Return: ARMMachineReturnException,
		}}
		// Go asm emits this unconditional A32 word for every RFE spelling.
		words[name] = []uint32{0xe8fd8000}
	}
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Goarch: "arm", TargetTriple: triple, Sigs: signatures}
	text, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	if module.Context() != ctx {
		t.Fatal("exception entry escaped the caller-owned LLVM context")
	}
	pkg := mustGoPackage(t, "example.com/entry", "package entry\nfunc anchor()\n")
	goTranslation, err := TranslateGoModule(pkg, []byte(source.String()), GoModuleOptions{
		GOOS: "linux", GOARCH: "arm", TargetTriple: triple,
		ResolveSym: func(name string) string { return strings.TrimSuffix(name, "(SB)") },
		ManualSig: func(name string) (FuncSig, bool) {
			sig, known := signatures[name]
			return sig, known
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer goTranslation.Module.Dispose()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, ir := range []string{text, module.String(), goTranslation.Module.String()} {
		for _, level := range []string{"-O0", "-O2"} {
			requireARMExceptionReturnObject(t, llc, level, ir, words)
		}
	}
}

func requireARMExceptionReturnObject(t *testing.T, llc, level, ir string, words map[string][]uint32) {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "restore.ll"), filepath.Join(dir, "restore.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	cmd := exec.CommandContext(ctx, llc, level, "-filetype=obj", input, "-o", output)
	if diagnostic, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("compile %s: %v\n%s", level, err, diagnostic)
	}
	object, err := elf.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	section := object.Section(".text")
	if section == nil {
		t.Fatal("missing ARM code section")
	}
	code, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := object.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, symbol := range symbols {
		want, known := words[symbol.Name]
		if !known {
			continue
		}
		if symbol.Size != uint64(len(want)*4) || symbol.Value+symbol.Size > uint64(len(code)) {
			t.Fatalf("%s %s must contain exactly its frame-free source instructions: size=%d offset=%d",
				level, symbol.Name, symbol.Size, symbol.Value)
		}
		for index, word := range want {
			offset := symbol.Value + uint64(index*4)
			if got := object.ByteOrder.Uint32(code[offset : offset+4]); got != word {
				t.Fatalf("%s %s instruction %d is %#08x, want %#08x", level, symbol.Name, index, got, word)
			}
		}
		count++
	}
	if count != len(words) {
		t.Fatalf("compiled %d of %d exception entry symbols", count, len(words))
	}
}

func TestARMMachineExceptionReturnRequiresA32PhysicalEntry(t *testing.T) {
	for _, test := range []struct {
		name, triple, text, body string
		entry                    *ARMMachineEntry
	}{
		{"ordinary", "armv7-unknown-linux-gnueabihf", "516,$0-0", "RFE", nil},
		{"ordinary word", "armv7-unknown-linux-gnueabihf", "516,$0-0", "WORD $0xe8fd8000", nil},
		{"thumb", "thumbv7-pc-windows-msvc", "516,$0-0", "RFE", &ARMMachineEntry{Return: ARMMachineReturnException}},
		{"source frame", "armv7-unknown-linux-gnueabihf", "4,$16-0", "RFE", &ARMMachineEntry{Return: ARMMachineReturnException}},
		{"preceding instruction", "armv7-unknown-linux-gnueabihf", "516,$0-0", "MOVW R0,R1\n RFE", &ARMMachineEntry{Return: ARMMachineReturnException}},
		{"unexpected operand", "armv7-unknown-linux-gnueabihf", "516,$0-0", "RFE R0", &ARMMachineEntry{Return: ARMMachineReturnException}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT Restore(SB)," + test.text + "\n " + test.body + "\n"
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: test.triple,
				Sigs: map[string]FuncSig{"Restore": {Name: "Restore", Ret: Void, ARMEntry: test.entry}},
			}); err == nil || test.entry == nil && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("invalid physical exception entry: %v", err)
			}
		})
	}
}
