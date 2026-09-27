package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestX86AddressSensitiveRawTextBlobReportedURootFarJump(t *testing.T) {
	const source = `TEXT setup(SB),NOSPLIT,$0-0
	MOVL AX, farjump64+6(SB)
	JMP farjump64(SB)
TEXT farjump64(SB),NOSPLIT,$0-0
	BYTE $0xff; BYTE $0x2d; LONG $0
	LONG $0
	LONG $8
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
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
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"setup":     {Name: "setup", Ret: Void},
					"farjump64": {Name: "farjump64", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "define void @farjump64()") ||
				!strings.Contains(ir, "naked noinline") ||
				!strings.Contains(ir, `.byte 255, 45, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0`) {
				t.Fatalf("byte-exact naked raw TEXT body missing:\n%s", ir)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "raw-text-"+target.name+".ll", "raw-text-"+target.name+".o", ir)
			assertX86RawTextAssemblyBytes(t, llc, target.triple, ir, []byte{0xff, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0})
		})
	}
}

func TestX86AddressSensitiveRawTextLeadingPCALIGNFormats(t *testing.T) {
	for _, alignment := range []int{8, 16, 32, 64, 128, 256, 512, 1024, 2048} {
		t.Run(strconv.Itoa(alignment), func(t *testing.T) {
			source := fmt.Sprintf(`TEXT refer(SB),$0-0
	LEAQ data(SB), AX
	RET
TEXT data(SB),$0
	PCALIGN $%d
	LONG $0xdeadbeef
`, alignment)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			for pass := 0; pass < 2; pass++ {
				file, err = normalizeX86RawFile(file, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				if got := file.Funcs[1].X86RawAlign; got != int64(alignment) {
					t.Fatalf("alignment after normalization = %d, want %d", got, alignment)
				}
			}
		})
	}
}

func assertX86RawTextAssemblyBytes(t *testing.T, llc, triple, ir string, want []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "raw-text.ll")
	if err := os.WriteFile(path, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(llc, "-mtriple="+triple, "-filetype=asm", "-o", "-", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM 22 assembly emission failed: %v\n%s", err, out)
	}
	var got []byte
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != ".byte" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 0, 8)
		if err != nil {
			t.Fatalf("parse emitted byte line %q: %v", line, err)
		}
		got = append(got, byte(value))
	}
	if string(got) != string(want) {
		t.Fatalf("LLVM 22 emitted raw TEXT bytes %v, want %v\n%s", got, want, out)
	}
}

func TestX86AddressSensitiveRawTextBlobSelection(t *testing.T) {
	const source = `TEXT refs(SB),NOSPLIT,$0-0
	MOVL AX, farjump32+1(SB)
	LEAQ gdt(SB), CX
	MOVL info(SB), BX
	RET
TEXT farjump32(SB),NOSPLIT,$0-0
	BYTE $0xea; LONG $0; WORD $0x18
TEXT gdt(SB),NOSPLIT,$0-0
	QUAD $0; QUAD $0x00cf9a000000ffff
TEXT info(SB),NOSPLIT,$0-0
	LONG $0
TEXT semantic(SB),NOSPLIT,$0-0
	BYTE $0x90; BYTE $0xc3
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string][]byte{
		"farjump32": {0xea, 0, 0, 0, 0, 0x18, 0},
		"gdt":       {0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0x9a, 0xcf, 0},
		"info":      {0, 0, 0, 0},
	}
	for _, fn := range normalized.Funcs {
		want, selected := wants[fn.Sym]
		if selected && string(fn.X86RawText) != string(want) {
			t.Fatalf("%s raw TEXT bytes %v, want %v", fn.Sym, fn.X86RawText, want)
		}
		if fn.Sym == "semantic" && fn.X86RawText != nil {
			t.Fatal("unaddressed raw instruction body bypassed semantic decoding")
		}
	}
}

func TestX86AddressSensitiveAlignedRawTextBlobReportedURoot(t *testing.T) {
	const source = `TEXT trampoline_start(SB),$0-0
	LEAQ stack_top(SB), AX
	MOVQ (AX), AX
	RET
TEXT stack_top(SB),$0
	PCALIGN $32
	LONG $0xdeadbeef
`
	requireX86GoAssemblerResult(t, "amd64", source, true)

	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var blob *Func
	for index := range normalized.Funcs {
		if normalized.Funcs[index].Sym == "stack_top" {
			blob = &normalized.Funcs[index]
		}
	}
	if blob == nil || string(blob.X86RawText) != string([]byte{0xef, 0xbe, 0xad, 0xde}) || blob.X86RawAlign != 32 {
		t.Fatalf("aligned raw TEXT was not retained: %+v", blob)
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "linux", triple: "x86_64-unknown-linux-gnu"},
		{name: "darwin", triple: "x86_64-apple-darwin"},
		{name: "windows", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"trampoline_start": {Name: "trampoline_start", Ret: Void},
					"stack_top":        {Name: "stack_top", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "define void @stack_top()") || !strings.Contains(ir, " align 32 {") {
				t.Fatal("aligned raw TEXT declaration missing")
			}
			compileLLVMToObject(t, llc, target.triple, "aligned-raw-text.ll", "aligned-raw-text.o", ir)
			assertX86RawTextAssemblyBytes(t, llc, target.triple, ir, []byte{0xef, 0xbe, 0xad, 0xde})
		})
	}
}
