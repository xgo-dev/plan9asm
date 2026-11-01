package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Intel SDM volume 2B: UMONITOR/UMWAIT/TPAUSE share 0F AE /6, mod=3.
// Go 1.27 uses ywrfsbase's single Yrl operand for all three spellings.
func TestX86RawWaitPackageFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		for _, form := range []struct {
			op     Op
			prefix byte
		}{{"UMONITOR", 0xf3}, {"UMWAIT", 0xf2}, {"TPAUSE", 0x66}} {
			t.Run(target.triple+"/"+string(form.op), func(t *testing.T) {
				code := []byte{form.prefix}
				if target.arch == "amd64" {
					// ixl-go's UMONITOR uses REX.W; W does not select its width.
					code = append(code, 0x48)
				}
				code = append(code, 0x0f, 0xae, 0xf0)
				var source strings.Builder
				source.WriteString("TEXT waitpkg(SB),$0-0\n")
				for _, value := range code {
					fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
				}
				source.WriteString("RET\n")
				requireX86GoAssemblerResult(t, target.arch, source.String(), true)
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				var ir string
				if form.op == "UMONITOR" {
					// Address-monitoring retains its separate existing contract.
					ir, err = Translate(file, Options{
						Goarch: target.arch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"waitpkg": {Name: "waitpkg", Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					ir = x86UnboundVoidRawScalarFormatObject(t, source.String(), target.arch, target.triple)
				}
				if !strings.Contains(ir, strings.ToLower(string(form.op))) {
					t.Fatalf("decoded %x as another instruction", code)
				}
				compileLLVMToObject(t, llc, target.triple, "waitpkg.ll", "waitpkg.o", ir)
			})
		}
	}
}

func TestX86WaitPackageClearsOtherFlags(t *testing.T) {
	for _, op := range []string{"UMWAIT", "TPAUSE"} {
		source := "TEXT flags(SB),$0-0\n" + op + " BX\nRET\n"
		ir := x86UnboundVoidScalarFormatObject(t, source, "flags", "amd64", "x86_64-unknown-linux-gnu")
		_, after, ok := strings.Cut(ir, "asm sideeffect")
		if !ok {
			t.Fatal("no hardware wait operation")
		}
		for _, flag := range []string{"z", "slt", "pf", "of"} {
			if !strings.Contains(after, "store i1 false, ptr %flags_"+flag) {
				t.Errorf("%s did not clear %s after capturing carry", op, flag)
			}
		}
	}
}

func TestX86RawWaitPackageRegisterGrammar(t *testing.T) {
	for _, mode := range []int{32, 64} {
		registerCount := 8
		if mode == 64 {
			registerCount = 16
		}
		for _, form := range []struct {
			op     Op
			prefix byte
		}{{"UMONITOR", 0xf3}, {"UMWAIT", 0xf2}, {"TPAUSE", 0x66}} {
			for register := 0; register < registerCount; register++ {
				for _, ignoredREX := range []byte{0, 2, 4, 8, 14} {
					code := []byte{form.prefix, 0x67}
					if mode == 64 {
						code = append(code, 0x40|ignoredREX|byte(register>>3))
					}
					code = append(code, 0x0f, 0xae, 0xf0|byte(register&7))
					ins, length, ok, err := decodedX86WaitPackageInstruction(code, mode)
					wantRegister, _ := decodedX86GeneralRegister(register)
					if err != nil || !ok || length != len(code) || ins.Op != form.op ||
						len(ins.Args) != 1 || ins.Args[0].Reg != wantRegister {
						t.Fatalf("mode=%d bytes=%x: %+v, length=%d, ok=%v, err=%v", mode, code, ins, length, ok, err)
					}
					if form.op == "UMONITOR" && ins.x86AddressBits != mode/2 {
						t.Fatalf("UMONITOR address size = %d, want %d", ins.x86AddressBits, mode/2)
					}
				}
			}
		}
	}
	for _, other := range [][]byte{
		{0x0f, 0xae, 0xf0},       // MFENCE
		{0x66, 0x0f, 0xae, 0x30}, // CLWB (AX)
		{0xf3, 0x0f, 0xae, 0xc0}, // RDFSBASEL AX
		{0xf3, 0x0f, 0xae, 0x30}, // a memory encoding, not WAITPKG
		{0xf2, 0x0f, 0xae, 0x30}, // a memory encoding, not WAITPKG
	} {
		if _, _, ok, _ := decodedX86WaitPackageInstruction(other, 64); ok {
			t.Fatalf("claimed another 0F AE family: %x", other)
		}
	}
	for _, invalid := range [][]byte{
		{0xf3, 0x0f, 0xae},
		{0xf0, 0xf3, 0x0f, 0xae, 0xf0},
		append(bytes.Repeat([]byte{0x67}, 12), 0xf3, 0x0f, 0xae, 0xf0),
	} {
		if _, err := decodeX86RawDirectiveGroup(invalid, 64, 0, "invalid WAITPKG", map[string]bool{}); err == nil {
			t.Fatalf("accepted invalid WAITPKG encoding %x", invalid)
		}
	}
}

func TestX86RawWaitPackageMonitorAddressOverrides(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		arch, triple string
		mode         int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", 64},
		{"amd64", "x86_64-apple-darwin", 64},
		{"amd64", "x86_64-pc-windows-msvc", 64},
		{"386", "i386-unknown-linux-gnu", 32},
		{"386", "i686-pc-windows-msvc", 32},
	} {
		for _, segment := range []byte{0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65} {
			t.Run(fmt.Sprintf("%s/%02x", target.triple, segment), func(t *testing.T) {
				source := fmt.Sprintf(`TEXT monitor(SB),$0-0
	BYTE $0x%02x
	BYTE $0x67; BYTE $0xf3; BYTE $0x0f; BYTE $0xae; BYTE $0xf3
	RET
`, segment)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"monitor": {Name: "monitor", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ir, fmt.Sprintf(".byte 0x%02x; umonitor", segment)) ||
					!strings.Contains(ir, fmt.Sprintf("zext i%d", target.mode/2)) {
					t.Fatal("lost monitor segment or narrow address semantics")
				}
				compileLLVMToObject(t, llc, target.triple, "monitor.ll", "monitor.o", ir)
			})
		}
	}
}
