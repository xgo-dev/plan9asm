package plan9asm

import (
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARM64OfficialSystemContextObjects(t *testing.T) {
	corpus := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata")
	var source strings.Builder
	expected := make(map[string]uint32)
	signatures := make(map[string]FuncSig)
	add := func(instruction, register string, read bool, word uint32) {
		name := fmt.Sprintf("system%d", len(expected))
		expected[name] = word
		signatures[name] = FuncSig{
			Name: name, Args: []LLVMType{I64}, Ret: I64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
			},
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\n", name)
		preserve := register == "R29" || register == "R30"
		if preserve {
			fmt.Fprintf(&source, "MOVD %s,R16\n", register)
		}
		if register != "" && register != "ZR" && !read {
			fmt.Fprintf(&source, "MOVD value+0(FP),%s\n", register)
		}
		fmt.Fprintln(&source, instruction)
		if read {
			fmt.Fprintf(&source, "MOVD %s,ret+8(FP)\n", register)
		} else {
			source.WriteString("MOVD value+0(FP),R0\nMOVD R0,ret+8(FP)\n")
		}
		if preserve {
			fmt.Fprintf(&source, "MOVD R16,%s\n", register)
		}
		source.WriteString("RET\n")
	}

	for _, name := range []string{"arm64.s", "arm64enc.s"} {
		data, err := os.ReadFile(filepath.Join(corpus, name))
		if err != nil {
			t.Fatal(err)
		}
		for line, raw := range strings.Split(string(data), "\n") {
			op, encoding, _ := strings.Cut(raw, "//")
			instruction := strings.TrimSpace(op)
			fields := strings.Fields(instruction)
			if len(fields) == 0 || fields[0] != "TLBI" && fields[0] != "SYS" && fields[0] != "SYSL" {
				continue
			}
			code, err := hex.DecodeString(strings.TrimSpace(encoding))
			if err != nil || len(code) != 4 {
				t.Fatalf("%s:%d has no original system word: %q", name, line+1, encoding)
			}
			_, register, _ := strings.Cut(instruction, ",")
			add(instruction, strings.TrimSpace(register), fields[0] == "SYSL", binary.LittleEndian.Uint32(code))
		}
	}
	if len(expected) != 82 {
		t.Fatalf("found %d original ARM64 system operations, want 82", len(expected))
	}
	add("WORD $0xd50e8734", "R20", false, 0xd50e8734) // TLBI VAE3, R20.
	add("SYS $427808, R20", "R20", false, 0xd50e8734)
	// AT and SYS have the same two operand rows in Go's arm64 encoder.
	add("AT $30720", "", false, 0xd508781f)
	add("AT $30720, R3", "R3", false, 0xd5087803)
	add("AT $30720, ZR", "ZR", false, 0xd508781f)
	assembly := source.String()
	requireARM64GoAssemblerResult(t, assembly, true)
	file, err := Parse(ArchARM64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, Sigs: signatures})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, text := range []string{ir, armFloatEffectOptimizedIR(t, ir)} {
		object := compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "official-system.ll", "official-system.o", text)
		requireARM64OfficialSystemWords(t, object, expected)
	}

	for _, row := range []struct {
		name string
		body string
	}{
		{"unknown SYS effect", "MOVD value+0(FP),R20\nSYS $32768,R20\n"},
		{"unknown AT effect", "MOVD value+0(FP),R20\nAT $30720,R20\n"},
		{"reserved TLBI register field", "MOVD value+0(FP),R20\nSYS $34560,R20\n"},
		{"missing TLBI input", "TLBI VAE3,R20\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT system0(SB),4,$0-16\n" + row.body +
				"MOVD value+0(FP),R0\nMOVD R0,ret+8(FP)\nRET\n"
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple, Sigs: signatures})
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("incomplete system operation returned IR=%t, error=%v", ir != "", err)
			}
		})
	}
}

func requireARM64OfficialSystemWords(t *testing.T, object string, expected map[string]uint32) {
	t.Helper()
	elfFile, err := elf.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer elfFile.Close()
	section := elfFile.Section(".text")
	if section == nil {
		t.Fatal("missing AArch64 code section")
	}
	code, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := elfFile.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, symbol := range symbols {
		word, known := expected[symbol.Name]
		if !known {
			continue
		}
		if symbol.Size%4 != 0 || symbol.Value+symbol.Size > uint64(len(code)) {
			t.Fatalf("invalid code range for %s", symbol.Name)
		}
		count := 0
		for offset := symbol.Value; offset < symbol.Value+symbol.Size; offset += 4 {
			actual := elfFile.ByteOrder.Uint32(code[offset : offset+4])
			if actual&0xffd80000 != 0xd5080000 {
				continue
			}
			if actual&^31 != word&^31 || (actual&31 == 31) != (word&31 == 31) {
				t.Fatalf("%s system operand fields %#x, want %#x", symbol.Name, actual, word)
			}
			count++
		}
		if count != 1 {
			t.Fatalf("%s compiled %d system operations, want one", symbol.Name, count)
		}
		seen++
	}
	if seen != len(expected) {
		t.Fatalf("compiled %d of %d original system functions", seen, len(expected))
	}
}
