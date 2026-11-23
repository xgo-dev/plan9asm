package plan9asm

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86LiteralControlLinkedTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	elfLinker, coffLinker := findLLVM22Tool("ld.lld"), findLLVM22Tool("lld-link")
	machLinker := findLLVM22Tool("ld64.lld")
	if llc == "" || elfLinker == "" || coffLinker == "" || machLinker == "" {
		t.Fatal("x86 literal control needs LLVM 22 llc and ELF, COFF, and Mach-O linkers")
	}
	for _, target := range []struct {
		arch, triple, format string
	}{
		{"386", "i386-unknown-linux-gnu", "elf"},
		{"386", "i686-pc-windows-msvc", "coff"},
		{"amd64", "x86_64-unknown-linux-gnu", "elf"},
		{"amd64", "x86_64-pc-windows-msvc", "coff"},
		{"amd64", "x86_64-apple-darwin", "macho"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			for _, form := range []struct {
				name, source string
				opcode       byte
				destination  uint64
			}{
				{"jump", "JMP $4\n", 0xe9, 4},
				{"signed", "JMP $-1\nRET\n", 0xe9, ^uint64(0)},
				{"call", "CALL $4\nRET\n", 0xe8, 4},
				{"unsigned", "JMP $0x80000000\n", 0xe9, 0x80000000},
			} {
				t.Run(form.name, func(t *testing.T) {
					text := "TEXT ·literal(SB),516,$0-0\n" + form.source
					goAssemblerOracleOutput(t, target.arch, text, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, text, "func literal()\n", target.arch, target.triple, api)
						if err != nil {
							t.Fatal(api, err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							object := x86PackedStringCompileObject(t, llc, target.triple, ir, level)
							output := filepath.Join(t.TempDir(), "literal")
							switch target.format {
							case "coff":
								machine := "x64"
								if target.arch == "386" {
									machine = "x86"
								}
								x86FloatCompareCaptureCommand(t, exec.Command(coffLinker, "/machine:"+machine, "/base:0x400000",
									"/entry:literal", "/subsystem:console", "/nodefaultlib", "/safeseh:no",
									"/fixed", "/out:"+output, object))
							case "macho":
								x86FloatCompareCaptureCommand(t, exec.Command(machLinker, "-arch", "x86_64", "-platform_version",
									"macos", "11.0", "11.0", "-pagezero_size", "0x100000", "-e", "_literal", "-o", output, object))
							case "elf":
								machine := "elf_x86_64"
								if target.arch == "386" {
									machine = "elf_i386"
								}
								x86FloatCompareCaptureCommand(t, exec.Command(elfLinker, "-m", machine,
									"-e", "literal", "-o", output, object))
							}
							code, pc := x86LiteralControlLinkedEntry(t, output, target.format)
							if len(code) < 5 || code[0] != form.opcode {
								t.Fatalf("%s/%s: %s lost its near transfer opcode: %x", api, level, form.name, code)
							}
							actual := pc + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(code[1:5]))))
							want := form.destination
							if target.arch == "386" {
								actual, want = uint64(uint32(actual)), uint64(uint32(want))
							}
							if actual != want {
								t.Fatalf("%s/%s: %s entered %#x with code %x, want direct transfer to %#x",
									api, level, form.name, pc, code, want)
							}
							if strings.Contains(form.source, "RET") && (len(code) < 6 || code[5] != 0xc3) {
								t.Fatalf("%s/%s: original return byte missing directly after the transfer", api, level)
							}
						}
					}
				})
			}
		})
	}
}

func x86LiteralControlLinkedEntry(t *testing.T, path, format string) ([]byte, uint64) {
	t.Helper()
	switch format {
	case "coff":
		object, err := pe.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer object.Close()
		var pc, entry uint64
		switch header := object.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			entry = uint64(header.AddressOfEntryPoint)
			pc = uint64(header.ImageBase) + entry
		case *pe.OptionalHeader64:
			entry = uint64(header.AddressOfEntryPoint)
			pc = header.ImageBase + entry
		default:
			t.Fatal("linked COFF image has no optional header")
		}
		section := object.Section(".text")
		if section == nil || entry < uint64(section.VirtualAddress) {
			t.Fatal("linked COFF image has no text entry")
		}
		code, err := section.Data()
		if err != nil {
			t.Fatal(err)
		}
		offset := entry - uint64(section.VirtualAddress)
		if offset >= uint64(len(code)) {
			t.Fatal("linked COFF entry is outside .text")
		}
		return code[offset:], pc
	case "macho":
		object, err := macho.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer object.Close()
		section := object.Section("__text")
		if section == nil || object.Symtab == nil {
			t.Fatal("linked Mach-O has no text or symbols")
		}
		code, err := section.Data()
		if err != nil {
			t.Fatal(err)
		}
		for _, sym := range object.Symtab.Syms {
			if sym.Name == "_literal" && sym.Value >= section.Addr && sym.Value-section.Addr < uint64(len(code)) {
				return code[sym.Value-section.Addr:], sym.Value
			}
		}
		t.Fatal("linked Mach-O has no original text entry")
		return nil, 0
	}
	object, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	section := object.Section(".text")
	if section == nil || object.Entry < section.Addr {
		t.Fatal("linked ELF image has no text entry")
	}
	code, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	offset := object.Entry - section.Addr
	if offset >= uint64(len(code)) {
		t.Fatal("linked ELF entry is outside .text")
	}
	return code[offset:], object.Entry
}

func TestX86LiteralControlRejectsUnboundNativeState(t *testing.T) {
	for _, row := range []struct{ arch, source, declaration, triple string }{
		{"386", "TEXT ·literal(SB),0,$0-0\nJMP $4\n", "func literal()", "i386-unknown-linux-gnu"},
		{"386", "TEXT ·literal(SB),4,$8-0\nJMP $4\n", "func literal()", "i386-unknown-linux-gnu"},
		{"386", "TEXT ·literal(SB),516,$0-4\nJMP $4\n", "func literal(x uint32)", "i386-unknown-linux-gnu"},
		{"386", "TEXT ·literal(SB),516,$0-0\nCALL $4\n", "func literal()", "i386-unknown-linux-gnu"},
		{"386", "TEXT ·literal(SB),516,$0-0\nJMP $0x100000000\n", "func literal()", "i386-unknown-linux-gnu"},
		{"386", "TEXT ·literal(SB),516,$0-0\nJMP $4\n", "func literal()", "x86_64-unknown-linux-gnu"},
		{"amd64", "TEXT ·literal(SB),4,$0-0\nCALL $4\nRET\n", "func literal()", "x86_64-unknown-linux-gnu"},
		{"amd64", "TEXT ·literal(SB),516,$0-0\nJMP $4\n", "func literal()", "aarch64-apple-darwin"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration, row.arch, row.triple, api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s: %q on %s needs original native entry context: %v", api, row.source, row.triple, err)
			}
		}
	}
}
