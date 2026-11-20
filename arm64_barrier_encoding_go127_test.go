//go:build go1.27
// +build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func arm64BarrierAuditOutput(t *testing.T, tool string, arguments []string, input string, environment []string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, tool, arguments...)
	command.Stdin = strings.NewReader(input)
	command.Env = environment
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("barrier encoding oracle %s: %v\n%s", filepath.Base(tool), err, output)
	}
	return output
}

func arm64BarrierObjectText(t *testing.T, object, triple string) []byte {
	t.Helper()
	if strings.Contains(triple, "apple") {
		file, err := macho.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if section := file.Section("__text"); section != nil {
			data, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	} else if strings.Contains(triple, "windows") {
		file, err := pe.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if section := file.Section(".text"); section != nil {
			data, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	} else {
		file, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if section := file.Section(".text"); section != nil {
			data, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
	t.Fatalf("missing instruction section in %s object", triple)
	return nil
}

func TestARM64SpeculationBarrierMatchesGoAndLLVMEncoding(t *testing.T) {
	// Go's ASB SYSOP and LLVM's feature-gated SB encode D50330FF.
	// HINT #7 is D50320FF: accepting either string is not a byte oracle.
	source := "TEXT barrier(SB),516,$0-0\nSB\nRET\n"
	dir := t.TempDir()
	asm := filepath.Join(dir, "original.s")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	listing := arm64BarrierAuditOutput(t, "go", []string{"tool", "asm", "-S", "-o", filepath.Join(dir, "original.o"), asm}, "",
		append(os.Environ(), "GOOS=linux", "GOARCH=arm64"))
	var native []byte
	for _, row := range regexp.MustCompile(`(?m)^\s*0x[0-9a-f]+((?: [0-9a-f]{2}){4,16})(?:\s|$)`).FindAllSubmatch(listing, -1) {
		decoded, err := hex.DecodeString(strings.ReplaceAll(string(row[1]), " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		native = append(native, decoded...)
	}
	want := []byte{0xff, 0x30, 0x03, 0xd5}
	if len(native) < 8 || !bytes.Equal(native[:4], want) || !bytes.Equal(native[4:8], []byte{0xc0, 0x03, 0x5f, 0xd6}) {
		t.Fatalf("actual Go SB/RET object = %x, want ff3003d5c0035fd6", native)
	}
	llc, mc := findLLVM22Tool("llc"), findLLVM22Tool("llvm-mc")
	if llc == "" || mc == "" {
		t.Fatal("LLVM 22 llc and llvm-mc are required")
	}
	encoding := arm64BarrierAuditOutput(t, mc, []string{"-triple=aarch64", "-mattr=+sb", "-show-encoding"}, "sb\n", os.Environ())
	if !bytes.Contains(encoding, []byte("[0xff,0x30,0x03,0xd5]")) {
		t.Fatalf("independent LLVM SB encoding = %s", encoding)
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"barrier": {Name: "barrier", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llPath, object := filepath.Join(t.TempDir(), "barrier.ll"), filepath.Join(t.TempDir(), "barrier.o")
			if err := os.WriteFile(llPath, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			arm64BarrierAuditOutput(t, llc, []string{"-O0", "-mtriple=" + triple, "-filetype=obj", llPath, "-o", object}, "", os.Environ())
			text := arm64BarrierObjectText(t, object, triple)
			// LLVM may independently use XPACLRI (the HINT #7 encoding)
			// when implementing llvm.returnaddress in the entry harness.
			// Bind the source operation to its IR and the real SB word,
			// rather than banning that unrelated compiler-generated effect.
			if bytes.Count(text, want) != 1 || strings.Contains(ir, `asm sideeffect "hint #7"`) {
				t.Fatalf("LLVM SB object = %x, source must emit exact SB once, not substitute HINT #7", text)
			}
		})
	}
}
