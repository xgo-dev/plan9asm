package plan9asm

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type x86RawFP16ObjectEncoding struct {
	code          []byte
	lengthIgnored bool
	maskMove      string
}

// Compare actual LLVM object fields with independent original physical bytes.
// Register allocation may change register numbers, but not opcode, source role,
// vector length, mask, zeroing, broadcast or ER/SAE controls. Scalar LLIG and
// widening register-SAE LL are intentionally ignored by the ISA.
func x86RawFP16CheckObject(t *testing.T, llc, triple, ir, level string, want map[string]x86RawFP16ObjectEncoding) {
	t.Helper()
	disassembler := findLLVM22Tool("llvm-objdump")
	if disassembler == "" {
		t.Fatal("LLVM22 disassembler required")
	}
	dir := t.TempDir()
	input, object := filepath.Join(dir, "fp16.ll"), filepath.Join(dir, "fp16.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+triple, "-filetype=obj", input, "-o", object))
	listing := x86FloatCompareCaptureCommand(t, exec.Command(disassembler, "--disassemble", object))
	sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <_?((?:conversion|halfSqrt|halfFMA|halfBinary)[0-9]+)>:\n`).FindAllSubmatchIndex(listing, -1)
	seen := make(map[string]bool)
	for index, section := range sections {
		name := string(listing[section[2]:section[3]])
		expected, found := want[name]
		if !found || seen[name] {
			t.Fatal("unexpected or duplicated FP16 object symbol", name)
		}
		end := len(listing)
		if index+1 < len(sections) {
			end = sections[index+1][0]
		}
		operations, masks := 0, 0
		for _, line := range strings.Split(string(listing[section[1]:end]), "\n") {
			if strings.Contains(line, "kmovw") || strings.Contains(line, "kmovd") {
				if !strings.Contains(line, expected.maskMove) {
					t.Fatal("FP16 operation changed its full active mask width", name, line)
				}
				masks++
			}
			fields := strings.Fields(line)
			if len(fields) < 7 || !strings.HasSuffix(fields[0], ":") {
				continue
			}
			var code []byte
			for _, field := range fields[1:] {
				if len(field) != 2 {
					break
				}
				value, err := hex.DecodeString(field)
				if err != nil {
					break
				}
				code = append(code, value[0])
			}
			if len(code) < 6 || code[0] != 0x62 || code[1]&7 < 5 {
				continue
			}
			operations++
			original := expected.code
			register := code[5]&0xc0 == 0xc0
			if code[1]&7 != original[1]&7 || code[2]&0x87 != original[2]&0x87 ||
				code[3]&0x97 != original[3]&0x97 || code[4] != original[4] ||
				register != (original[5]&0xc0 == 0xc0) {
				t.Fatalf("%s changed native FP16 opcode, mask, zeroing or source/control role: %x versus %x", name, code, original)
			}
			if !expected.lengthIgnored && code[3]&0x60 != original[3]&0x60 {
				t.Fatalf("%s changed native source width or rounding: %x versus %x", name, code, original)
			}
		}
		wantMasks := 1
		if expected.maskMove == "" {
			wantMasks = 0
		}
		if operations != 1 || masks != wantMasks {
			t.Fatal("object did not retain exactly one original FP16 operation and full mask", name, operations, masks)
		}
		seen[name] = true
	}
	if len(seen) != len(want) {
		t.Fatal("incomplete native FP16 object inventory", len(seen), len(want))
	}
}
