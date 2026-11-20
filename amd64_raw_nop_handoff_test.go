package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Intel SDM NOP (90 and 0F 1F /0) has no register or memory effect.
// Independently enumerate ModRM/SIB and prefix axes, including addresses
// which would need a caller, segment, stack or PC contract if dereferenced.
func x86RawNOPWitnesses(mode int) [][]byte {
	forms := [][]byte{{0x90}, {0x66, 0x90}}
	for mod := byte(0); mod < 4; mod++ {
		for rm := byte(0); rm < 8; rm++ {
			code := []byte{0x0f, 0x1f, mod<<6 | rm}
			if mod != 3 && rm == 4 {
				code = append(code, 0x24)
			}
			switch {
			case mod == 1:
				code = append(code, 0xff)
			case mod == 2 || mod == 0 && rm == 5:
				code = append(code, 0xff, 0xff, 0xff, 0x7f)
			}
			forms = append(forms, code)
		}
	}
	for sib := 0; sib < 256; sib++ {
		code := []byte{0x0f, 0x1f, 0x04, byte(sib)}
		if sib&7 == 5 {
			code = append(code, 0xff, 0xff, 0xff, 0x7f)
		}
		forms = append(forms, code)
	}
	for _, prefix := range []byte{0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66} {
		forms = append(forms, []byte{prefix, 0x0f, 0x1f, 0x00})
	}
	forms = append(forms, []byte{0x66, 0x0f, 0x1f, 0x84, 0x00, 0, 0, 0, 0})
	if mode == 32 {
		// The 16-bit address decoder must not manufacture BX/SI inputs.
		forms = append(forms, []byte{0x67, 0x0f, 0x1f, 0x00})
	} else {
		// Inert EIP-relative address and actual extended REX banks.
		forms = append(forms, []byte{0x67, 0x0f, 0x1f, 0x05, 0xff, 0xff, 0xff, 0x7f})
		for rex := byte(0x40); rex < 0x50; rex++ {
			forms = append(forms, []byte{rex, 0x0f, 0x1f, 0x04, 0x00})
		}
	}
	return forms
}

func TestX86RawNOPPhysicalFieldsAreInert(t *testing.T) {
	for _, mode := range []int{32, 64} {
		arch := "amd64"
		if mode == 32 {
			arch = "386"
		}
		forms := x86RawNOPWitnesses(mode)
		var complete []byte
		for _, code := range forms {
			complete = append(complete, code...)
		}
		x86HandoffOriginalBytes(t, arch, complete)
		for _, code := range forms {
			t.Run(fmt.Sprintf("mode%d/%x", mode, code), func(t *testing.T) {
				physical, err := x86asm.Decode(code, mode)
				// The independent literal object and runtime oracle cover the
				// pinned decoder's missing REX.W NOP row; do not use the
				// production adapter as its own acceptance oracle.
				missingWidth := mode == 64 && code[0]&0xf8 == 0x48
				if !missingWidth && (err != nil || physical.Op != x86asm.NOP || physical.Len != len(code)) {
					t.Fatalf("independent NOP encoding: %+v %v", physical, err)
				}
				instructions, err := decodeX86RawDirectiveGroup(code, mode, 0, "NOP witness", map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(instructions) != 1 || instructions[0].Op != "NOP" || len(instructions[0].Args) != 0 ||
					instructions[0].x86UnboundAddressOverride || instructions[0].x86AddressBits != 0 {
					t.Fatalf("inert address acquired an effect: %+v", instructions)
				}
			})
		}
	}
}

func TestX86RawNOPGoEncoderWitnesses(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, registration := range []string{
		"var ydivl = []ytab{\n\t{Zm_o, 2, argList{Yml}},\n}",
		"{ANOPW, ydivl, Pe, opBytes{0x0f, 0x1f, 00}}",
		"{ANOPL, ydivl, Px, opBytes{0x0f, 0x1f, 00}}",
	} {
		if !strings.Contains(string(table), registration) {
			t.Fatal("Go NOP encoder changed:", registration)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, spelling := range []string{"NOPL AX", "NOPW AX", "NOPL (AX)", "NOPW -1(AX)(CX*8)"} {
			code := x86OrderingHintGoBytes(t, arch, "TEXT probe(SB),4,$0-0\n"+spelling+"\n")
			mode := 64
			if arch == "386" {
				mode = 32
			}
			decoded, err := decodeX86RawDirectiveGroup(code, mode, 0, spelling, map[string]bool{})
			if err != nil || len(decoded) != 1 || decoded[0].Op != "NOP" {
				t.Fatalf("actual %s %s bytes %x: %+v %v", arch, spelling, code, decoded, err)
			}
		}
	}
}

func TestX86RawNOPDoesNotEraseOtherEffectsOrBoundaries(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, code := range [][]byte{
			{0xf0, 0x90}, {0xf0, 0x0f, 0x1f, 0x00},
			{0xf0, 0x48, 0x0f, 0x1f, 0x00},
			{0x0f}, {0x0f, 0x1f}, {0x0f, 0x1f, 0x84, 0x00},
			{0x48, 0x0f, 0x1f, 0x84, 0x00},
		} {
			if _, err := decodeX86RawDirectiveGroup(code, mode, 0, "invalid NOP", map[string]bool{}); err == nil {
				t.Fatalf("mode %d accepted invalid/truncated bytes %x", mode, code)
			}
		}
		for extension := byte(1); extension < 8; extension++ {
			code := []byte{0x0f, 0x1f, extension << 3}
			if _, err := decodeX86RawDirectiveGroup(code, mode, 0, "reserved NOP extension", map[string]bool{}); err == nil {
				t.Fatalf("reserved /%d NOP accepted", extension)
			}
			if _, ok := decodedX86REXWNOP(append([]byte{0x48}, code...)); ok {
				t.Fatalf("REX.W adapter accepted reserved /%d", extension)
			}
		}
		for _, code := range [][]byte{{0xf3, 0x90}, {0x87, 0xc0}, {0x8b, 0x00}} {
			instructions, err := decodeX86RawDirectiveGroup(code, mode, 0, "not NOP", map[string]bool{})
			if err != nil || len(instructions) != 1 || instructions[0].Op == "NOP" {
				t.Fatalf("mode %d lost non-NOP effect %x: %+v %v", mode, code, instructions, err)
			}
		}
		// A branch into a NOP's ModRM byte is still a mid-instruction edge.
		interior := []byte{0x74, 1, 0x0f, 0x1f, 0x00, 0xc3}
		if _, err := decodeX86RawDirectiveGroup(interior, mode, 0, "interior", map[string]bool{}); err == nil {
			t.Fatal("branch into multi-byte NOP accepted")
		}
		boundary := []byte{0x74, 3, 0x0f, 0x1f, 0x00, 0x90, 0xc3}
		if _, err := decodeX86RawDirectiveGroup(boundary, mode, 0, "boundary", map[string]bool{}); err != nil {
			t.Fatal("valid branch/NOP boundaries:", err)
		}
		// The generic physical handoff remains strict for real memory.
		physical, err := x86asm.Decode([]byte{0x8b, 0x00}, mode)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseDecodedX86PhysicalInstruction(physical, "NOP"); err == nil {
			t.Fatal("formatter erased a real memory read")
		}
	}
}

func TestX86RawNOPThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86OrderingHintTargets {
		mode := 64
		if target.arch == "386" {
			mode = 32
		}
		var source strings.Builder
		source.WriteString("TEXT ·probe(SB),4,$0-4\n")
		for _, code := range x86RawNOPWitnesses(mode) {
			source.WriteString(x86RawDisplacementDirectives(code))
		}
		source.WriteString("MOVL $73,ret+0(FP)\nRET\n")
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), "package ordering\nfunc probe() uint32\n", target.arch, target.triple)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains([]byte(ir), []byte("inttoptr")) {
					t.Fatal("inert NOP address became a native pointer")
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, object := filepath.Join(dir, "nop.ll"), filepath.Join(dir, "nop.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", "-o", object, input))
				}
			})
		}
	}
}
