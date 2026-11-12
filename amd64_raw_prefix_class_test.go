package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86OrderingHintsPhysicalFenceRMIsIgnored(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, row := range []struct {
			op   Op
			base byte
		}{
			{"LFENCE", 0xe8},
			{"MFENCE", 0xf0},
			{"SFENCE", 0xf8},
		} {
			for rm := byte(0); rm < 8; rm++ {
				t.Run(fmt.Sprintf("%d/%s/rm=%d", mode, row.op, rm), func(t *testing.T) {
					code := []byte{0x0f, 0xae, row.base | rm}
					x86PrefixOriginalBytes(t, mode, code)
					got, err := decodeX86RawDirectiveGroup(code, mode, 0, "physical fence", nil)
					if err != nil || len(got) != 1 || got[0].Op != row.op || len(got[0].Args) != 0 {
						t.Fatalf("physical ignored-r/m fence changed: %x: %+v/%v", code, got, err)
					}
				})
			}
		}
	}
}

// The complete Intel LOCK list is independent of the translator. The original
// named Go object binds width, destination and opcode; no RMW is executed here.
// Valid raw LOCK remains Context until the complete atomic effect is bound.
func TestX86RawValidLockCompleteRMWClass(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		mode := 32
		widths := "BWL"
		if arch == "amd64" {
			mode = 64
			widths += "Q"
		}
		var forms []string
		for _, stem := range []string{"ADD", "ADC", "AND", "OR", "SBB", "SUB", "XOR", "CMPXCHG", "XADD", "XCHG"} {
			for _, width := range widths {
				reg := "CX"
				if width == 'B' {
					reg = "CL"
				}
				forms = append(forms, fmt.Sprintf("%s%c %s,(AX)", stem, width, reg))
			}
		}
		for _, stem := range []string{"INC", "DEC", "NEG", "NOT"} {
			for _, width := range widths {
				forms = append(forms, fmt.Sprintf("%s%c (AX)", stem, width))
			}
		}
		for _, stem := range []string{"BTC", "BTR", "BTS"} {
			for _, width := range strings.TrimPrefix(widths, "B") {
				forms = append(forms, fmt.Sprintf("%s%c CX,(AX)", stem, width))
			}
		}
		forms = append(forms, "CMPXCHG8B (AX)")
		if arch == "amd64" {
			forms = append(forms, "CMPXCHG16B (AX)")
		}
		want := 49
		if arch == "amd64" {
			want = 67
		}
		if len(forms) != want {
			t.Fatal("complete native-width LOCK inventory changed", arch, len(forms))
		}
		for _, form := range forms {
			t.Run(arch+"/"+form, func(t *testing.T) {
				source := "TEXT locked(SB),4,$0-0\nLOCK\n" + form + "\nRET\n"
				actual := x86OrderingHintGoBytes(t, arch, source)
				if len(actual) < 3 || actual[0] != 0xf0 || actual[len(actual)-1] != 0xc3 {
					t.Fatalf("original named LOCK object lacks complete prefix/body/RET: %x", actual)
				}
				code := actual[:len(actual)-1]
				physical, err := x86asm.Decode(code, mode)
				if err != nil || physical.Len != len(code) {
					t.Fatalf("actual complete LOCK instruction %+v: %v", physical, err)
				}
				for _, prefix := range physical.Prefix {
					if prefix&x86asm.PrefixInvalid != 0 {
						t.Fatal("accepted memory RMW has invalid machine LOCK", physical)
					}
				}
				got, err := decodeX86RawDirectiveGroup(code, mode, 0, source, nil)
				if !errors.Is(err, ErrProbeNeedsContext) || len(got) != 0 {
					t.Fatalf("complete valid LOCK silently lost atomic/body effects: %+v/%v", got, err)
				}
				// The simple named (AX) form ends in its ModRM byte. Change only
				// mod to register addressing, retaining the original opcode/width.
				// BYTE acceptance binds invalid machine bytes, not ISA validity.
				bad := append([]byte(nil), code...)
				bad[len(bad)-1] |= 0xc0
				x86PrefixOriginalBytes(t, mode, bad)
				if got, err := decodeX86RawDirectiveGroup(bad, mode, 0, "invalid register-only LOCK "+form, nil); err == nil {
					t.Fatalf("complete LOCK class admitted register-only RMW: %x/%+v", bad, got)
				}
			})
		}
	}
}

func TestX86RawVisibleEffectPrefixesNeedWholeContract(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, code := range [][]byte{
			{0xf3, 0x89, 0x08}, // XRELEASE MOVL CX,(AX), no explicit LOCK.
			{0xf3, 0x87, 0x08}, // XRELEASE on implicitly locked XCHG.
			{0xf2, 0x87, 0x08}, // XACQUIRE on implicitly locked XCHG.
			{0xf2, 0xc3},       // BND RET, not an ordinary near return.
		} {
			t.Run(fmt.Sprintf("%d/%x", mode, code), func(t *testing.T) {
				x86PrefixOriginalBytes(t, mode, code)
				physical, err := x86asm.Decode(code, mode)
				if err != nil || physical.Len != len(code) {
					t.Fatal("complete original prefixed object", physical, err)
				}
				got, err := decodeX86RawDirectiveGroup(code, mode, 0, "whole effect prefix", nil)
				t.Logf("bytes=%x actualPrefix=%#v GoSyntax=%q parsed=%+v error=%v", code,
					physical.Prefix, x86asm.GoSyntax(physical, 0, nil), got, err)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("visible native effect became an ordinary opcode/string repeat without a contract", err)
				}
			})
		}
	}
}

// These BYTE objects observe conversion, not a new string/caller contract.
// Visible prefixes must either retain the complete body or fail closed.
func TestX86RawVisibleStringPrefixesRetainBody(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, row := range []struct {
			name string
			code []byte
			body Op
		}{
			{"REP MOVSB", []byte{0xf3, 0xa4}, "MOVSB"},
			{"REPE CMPSB", []byte{0xf3, 0xa6}, "CMPSB"},
			{"REPNE CMPSB", []byte{0xf2, 0xa6}, "CMPSB"},
			{"duplicate REP MOVSB", []byte{0xf3, 0xf3, 0xa4}, "MOVSB"},
			{"XRELEASE MOV", []byte{0xf3, 0x89, 0x08}, "MOVL"},
			{"XACQUIRE LOCK ADD", []byte{0xf2, 0xf0, 0x01, 0x08}, "ADDL"},
			{"XRELEASE LOCK ADD", []byte{0xf3, 0xf0, 0x01, 0x08}, "ADDL"},
		} {
			t.Run(fmt.Sprintf("%d/%s", mode, row.name), func(t *testing.T) {
				x86PrefixOriginalBytes(t, mode, row.code)
				physical, err := x86asm.Decode(row.code, mode)
				if err != nil || physical.Len != len(row.code) {
					t.Fatal("complete physical visible prefix", physical, err)
				}
				got, err := decodeX86RawDirectiveGroup(row.code, mode, 0, row.name, nil)
				t.Logf("actual bytes=%x syntax=%q whole=%+v error=%v", row.code,
					x86asm.GoSyntax(physical, 0, nil), got, err)
				if err != nil {
					return
				}
				body := false
				for _, instruction := range got {
					body = body || instruction.Op == row.body
				}
				if !body {
					t.Fatal("visible prefix conversion discarded its actual instruction body", got)
				}
			})
		}
	}
}
