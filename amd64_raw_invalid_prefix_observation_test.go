package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// BYTE acceptance establishes original bytes only. These instructions are not
// executed: Intel specifies #UD for their LOCK prefix. The observed decoder
// marks that prefix invalid; a textual conversion must not erase that fact.
func TestX86RawInvalidLockPrefixesMustNotDisappear(t *testing.T) {
	rows := []struct {
		op      string
		machine []byte
	}{
		{"RDTSC", []byte{0x0f, 0x31}},
		{"RDTSCP", []byte{0x0f, 0x01, 0xf9}},
		{"LFENCE", []byte{0x0f, 0xae, 0xe8}},
		{"MFENCE", []byte{0x0f, 0xae, 0xf0}},
		{"SFENCE", []byte{0x0f, 0xae, 0xf8}},
		{"PAUSE", []byte{0xf3, 0x90}},
	}
	for _, mode := range []int{32, 64} {
		arch := "386"
		if mode == 64 {
			arch = "amd64"
		}
		for _, row := range rows {
			for _, prefix := range [][]byte{{0xf0}, {0xf0, 0x66}} {
				t.Run(fmt.Sprintf("%d/%s/%x", mode, row.op, prefix), func(t *testing.T) {
					code := append(append([]byte(nil), prefix...), row.machine...)
					original := "TEXT invalid(SB),4,$0-0\n"
					for _, value := range code {
						original += fmt.Sprintf("BYTE $%d\n", value)
					}
					goAssemblerOracleOutput(t, arch, original+"RET\n", "", true)
					physical, err := x86asm.Decode(code, mode)
					if err != nil {
						t.Fatal("actual pinned decoder observation", err)
					}
					invalid := false
					for _, value := range physical.Prefix {
						invalid = invalid || value&x86asm.PrefixInvalid != 0
					}
					if !invalid {
						t.Fatalf("decoder did not identify specified LOCK invalidity: %#v", physical)
					}
					decoded, conversion := decodeX86RawDirectiveGroup(code, mode, 0, original, nil)
					t.Logf("actual bytes=%x prefix=%#v GoSyntax=%q whole=%#v error=%v",
						code, physical.Prefix, x86asm.GoSyntax(physical, 0, nil), decoded, conversion)
					if conversion == nil {
						t.Fatal("whole raw decoder erased a machine-invalid prefix")
					}
				})
			}
		}
	}
}

func x86PrefixOriginalBytes(t *testing.T, mode int, code []byte) {
	t.Helper()
	arch := "386"
	if mode == 64 {
		arch = "amd64"
	}
	source := "TEXT prefix(SB),4,$0-0\n"
	for _, value := range code {
		source += fmt.Sprintf("BYTE $%d\n", value)
	}
	actual := x86OrderingHintGoBytes(t, arch, source+"RET\n")
	want := append(append([]byte(nil), code...), 0xc3)
	if !bytes.Equal(actual, want) {
		t.Fatalf("original BYTE object identity %x, want %x", actual, want)
	}
}

// The rule is decoder metadata, not an opcode whitelist. Include width,
// arithmetic, control, x87 and mnemonic-alias paths through GoSyntax.
func TestX86RawInvalidPrefixEntireDecodedClass(t *testing.T) {
	rows := []struct {
		name string
		code []byte
	}{
		{"MOV", []byte{0x8b, 0xc1}},
		{"ADD register", []byte{0x01, 0xc8}},
		{"CMP memory", []byte{0x39, 0x08}},
		{"TEST memory", []byte{0x85, 0x08}},
		{"MUL", []byte{0xf7, 0xe1}},
		{"DIV", []byte{0xf7, 0xf1}},
		{"LEA", []byte{0x8d, 0x00}},
		{"NOP", []byte{0x90}},
		{"INT3", []byte{0xcc}},
		{"UD2 fault", []byte{0x0f, 0x0b}},
		{"RET", []byte{0xc3}},
		{"PACK alias", []byte{0x66, 0x0f, 0x6b, 0xca}},
		{"FINIT alias", []byte{0xdb, 0xe3}},
	}
	for _, mode := range []int{32, 64} {
		for _, row := range rows {
			for _, prefix := range [][]byte{{0xf0}, {0xf0, 0x66}, {0x66, 0xf0}, {0xf0, 0xf0}} {
				t.Run(fmt.Sprintf("%d/%s/%x", mode, row.name, prefix), func(t *testing.T) {
					code := append(append([]byte(nil), prefix...), row.code...)
					x86PrefixOriginalBytes(t, mode, code)
					physical, err := x86asm.Decode(code, mode)
					if err != nil || physical.Len != len(code) {
						t.Fatalf("complete original decode %+v: %v", physical, err)
					}
					invalid := false
					for _, value := range physical.Prefix {
						invalid = invalid || value&x86asm.PrefixInvalid != 0
					}
					if !invalid {
						t.Fatal("actual original bytes lack the expected invalid LOCK metadata")
					}
					if syntax, err := decodedX86GoSyntax(physical, code); err == nil {
						t.Fatalf("invalid metadata became legal syntax %q", syntax)
					}
					if got, err := decodeX86RawDirectiveGroup(code, mode, 0, row.name, nil); err == nil {
						t.Fatalf("invalid metadata escaped whole decoding: %+v", got)
					}
				})
			}
		}
	}
}

func TestX86RawIgnoredPrefixesRemainDistinctFromInvalid(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, row := range []struct {
			name string
			code []byte
			want Op
		}{
			{"duplicate operand override", []byte{0x66, 0x66, 0x89, 0xc8}, "MOVW"},
			{"duplicate address override", []byte{0x67, 0x67, 0x0f, 0x31}, "RDTSC"},
			{"ignored operand override", []byte{0x66, 0x66, 0x0f, 0x31}, "RDTSC"},
		} {
			t.Run(fmt.Sprintf("%d/%s", mode, row.name), func(t *testing.T) {
				x86PrefixOriginalBytes(t, mode, row.code)
				physical, err := x86asm.Decode(row.code, mode)
				if err != nil || physical.Len != len(row.code) {
					t.Fatalf("complete original decode %+v: %v", physical, err)
				}
				ignored := false
				for _, prefix := range physical.Prefix {
					if prefix&x86asm.PrefixInvalid != 0 {
						t.Fatal("legal control has invalid metadata")
					}
					ignored = ignored || prefix&x86asm.PrefixIgnored != 0
				}
				if !ignored {
					t.Fatal("control does not observe PrefixIgnored")
				}
				got, err := decodeX86RawDirectiveGroup(row.code, mode, 0, row.name, nil)
				if err != nil || len(got) != 1 || got[0].Op != row.want {
					t.Fatalf("legal ignored prefix changed: %+v, %v", got, err)
				}
			})
		}
	}
}

func TestX86RawValidLockRequiresItsWholeAtomicEffect(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, row := range []struct {
			name string
			code []byte
		}{
			{"ADD", []byte{0x01, 0x08}},
			{"AND", []byte{0x21, 0x08}},
			{"XADD", []byte{0x0f, 0xc1, 0x08}},
			{"XCHG", []byte{0x87, 0x08}},
		} {
			for _, prefix := range [][]byte{{0xf0}, {0xf0, 0xf0}} {
				t.Run(fmt.Sprintf("%d/%s/%x", mode, row.name, prefix), func(t *testing.T) {
					code := append(append([]byte(nil), prefix...), row.code...)
					x86PrefixOriginalBytes(t, mode, code)
					physical, err := x86asm.Decode(code, mode)
					if err != nil || physical.Len != len(code) {
						t.Fatalf("complete original decode %+v: %v", physical, err)
					}
					for _, value := range physical.Prefix {
						if value&x86asm.PrefixInvalid != 0 {
							t.Fatal("actual legitimate LOCK classified as machine invalid")
						}
					}
					got, err := decodeX86RawDirectiveGroup(code, mode, 0, row.name, nil)
					t.Logf("bytes=%x syntax=%q parsed=%+v error=%v", code,
						x86asm.GoSyntax(physical, 0, nil), got, err)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("raw atomic-prefix effect is not bound; may not become a standalone LOCK no-op: %+v/%v", got, err)
					}
				})
			}
		}
	}
}
