package plan9asm

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const x86URootFarJumpOriginalSource = `TEXT setup(SB),NOSPLIT,$0-0
	MOVL AX, farjump64+6(SB)
	JMP farjump64(SB)
TEXT farjump64(SB),NOSPLIT,$0-0
	BYTE $0xff; BYTE $0x2d; LONG $0
	LONG $0
	LONG $8
`

func x86URootFarJumpNormalizedFile(t *testing.T, file *File, arch string) *File {
	t.Helper()
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("complete original far-jump source could not be normalized", err)
	}
	if len(normalized.Funcs) != 2 || normalized.Funcs[0].Sym != "setup" || normalized.Funcs[1].Sym != "farjump64" ||
		len(normalized.Data) != 0 || len(normalized.Globl) != 0 {
		t.Fatal("original setup/raw-TEXT inventory changed")
	}
	if len(normalized.Funcs[0].Instrs) != 3 || normalized.Funcs[0].X86RawText != nil ||
		!reflect.DeepEqual(normalized.Funcs[0].Instrs, file.Funcs[0].Instrs) {
		t.Fatal("raw TEXT selection omitted or rewrote the original setup instructions")
	}
	want := []byte{0xff, 0x2d, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0}
	if len(normalized.Funcs[1].Instrs) != 6 || !bytes.Equal(normalized.Funcs[1].X86RawText, want) {
		t.Fatalf("complete original 14-byte far-jump inventory changed: %x", normalized.Funcs[1].X86RawText)
	}
	return normalized
}

func TestX86AddressSensitiveRawTextFarJumpOriginalContextAndInventory(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			// Stock Go accepts the complete original source. Its public LLVM
			// translation still needs initialized AX and writable TEXT backing.
			file, _ := x86UnboundVoidFormatSources(t, x86URootFarJumpOriginalSource, target.arch, target.triple)
			x86URootFarJumpNormalizedFile(t, file, target.arch)
		})
	}
}

func TestX86AddressSensitiveRawTextStoreNeedsSourceAndWritableData(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			name       string
			initialize string
			text       bool
			context    bool
		}{
			{name: "owned-data-initialized", initialize: "MOVL $7, AX\n"},
			{name: "owned-data-uninitialized", context: true},
			{name: "owned-data-partial-input", initialize: "MOVW $7, AX\n", context: true},
			{name: "text-initialized", initialize: "MOVL $7, AX\n", text: true, context: true},
			{name: "text-uninitialized", text: true, context: true},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				storage := "GLOBL cell(SB),NOPTR,$14\n"
				var tail string
				declarations := "func patch()\n"
				if row.text {
					storage = ""
					tail = "TEXT cell(SB),NOSPLIT,$0-0\nBYTE $0xff; BYTE $0x2d; LONG $0\nLONG $0\nLONG $8\n"
					declarations += "func cell()\n"
				}
				source := storage + "TEXT patch(SB),NOSPLIT,$0-0\n" + row.initialize + "MOVL AX, cell+6(SB)\nRET\n" + tail
				x86LEAActualTargetGoObject(t, target.arch, target.triple, "#include \"textflag.h\"\n"+source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
						if row.context {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "MOVL AX, cell+6(SB)") {
								t.Fatal("static store invented numerical input or writable TEXT backing", err)
							}
						} else if err != nil || ir == "" {
							t.Fatal("initialized store to actual module-owned writable DATA failed", err)
						}
					})
				}
			})
		}
	}
}
