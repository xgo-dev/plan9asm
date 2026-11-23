package plan9asm

import (
	"bytes"
	"math"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86OfficialDirectiveRows(t *testing.T) []goasmrules.X86DirectiveRow {
	t.Helper()
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86DirectiveRows(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestX86RawDirectiveIntegerGrammar(t *testing.T) {
	// With its exact bits unchanged the float would decode as ordinary 0x90
	// padding, so a later instruction decoder cannot detect the wrong class.
	const bits = 0x9090909090909090
	floating := strconv.FormatFloat(math.Float64frombits(bits), 'g', -1, 64)
	for _, row := range x86OfficialDirectiveRows(t) {
		if row.Bytes == 0 {
			continue
		}
		for _, arch := range []string{"amd64", "386"} {
			t.Run(arch+"/"+row.Opcode, func(t *testing.T) {
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				const declaration = "func RawBytes()\n"
				source := func(value string) string {
					return "TEXT ·RawBytes(SB),4,$0-0\n" + row.Opcode + " $" + value + "\nRET\n"
				}
				integer := source("0x9090909090909090")
				want := append(bytes.Repeat([]byte{0x90}, row.Bytes), 0xc3)
				if got := assembleX87ControlBytes(t, arch, integer); !bytes.Equal(got, want) {
					t.Fatalf("Go emitted %x, want %x", got, want)
				}
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, integer, declaration, arch, triple, api); err != nil {
						t.Fatalf("%s rejected integer padding: %v", api, err)
					}
					if _, err := x86ScalarFPBitViewAPI(t, source(floating), declaration, arch, triple, api); err == nil ||
						!strings.Contains(err.Error(), "resolved integer constant") {
						t.Errorf("%s failed to reject a floating raw directive before decoding: %v", api, err)
					}
				}
			})
		}
	}
}
