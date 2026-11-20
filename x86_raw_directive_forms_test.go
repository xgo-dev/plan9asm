package plan9asm

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestX86RawDirectiveIntegerGrammar(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	if !strings.Contains(compact, "varybyte=[]ytab{{Zbyte,1,argList{Yi64}},}") {
		t.Fatal("Go's common raw directive table must have the one integer row")
	}
	// With its exact bits unchanged the float would decode as ordinary 0x90
	// padding, so a later instruction decoder cannot detect the wrong class.
	const bits = 0x9090909090909090
	floating := strconv.FormatFloat(math.Float64frombits(bits), 'g', -1, 64)
	for _, form := range []struct {
		op    string
		width int
	}{{"BYTE", 1}, {"WORD", 2}, {"LONG", 4}, {"QUAD", 8}} {
		if !strings.Contains(compact, "{A"+form.op+",ybyte,") {
			t.Fatalf("Go %s no longer uses the shared integer row", form.op)
		}
		for _, arch := range []string{"amd64", "386"} {
			t.Run(arch+"/"+form.op, func(t *testing.T) {
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				const declaration = "func RawBytes()\n"
				source := func(value string) string {
					return "TEXT ·RawBytes(SB),4,$0-0\n" + form.op + " $" + value + "\nRET\n"
				}
				integer := source("0x9090909090909090")
				want := append(bytes.Repeat([]byte{0x90}, form.width), 0xc3)
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
