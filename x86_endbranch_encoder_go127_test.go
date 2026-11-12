//go:build go1.27

package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86EndBranchCurrentGoEncoderRow(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	for _, row := range []string{
		"varynone=[]ytab{{Zlit,1,argList{}},}",
		"{AENDBR64,ynone,Pf3,opBytes{0x1e,0xfa}},",
	} {
		if !strings.Contains(compact, row) {
			t.Fatal("complete operand-free Go ENDBR row changed", row)
		}
	}
	if strings.Contains(compact, "{AENDBR32,") {
		t.Fatal("Go added an ENDBR32 mnemonic; revisit the raw-only contract")
	}
	for _, arch := range []string{"386", "amd64"} {
		code := assembleX87ControlBytes(t, arch, "TEXT marker(SB),4,$0-0\nENDBR64\nRET\n")
		if !bytes.Equal(code, []byte{0xf3, 0x0f, 0x1e, 0xfa, 0xc3}) {
			t.Fatalf("original Go %s ENDBR bytes changed: %x", arch, code)
		}
	}
}
