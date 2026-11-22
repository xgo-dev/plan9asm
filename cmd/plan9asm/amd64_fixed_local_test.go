package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestSimpleCLIFixedLocalVSIB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for key, value := range map[string]string{
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "",
		"GOPACKAGESDRIVER": "off", "CGO_ENABLED": "0",
	} {
		t.Setenv(key, value)
	}
	const source = `#include "textflag.h"
TEXT ·Gather(SB),NOSPLIT,$64-16
MOVQ value+0(FP),AX
MOVQ AX,16(SP)
VPXOR X0,X0,X0
VPCMPEQD X0,X0,X0
VPXOR X1,X1,X1
VPXOR X2,X2,X2
VPGATHERQQ X0, 16(SP)(X1*1), X2
VMOVUPS X2,32(SP)
MOVQ 32(SP),AX
MOVQ AX,ret+8(FP)
RET
`
	const asmFile = "gather_amd64.s"
	for name, contents := range map[string]string{
		"go.mod":   "module example.invalid/stackgather\n\ngo 1.20\n",
		"value.go": "package stackgather\nfunc Gather(value uint64) uint64\n",
		asmFile:    source,
	} {
		if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "object-ir")
			if err := runTranspile([]string{"-goos", goos, "-goarch", "amd64", "-dir", out, "."}); err != nil {
				t.Fatal(err)
			}
			ir, err := os.ReadFile(filepath.Join(out, asmFile+".ll"))
			if err != nil || !strings.Contains(string(ir), "%fixed_local_native = alloca") ||
				!strings.Contains(string(ir), "load volatile i64") {
				t.Fatalf("the translated function lost its private-frame gather: %v\n%s", err, ir)
			}
		})
	}

	outOfFrame := strings.Replace(source, "16(SP)(X1*1)", "64(SP)(X1*1)", 1)
	if err := os.WriteFile(asmFile, []byte(outOfFrame), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "rejected.ll")
	err := runTranspile([]string{"-goos", "linux", "-goarch", "amd64", "-i", asmFile, "-o", out})
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || !strings.Contains(err.Error(), "VSIB lane crosses private storage") {
		t.Fatalf("expected the fixed-local lane bounds check: %v", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected translation left an output: %v", err)
	}
}
