package plan9asm

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestGoAMD64FrameListingHexASCII(t *testing.T) {
	const assembly = `TEXT ·Value(SB),4,$16-16
	MOVQ a+0(FP),AX
	MOVQ AX,0(SP)
	MOVQ 0(SP),AX
	MOVQ AX,ret+8(FP)
	RET
TEXT ·HexASCII(SB),4,$0-0
	XORB (R8),AH
	RET
`
	pkg, request, _, _ := fixedLocalTransportFixture(t, assembly,
		"func Value(a uint64) uint64\nfunc HexASCII()\n", "linux/amd64", "x86_64-unknown-linux-gnu")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("complete original Go listing with hex-looking ASCII", err)
	}
	defer source.Close()
	fn, found := source.functions[pkg.Path+".HexASCII"]
	if !found || !bytes.Equal(fn.code, []byte{0x41, 0x32, 0x20, 0xc3}) {
		t.Fatalf("Go listing ASCII was interpreted as an instruction byte: %x", fn.code)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
