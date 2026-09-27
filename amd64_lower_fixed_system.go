package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FixedSystemEffect uint8

const (
	amd64FixedSystemContinue amd64FixedSystemEffect = iota
	amd64FixedSystemTrap
	amd64FixedSystemControlTransfer
)

type amd64FixedSystemSpec struct {
	encoding string
	effect   amd64FixedSystemEffect
}

// amd64FixedSystemSpecs is the complete Go 1.27 operand-free system/state
// family that has no modeled GP-register data flow. Exact bytes keep Go's
// accepted 386 compatibility rows (notably ENDBR64 and SWAPGS) object-level
// compatible even when LLVM's mnemonic matcher applies architectural mode
// restrictions. Effects remain typed so traps and non-returning RSM cannot
// accidentally acquire ordinary fallthrough.
var amd64FixedSystemSpecs = map[Op]amd64FixedSystemSpec{
	"CLAC":    {encoding: ".byte 0x0f, 0x01, 0xca"},
	"CLI":     {encoding: ".byte 0xfa"},
	"CLTS":    {encoding: ".byte 0x0f, 0x06"},
	"ENDBR64": {encoding: ".byte 0xf3, 0x0f, 0x1e, 0xfa"},
	"ICEBP":   {encoding: ".byte 0xf1", effect: amd64FixedSystemTrap},
	"INVD":    {encoding: ".byte 0x0f, 0x08"},
	"RSM":     {encoding: ".byte 0x0f, 0xaa", effect: amd64FixedSystemControlTransfer},
	"STAC":    {encoding: ".byte 0x0f, 0x01, 0xcb"},
	"STI":     {encoding: ".byte 0xfb"},
	"SWAPGS":  {encoding: ".byte 0x0f, 0x01, 0xf8"},
	"UD1":     {encoding: ".byte 0x0f, 0xb9, 0x00", effect: amd64FixedSystemTrap},
	"WBINVD":  {encoding: ".byte 0x0f, 0x09"},
}

func (c *amd64Ctx) lowerFixedSystem(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64FixedSystemSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n",
		spec.encoding, "~{memory},~{dirflag},~{fpsr},~{flags}")
	if spec.effect == amd64FixedSystemContinue {
		return true, false, nil
	}
	c.b.WriteString("  unreachable\n")
	return true, true, nil
}
