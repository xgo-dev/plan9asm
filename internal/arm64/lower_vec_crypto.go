package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

// Encodings use V0 for the destination and V1..V3 for the native sources.
// Constrain only the instruction itself: enabling +crypto on a whole function
// would also permit crypto instructions before a runtime feature check.
var cryptoEncoding = map[asm.Op]struct {
	word     uint32
	sources  int
	readsDst bool
}{
	"AESE":      {0x4e284820, 1, true},  // aese v0.16b,v1.16b
	"AESD":      {0x4e285820, 1, true},  // aesd v0.16b,v1.16b
	"AESMC":     {0x4e286820, 1, false}, // aesmc v0.16b,v1.16b
	"AESIMC":    {0x4e287820, 1, false}, // aesimc v0.16b,v1.16b
	"SHA1C":     {0x5e020020, 2, true},  // sha1c q0,s1,v2.4s
	"SHA1M":     {0x5e022020, 2, true},  // sha1m q0,s1,v2.4s
	"SHA1P":     {0x5e021020, 2, true},  // sha1p q0,s1,v2.4s
	"SHA1H":     {0x5e280820, 1, false}, // sha1h s0,s1
	"SHA1SU0":   {0x5e023020, 2, true},  // sha1su0 v0.4s,v1.4s,v2.4s
	"SHA1SU1":   {0x5e281820, 1, true},  // sha1su1 v0.4s,v1.4s
	"SHA256H":   {0x5e024020, 2, true},  // sha256h q0,q1,v2.4s
	"SHA256H2":  {0x5e025020, 2, true},  // sha256h2 q0,q1,v2.4s
	"SHA256SU0": {0x5e282820, 1, true},  // sha256su0 v0.4s,v1.4s
	"SHA256SU1": {0x5e026020, 2, true},  // sha256su1 v0.4s,v1.4s,v2.4s
	"SHA512H":   {0xce628020, 2, true},  // sha512h q0,q1,v2.2d
	"SHA512H2":  {0xce628420, 2, true},  // sha512h2 q0,q1,v2.2d
	"SHA512SU0": {0xcec08020, 1, true},  // sha512su0 v0.2d,v1.2d
	"SHA512SU1": {0xce628820, 2, true},  // sha512su1 v0.2d,v1.2d,v2.2d
	"VEOR3":     {0xce020c20, 3, false}, // eor3 v0.16b,v1.16b,v2.16b,v3.16b
	"VBCAX":     {0xce220c20, 3, false}, // bcax v0.16b,v1.16b,v2.16b,v3.16b
	"VRAX1":     {0xce628c20, 2, false}, // rax1 v0.2d,v1.2d,v2.2d
	"VXAR":      {0xce820020, 2, false}, // xar v0.2d,v1.2d,v2.2d,#0
	"VPMULL":    {0x0ee2e020, 2, false}, // pmull v0.1q,v1.1d,v2.1d
	"VPMULL2":   {0x4ee2e020, 2, false}, // pmull2 v0.1q,v1.2d,v2.2d
	"VPMULLB":   {0x0e22e020, 2, false}, // pmull v0.8h,v1.8b,v2.8b
	"VPMULL2B":  {0x4e22e020, 2, false}, // pmull2 v0.8h,v1.16b,v2.16b
}

func (c *arm64Ctx) lowerCrypto(op asm.Op, ins asm.Instr) error {
	if !c.nativeAArch64 {
		return fmt.Errorf("%w: %s needs an AArch64 target", asm.ErrProbeNeedsContext, op)
	}
	args := ins.Args
	var imm uint32
	if op == "VXAR" {
		if len(args) < 1 || args[0].Kind != asm.OpImm || args[0].ImmRaw != "" || args[0].Imm < 0 || args[0].Imm > 63 {
			return fmt.Errorf("invalid VXAR rotation: %s", ins.Raw)
		}
		imm = uint32(args[0].Imm) << 10
		args = args[1:]
	}
	if (op == "VPMULL" || op == "VPMULL2") && len(args) > 0 && strings.Contains(string(args[0].Reg), ".B") {
		op += "B"
	}
	d := cryptoEncoding[op]
	if len(args) != 1+d.sources {
		return fmt.Errorf("invalid %s operand count: %s", op, ins.Raw)
	}
	for _, a := range args {
		if _, ok := arm64ParseVReg(a.Reg); a.Kind != asm.OpReg || !ok {
			return fmt.Errorf("invalid %s vector register: %s", op, ins.Raw)
		}
	}
	dst := args[len(args)-1].Reg
	constraints := []string{"={v0}"}
	var inputs []string
	for i := 1; i <= d.sources; i++ {
		v, err := c.loadVReg(args[len(args)-i-1].Reg)
		if err != nil {
			return err
		}
		constraints = append(constraints, fmt.Sprintf("{v%d}", i))
		inputs = append(inputs, "<16 x i8> "+v)
	}
	if d.readsDst {
		v, err := c.loadVReg(dst)
		if err != nil {
			return err
		}
		constraints = append(constraints, "0")
		inputs = append(inputs, "<16 x i8> "+v)
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <16 x i8> asm \".inst 0x%08x\", %q(%s)\n", t, d.word|imm, strings.Join(constraints, ","), strings.Join(inputs, ", "))
	return c.storeVReg(dst, "%"+t)
}
