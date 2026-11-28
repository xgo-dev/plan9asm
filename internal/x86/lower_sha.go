package x86

import (
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Bit-exact target-independent LLVM IR lowerers for Intel SHA-NI instructions:
//   - SHA256MSG1, SHA256MSG2, SHA256RNDS2
//   - SHA1MSG1, SHA1MSG2, SHA1NEXTE, SHA1RNDS4
//
// Emitting portable LLVM IR (rather than +sha intrinsics) guarantees bit-exact
// Intel SDM / FIPS 180-4 semantics across every x86-64/386 CPU baseline without
// requiring target +sha feature flags.

func (c *amd64Ctx) shaIR(format string, args ...any) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = "+format+"\n", append([]any{t}, args...)...)
	return "%" + t
}

func (c *amd64Ctx) shaRotL32(x string, n int) string {
	return c.shaIR("call i32 @llvm.fshl.i32(i32 %s, i32 %s, i32 %d)", x, x, n)
}

func (c *amd64Ctx) shaRotR32(x string, n int) string {
	return c.shaIR("call i32 @llvm.fshr.i32(i32 %s, i32 %s, i32 %d)", x, x, n)
}

func (c *amd64Ctx) sha256Sigma0(a string) string {
	r2 := c.shaRotR32(a, 2)
	r13 := c.shaRotR32(a, 13)
	r22 := c.shaRotR32(a, 22)
	return c.shaIR("xor i32 %s, %s", c.shaIR("xor i32 %s, %s", r2, r13), r22)
}

func (c *amd64Ctx) sha256Sigma1(e string) string {
	r6 := c.shaRotR32(e, 6)
	r11 := c.shaRotR32(e, 11)
	r25 := c.shaRotR32(e, 25)
	return c.shaIR("xor i32 %s, %s", c.shaIR("xor i32 %s, %s", r6, r11), r25)
}

func (c *amd64Ctx) sha256LowerSigma1(x string) string {
	r17 := c.shaRotR32(x, 17)
	r19 := c.shaRotR32(x, 19)
	s10 := c.shaIR("lshr i32 %s, 10", x)
	return c.shaIR("xor i32 %s, %s", c.shaIR("xor i32 %s, %s", r17, r19), s10)
}

func (c *amd64Ctx) shaCh32(e, f, g string) string {
	ef := c.shaIR("and i32 %s, %s", e, f)
	ne := c.shaIR("xor i32 %s, -1", e)
	neg := c.shaIR("and i32 %s, %s", ne, g)
	return c.shaIR("xor i32 %s, %s", ef, neg)
}

func (c *amd64Ctx) shaMaj32(a, b, cv string) string {
	ab := c.shaIR("and i32 %s, %s", a, b)
	ac := c.shaIR("and i32 %s, %s", a, cv)
	bc := c.shaIR("and i32 %s, %s", b, cv)
	return c.shaIR("xor i32 %s, %s", c.shaIR("xor i32 %s, %s", ab, ac), bc)
}

func (c *amd64Ctx) shaExtract4(vec string) [4]string {
	var lanes [4]string
	for i := 0; i < 4; i++ {
		lanes[i] = c.shaIR("extractelement <4 x i32> %s, i32 %d", vec, i)
	}
	return lanes
}

func (c *amd64Ctx) shaPack4(lanes [4]string) string {
	cur := "poison"
	for i := 0; i < 4; i++ {
		cur = c.shaIR("insertelement <4 x i32> %s, i32 %s, i32 %d", cur, lanes[i], i)
	}
	return cur
}

func (c *amd64Ctx) lowerSHA256Msg1(ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA256MSG1 expects Xsrc, Xdst: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
		return fmt.Errorf("amd64 SHA256MSG1 dst must be Xreg: %q", ins.Raw)
	}
	src, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return err
	}
	dst, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	s32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", src)
	d32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dst)
	// [W1, W2, W3, W4] where W0..W3 = dst[0..3], W4 = src[0].
	w1234 := c.shaIR("shufflevector <4 x i32> %s, <4 x i32> %s, <4 x i32> <i32 1, i32 2, i32 3, i32 4>", d32, s32)
	r7 := c.shaIR("call <4 x i32> @llvm.fshr.v4i32(<4 x i32> %s, <4 x i32> %s, <4 x i32> <i32 7, i32 7, i32 7, i32 7>)", w1234, w1234)
	r18 := c.shaIR("call <4 x i32> @llvm.fshr.v4i32(<4 x i32> %s, <4 x i32> %s, <4 x i32> <i32 18, i32 18, i32 18, i32 18>)", w1234, w1234)
	s3 := c.shaIR("lshr <4 x i32> %s, <i32 3, i32 3, i32 3, i32 3>", w1234)
	sig0 := c.shaIR("xor <4 x i32> %s, %s", c.shaIR("xor <4 x i32> %s, %s", r7, r18), s3)
	res := c.shaIR("add <4 x i32> %s, %s", d32, sig0)
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(ins.Args[1].Reg, out)
}

func (c *amd64Ctx) lowerSHA256Msg2(ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA256MSG2 expects Xsrc, Xdst: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
		return fmt.Errorf("amd64 SHA256MSG2 dst must be Xreg: %q", ins.Raw)
	}
	src, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return err
	}
	dst, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	s32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", src)
	d32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dst)
	sl := c.shaExtract4(s32)
	dl := c.shaExtract4(d32)
	// W14 = src[2], W15 = src[3]
	w16 := c.shaIR("add i32 %s, %s", dl[0], c.sha256LowerSigma1(sl[2]))
	w17 := c.shaIR("add i32 %s, %s", dl[1], c.sha256LowerSigma1(sl[3]))
	w18 := c.shaIR("add i32 %s, %s", dl[2], c.sha256LowerSigma1(w16))
	w19 := c.shaIR("add i32 %s, %s", dl[3], c.sha256LowerSigma1(w17))
	res := c.shaPack4([4]string{w16, w17, w18, w19})
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(ins.Args[1].Reg, out)
}

func (c *amd64Ctx) lowerSHA256Rnds2(ins asm.Instr) error {
	var wkOp, srcOp, dstOp asm.Operand
	switch len(ins.Args) {
	case 3:
		// Plan 9 3-operand form: SHA256RNDS2 X0, src, dst
		wkOp, srcOp, dstOp = ins.Args[0], ins.Args[1], ins.Args[2]
	case 2:
		// Implicit-X0 form: SHA256RNDS2 src, dst
		wkOp = asm.Operand{Kind: asm.OpReg, Reg: asm.Reg("X0")}
		srcOp, dstOp = ins.Args[0], ins.Args[1]
	default:
		return fmt.Errorf("amd64 SHA256RNDS2 expects [X0,] Xsrc, Xdst: %q", ins.Raw)
	}
	if dstOp.Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA256RNDS2 dst must be Xreg: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(dstOp.Reg); !ok {
		return fmt.Errorf("amd64 SHA256RNDS2 dst must be Xreg: %q", ins.Raw)
	}
	wkBytes, err := c.loadXVecOperand(wkOp)
	if err != nil {
		return err
	}
	srcBytes, err := c.loadXVecOperand(srcOp)
	if err != nil {
		return err
	}
	dstBytes, err := c.loadX(dstOp.Reg)
	if err != nil {
		return err
	}
	wk32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", wkBytes)
	src32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", srcBytes)
	dst32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dstBytes)
	wl := c.shaExtract4(wk32)
	sl := c.shaExtract4(src32) // [F0, E0, B0, A0]
	dl := c.shaExtract4(dst32) // [H0, G0, D0, C0]

	a, b, cv, d := sl[3], sl[2], dl[3], dl[2]
	e, f, g, h := sl[1], sl[0], dl[1], dl[0]

	for round := 0; round < 2; round++ {
		t1 := c.shaIR("add i32 %s, %s", h, c.sha256Sigma1(e))
		t1 = c.shaIR("add i32 %s, %s", t1, c.shaCh32(e, f, g))
		t1 = c.shaIR("add i32 %s, %s", t1, wl[round])
		t2 := c.shaIR("add i32 %s, %s", c.sha256Sigma0(a), c.shaMaj32(a, b, cv))
		nextA := c.shaIR("add i32 %s, %s", t1, t2)
		nextE := c.shaIR("add i32 %s, %s", d, t1)
		h, g, f, e = g, f, e, nextE
		d, cv, b, a = cv, b, a, nextA
	}

	res := c.shaPack4([4]string{f, e, b, a})
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(dstOp.Reg, out)
}

func (c *amd64Ctx) lowerSHA1NextE(ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA1NEXTE expects Xsrc, Xdst: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
		return fmt.Errorf("amd64 SHA1NEXTE dst must be Xreg: %q", ins.Raw)
	}
	src, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return err
	}
	dst, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	s32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", src)
	d32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dst)
	dHi := c.shaIR("extractelement <4 x i32> %s, i32 3", d32)
	sHi := c.shaIR("extractelement <4 x i32> %s, i32 3", s32)
	rot := c.shaRotL32(dHi, 30)
	sum := c.shaIR("add i32 %s, %s", sHi, rot)
	res := c.shaIR("insertelement <4 x i32> %s, i32 %s, i32 3", s32, sum)
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(ins.Args[1].Reg, out)
}

func (c *amd64Ctx) lowerSHA1Msg1(ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA1MSG1 expects Xsrc, Xdst: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
		return fmt.Errorf("amd64 SHA1MSG1 dst must be Xreg: %q", ins.Raw)
	}
	src, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return err
	}
	dst, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	s32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", src)
	d32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dst)
	// dst = [W3, W2, W1, W0], src = [W7, W6, W5, W4]
	// out = [W3^W5, W2^W4, W1^W3, W0^W2]
	partner := c.shaIR("shufflevector <4 x i32> %s, <4 x i32> %s, <4 x i32> <i32 6, i32 7, i32 0, i32 1>", d32, s32)
	res := c.shaIR("xor <4 x i32> %s, %s", d32, partner)
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(ins.Args[1].Reg, out)
}

func (c *amd64Ctx) lowerSHA1Msg2(ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA1MSG2 expects Xsrc, Xdst: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(ins.Args[1].Reg); !ok {
		return fmt.Errorf("amd64 SHA1MSG2 dst must be Xreg: %q", ins.Raw)
	}
	src, err := c.loadXVecOperand(ins.Args[0])
	if err != nil {
		return err
	}
	dst, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	s32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", src)
	d32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dst)
	sl := c.shaExtract4(s32)
	dl := c.shaExtract4(d32)
	// W13 = src[2], W14 = src[1], W15 = src[0]
	w16 := c.shaRotL32(c.shaIR("xor i32 %s, %s", dl[3], sl[2]), 1)
	w17 := c.shaRotL32(c.shaIR("xor i32 %s, %s", dl[2], sl[1]), 1)
	w18 := c.shaRotL32(c.shaIR("xor i32 %s, %s", dl[1], sl[0]), 1)
	w19 := c.shaRotL32(c.shaIR("xor i32 %s, %s", dl[0], w16), 1)
	res := c.shaPack4([4]string{w19, w18, w17, w16})
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(ins.Args[1].Reg, out)
}

func (c *amd64Ctx) lowerSHA1Rnds4(ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("amd64 SHA1RNDS4 expects $imm, Xsrc, Xdst: %q", ins.Raw)
	}
	if _, ok := amd64ParseXReg(ins.Args[2].Reg); !ok {
		return fmt.Errorf("amd64 SHA1RNDS4 dst must be Xreg: %q", ins.Raw)
	}
	src, err := c.loadXVecOperand(ins.Args[1])
	if err != nil {
		return err
	}
	dst, err := c.loadX(ins.Args[2].Reg)
	if err != nil {
		return err
	}
	s32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", src)
	d32 := c.shaIR("bitcast <16 x i8> %s to <4 x i32>", dst)
	sl := c.shaExtract4(s32) // [W3, W2, W1, W0+E]
	dl := c.shaExtract4(d32) // [D, C, B, A]

	funcSel := ins.Args[0].Imm & 3
	var kConst int32
	switch funcSel {
	case 0:
		kConst = 0x5a827999
	case 1:
		kConst = 0x6ed9eba1
	case 2:
		kConst = -1894007588 // 0x8f1bbcdc
	default:
		kConst = -899497514 // 0xca62c1d6
	}
	words := [4]string{sl[3], sl[2], sl[1], sl[0]}
	a, b, cv, d := dl[3], dl[2], dl[1], dl[0]
	e := ""
	for r := 0; r < 4; r++ {
		var f string
		switch funcSel {
		case 0:
			f = c.shaCh32(b, cv, d)
		case 2:
			f = c.shaMaj32(b, cv, d)
		default:
			f = c.shaIR("xor i32 %s, %s", c.shaIR("xor i32 %s, %s", b, cv), d)
		}
		sum := c.shaIR("add i32 %s, %s", f, c.shaRotL32(a, 5))
		sum = c.shaIR("add i32 %s, %s", sum, words[r])
		sum = c.shaIR("add i32 %s, %d", sum, kConst)
		if r > 0 {
			sum = c.shaIR("add i32 %s, %s", sum, e)
		}
		nextC := c.shaRotL32(b, 30)
		e, d, cv, b, a = d, cv, nextC, a, sum
	}
	res := c.shaPack4([4]string{d, cv, b, a})
	out := c.shaIR("bitcast <4 x i32> %s to <16 x i8>", res)
	return c.storeX(ins.Args[2].Reg, out)
}
