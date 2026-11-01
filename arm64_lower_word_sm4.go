package plan9asm

import "fmt"

type arm64RawSM4Spec struct {
	base        uint32
	mask        uint32
	intrinsic   string
	destructive bool
}

// Arm DDI 0602: the Advanced SIMD SM4 family has only 128-bit, four-word
// register forms. Unlike SVE ZSM4E/ZSM4EKEY, Go exposes these through WORD.
// Keep decoding, implicit inputs, liveness and declarations on one spec.
var arm64RawSM4Specs = [...]arm64RawSM4Spec{
	{base: 0xcec08400, mask: 0xfffffc00, intrinsic: "sm4e", destructive: true},
	{base: 0xce60c800, mask: 0xffe0fc00, intrinsic: "sm4ekey"},
}

type arm64RawSM4 struct {
	spec                       arm64RawSM4Spec
	first, second, destination int
}

func decodeARM64RawSM4(word uint32) (arm64RawSM4, bool) {
	for _, spec := range arm64RawSM4Specs {
		if word&spec.mask != spec.base {
			continue
		}
		form := arm64RawSM4{
			spec: spec, destination: int(word & 31),
			first: int(word>>5) & 31, second: int(word>>16) & 31,
		}
		if spec.destructive {
			form.second = form.first
			form.first = form.destination
		}
		return form, true
	}
	return arm64RawSM4{}, false
}

func (c *arm64Ctx) lowerRawSM4(form arm64RawSM4) error {
	arrangement := arm64VectorArrangement{elementBits: 32, lanes: 4}
	reg := func(index int) Reg { return Reg(fmt.Sprintf("V%d.S4", index)) }
	first, err := c.loadARM64VectorInteger(reg(form.first), arrangement)
	if err != nil {
		return err
	}
	second, err := c.loadARM64VectorInteger(reg(form.second), arrangement)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> @llvm.aarch64.crypto.%s(<4 x i32> %s, <4 x i32> %s)\n",
		result, form.spec.intrinsic, first, second)
	return c.storeARM64VectorInteger(reg(form.destination), arrangement, "%"+result)
}
