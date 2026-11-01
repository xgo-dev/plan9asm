package plan9asm

import "fmt"

type arm64RawSM3Kind uint8

const (
	arm64SM3PARTW1 arm64RawSM3Kind = iota
	arm64SM3PARTW2
	arm64SM3SS1
	arm64SM3TT1A
	arm64SM3TT1B
	arm64SM3TT2A
	arm64SM3TT2B
)

type arm64RawSM3Spec struct {
	kind          arm64RawSM3Kind
	base, mask    uint32
	indexed       bool
	fourRegisters bool
}

// Arm DDI 0602, 2025-03, SM3PARTW1 through SM3TT2B: every form uses
// 128-bit SIMD registers, never GP register 30 or SP/ZR register 31. Go 1.27
// has no named NEON SM3 opcode; its WORD encoder emits the literal bits.
// The fixed-bit masks exclude adjacent SM4, SHA3 and reserved encodings.
var arm64RawSM3Specs = [...]arm64RawSM3Spec{
	{kind: arm64SM3PARTW1, base: 0xce60c000, mask: 0xffe0fc00},
	{kind: arm64SM3PARTW2, base: 0xce60c400, mask: 0xffe0fc00},
	{kind: arm64SM3SS1, base: 0xce400000, mask: 0xffe08000, fourRegisters: true},
	{kind: arm64SM3TT1A, base: 0xce408000, mask: 0xffe0cc00, indexed: true},
	{kind: arm64SM3TT1B, base: 0xce408400, mask: 0xffe0cc00, indexed: true},
	{kind: arm64SM3TT2A, base: 0xce408800, mask: 0xffe0cc00, indexed: true},
	{kind: arm64SM3TT2B, base: 0xce408c00, mask: 0xffe0cc00, indexed: true},
}

type arm64RawSM3 struct {
	spec                       arm64RawSM3Spec
	destination, first, second int
	third, lane                int
}

func decodeARM64RawSM3(word uint32) (arm64RawSM3, bool) {
	for _, spec := range arm64RawSM3Specs {
		if word&spec.mask != spec.base {
			continue
		}
		form := arm64RawSM3{
			spec: spec, destination: int(word & 31),
			first: int(word>>5) & 31, second: int(word>>16) & 31,
		}
		if spec.fourRegisters {
			form.third = int(word>>10) & 31
		}
		if spec.indexed {
			form.lane = int(word>>12) & 3
		}
		return form, true
	}
	return arm64RawSM3{}, false
}

// Use ordinary modulo-2^32 LLVM arithmetic, not a host SM3 assumption. The
// semantic oracle separately executes the original raw WORD with Go/QEMU.
// Read every input before writing the destination, including destructive d
// and all source/destination aliases. NZCV, GP and memory are unaffected.
func (c *arm64Ctx) lowerRawSM3(form arm64RawSM3) error {
	arrangement := arm64VectorArrangement{elementBits: 32, lanes: 4}
	reg := func(index int) Reg { return Reg(fmt.Sprintf("V%d.S4", index)) }
	load := func(index int) ([4]string, error) {
		var lanes [4]string
		vector, err := c.loadARM64VectorInteger(reg(index), arrangement)
		if err != nil {
			return lanes, err
		}
		for lane := range lanes {
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %s, i32 %d\n", name, vector, lane)
			lanes[lane] = "%" + name
		}
		return lanes, nil
	}
	n, err := load(form.first)
	if err != nil {
		return err
	}
	m, err := load(form.second)
	if err != nil {
		return err
	}
	var d, a [4]string
	if form.spec.fourRegisters {
		a, err = load(form.third)
	} else {
		d, err = load(form.destination)
	}
	if err != nil {
		return err
	}

	binary := func(op, left, right string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i32 %s, %s\n", name, op, left, right)
		return "%" + name
	}
	rotate := func(value string, amount int) string {
		return binary("or", binary("shl", value, fmt.Sprint(amount)),
			binary("lshr", value, fmt.Sprint(32-amount)))
	}
	xor3 := func(first, second, third string) string {
		return binary("xor", binary("xor", first, second), third)
	}
	p1 := func(value string) string {
		return xor3(value, rotate(value, 15), rotate(value, 23))
	}
	var result [4]string
	switch form.spec.kind {
	case arm64SM3PARTW1:
		for lane := 0; lane < 3; lane++ {
			result[lane] = p1(xor3(d[lane], n[lane], rotate(m[lane+1], 15)))
		}
		// The fourth word depends on the already permuted first result word.
		result[3] = p1(xor3(d[3], n[3], rotate(result[0], 15)))
	case arm64SM3PARTW2:
		var temporary [4]string
		for lane := range result {
			temporary[lane] = binary("xor", n[lane], rotate(m[lane], 7))
			result[lane] = binary("xor", d[lane], temporary[lane])
		}
		result[3] = binary("xor", result[3], p1(rotate(temporary[0], 15)))
	case arm64SM3SS1:
		sum := binary("add", binary("add", rotate(n[3], 12), m[3]), a[3])
		result = [4]string{"0", "0", "0", rotate(sum, 7)}
	case arm64SM3TT1A, arm64SM3TT1B, arm64SM3TT2A, arm64SM3TT2B:
		boolean := xor3(d[3], d[2], d[1])
		if form.spec.kind == arm64SM3TT1B {
			boolean = binary("or", binary("or", binary("and", d[3], d[1]),
				binary("and", d[3], d[2])), binary("and", d[1], d[2]))
		} else if form.spec.kind == arm64SM3TT2B {
			boolean = binary("or", binary("and", d[3], d[2]),
				binary("and", binary("xor", d[3], "-1"), d[1]))
		}
		ss := n[3]
		rotation := 19
		if form.spec.kind == arm64SM3TT1A || form.spec.kind == arm64SM3TT1B {
			ss = binary("xor", ss, rotate(d[3], 12))
			rotation = 9
		}
		tt := binary("add", binary("add", binary("add", boolean, d[0]), ss), m[form.lane])
		if rotation == 19 {
			tt = xor3(tt, rotate(tt, 9), rotate(tt, 17))
		}
		result = [4]string{d[1], rotate(d[2], rotation), d[3], tt}
	default:
		return fmt.Errorf("arm64 unsupported raw SM3 operation %d", form.spec.kind)
	}
	vector := "zeroinitializer"
	for lane, value := range result {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %s, i32 %s, i32 %d\n", name, vector, value, lane)
		vector = "%" + name
	}
	return c.storeARM64VectorInteger(reg(form.destination), arrangement, vector)
}
