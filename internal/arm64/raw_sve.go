package arm64

import (
	"fmt"
	"math/bits"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// decodeSVEWord supplements x/arch with scalable-vector encodings. Keep the
// result in Plan 9 operand order so named and WORD use the same lowering.
func decodeSVEWord(w uint32) (asm.Instr, bool) {
	const (
		rd   = uint32(31)
		rn   = rd << 5
		rm   = rd << 16
		pg   = uint32(7 << 10)
		size = uint32(3 << 22)
	)
	d, n, m := w&rd, w>>5&rd, w>>16&rd
	es := "BHSD"[w>>22&3]
	matches := func(base, fields uint32) bool { return (base^w)&^fields == 0 }
	reg := func(s string) asm.Operand { return asm.Operand{Kind: asm.OpReg, Reg: asm.Reg(s)} }
	z := func(r uint32, width byte) asm.Operand { return reg(fmt.Sprintf("Z%d.%c", r, width)) }
	p := func(r uint32, suffix string) asm.Operand { return reg(fmt.Sprintf("P%d%s", r, suffix)) }
	x := func(r uint32, stack bool) asm.Operand {
		if r == 31 {
			if stack {
				return reg("RSP")
			}
			return reg("ZR")
		}
		return reg(fmt.Sprintf("R%d", r))
	}
	imm := func(v int64) asm.Operand { return asm.Operand{Kind: asm.OpImm, Imm: v} }
	op := func(name asm.Op, args ...asm.Operand) (asm.Instr, bool) {
		return asm.Instr{Op: name, Args: args, DecodedFromRaw: true, Raw: fmt.Sprintf("WORD $%#x", w)}, true
	}
	mem := func(vl int64) asm.Operand {
		a := asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: x(n, true).Reg}}
		if vl != 0 {
			a.Mem.OffRaw = fmt.Sprintf("VL*%d", vl)
		}
		return a
	}
	signed := func(v uint32, width uint) int64 { return int64(int32(v<<(32-width)) >> (32 - width)) }
	switch {
	case matches(0x04bf5000, 63<<5|rd): // RDVL Xd, #imm6
		return op("RDVL", imm(signed(w>>5, 6)), x(d, false))
	case matches(0x2518e3e0, size|15): // PTRUE (all)
		return op("PPTRUE", p(d&15, "."+string(es)))
	case matches(0x2538c000, size|0x3fff): // DUP Z.d, #simm8{, lsl #8}
		v := signed(w>>5, 8)
		if w>>13&1 != 0 {
			if es == 'B' {
				break
			}
			v <<= 8
		}
		return op("ZDUP", imm(v), z(d, es))
	case matches(0x05203800, size|rn|rd): // DUP (scalar)
		return op("ZDUP", x(n, true), z(d, es))
	case matches(0x05202000, 31<<16|3<<22|rn|rd): // DUP indexed element
		tsz := w >> 16 & 31
		if tsz == 0 {
			break
		}
		shift := bits.TrailingZeros32(tsz)
		if shift > 3 {
			break
		}
		width := "BHSD"[shift]
		lane := (w>>22&3)<<5 | tsz
		return op("ZDUP", reg(fmt.Sprintf("Z%d.%c[%d]", n, width, lane>>(shift+1))), z(d, width))
	case matches(0x04200000, size|rm|rn|rd):
		return op("ZADD", z(m, es), z(n, es), z(d, es))
	case matches(0x04203000, rm|rn|rd):
		return op("ZAND", z(m, 'D'), z(n, 'D'), z(d, 'D'))
	case matches(0x04a03000, rm|rn|rd):
		return op("ZEOR", z(m, 'D'), z(n, 'D'), z(d, 'D'))
	case matches(0x04209400, size|31<<16|rn|rd): // LSR (immediate)
		x := (w>>22&3)<<5 | (w >> 16 & 31)
		if x < 8 {
			break
		}
		sz := bits.Len32(x) - 4
		width := "BHSD"[sz]
		return op("ZLSR", imm(int64(16<<sz)-int64(x)), z(n, width), z(d, width))
	case matches(0x0520c000, size|rm|15<<10|rn|rd):
		return op("ZSEL", z(m, es), z(n, es), p(w>>10&15, ""), z(d, es))
	case matches(0x04100000, size|pg|rn|rd):
		return op("ZMUL", z(n, es), z(d, es), p(w>>10&7, ".M"), z(d, es))
	case matches(0x05203000, size|rm|rn|rd):
		list := asm.Operand{Kind: asm.OpRegList, RegList: []asm.Reg{z(n, es).Reg}}
		return op("ZTBL", z(m, es), list, z(d, es))
	case matches(0x45007800, size|rm|rn|rd) && w>>22&3 != 0:
		src := "BHSD"[(w>>22&3)-1]
		return op("ZUMULLB", z(m, src), z(n, src), z(d, es))
	case matches(0x85804000, 63<<16|7<<10|rn|rd), matches(0xe5804000, 63<<16|7<<10|rn|rd):
		off := signed((w>>16&63)<<3|(w>>10&7), 9)
		if w>>30&1 != 0 {
			return op("ZSTR", z(d, 'B'), mem(off))
		}
		return op("ZLDR", mem(off), z(d, 'B'))
	case matches(0xa5e0a000, 15<<16|pg|rn|rd), matches(0xe5e0e000, 15<<16|pg|rn|rd),
		matches(0xa5e04000, rm|pg|rn|rd), matches(0xe5e04000, rm|pg|rn|rd):
		a := mem(0)
		if w>>15&1 == 0 {
			if m == 31 {
				return asm.Instr{}, false
			}
			a.Mem.Index = x(m, false).Reg
			a.Mem.Scale = 8
		} else {
			a = mem(signed(w>>16, 4))
		}
		g := w >> 10 & 7
		list := asm.Operand{Kind: asm.OpRegList, RegList: []asm.Reg{z(d, 'D').Reg}}
		if w>>30&1 != 0 {
			return op("ZST1D", list, p(g, ""), a)
		}
		return op("ZLD1D", a, p(g, ".Z"), list)
	}
	return asm.Instr{}, false
}
