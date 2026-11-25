package x86

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
	"golang.org/x/arch/x86/x86asm"
)

// DecodeRawDirectives decodes contiguous BYTE/WORD/LONG/QUAD directives in an
// x86 instruction stream into canonical Plan 9 asm.Instr values marked with
// DecodedFromRaw=true. Non-raw instructions pass through unchanged.
//
// Decoding uses:
//  1. A compact table-driven 2-byte/3-byte VEX decoder for AVX/AVX2/FMA/VAES
//     encodings (which golang.org/x/arch/x86/x86asm v0.14.0 does not decode).
//  2. golang.org/x/arch/x86/x86asm.Decode + GoSyntax for the full legacy/SSE/
//     AESNI/system instruction space.
func DecodeRawDirectives(instrs []asm.Instr, goarch string) ([]asm.Instr, error) {
	mode := 64
	if goarch == "386" {
		mode = 32
	}
	out := make([]asm.Instr, 0, len(instrs))
	for i := 0; i < len(instrs); {
		if !isRawDataDirective(instrs[i].Op) {
			out = append(out, instrs[i])
			i++
			continue
		}
		var buf []byte
		var rawLines []string
		for i < len(instrs) && isRawDataDirective(instrs[i].Op) {
			chunk, err := rawDirectiveBytes(instrs[i])
			if err != nil {
				return nil, err
			}
			buf = append(buf, chunk...)
			rawLines = append(rawLines, instrs[i].Raw)
			i++
		}
		decoded, err := DecodeRawBytes(buf, mode)
		if err != nil {
			return nil, fmt.Errorf("decode raw x86 directives (%s): %w", strings.Join(rawLines, "; "), err)
		}
		joined := strings.Join(rawLines, "; ")
		for idx := range decoded {
			decoded[idx].DecodedFromRaw = true
			if decoded[idx].Raw == "" {
				decoded[idx].Raw = joined
			}
		}
		out = append(out, decoded...)
	}
	return out, nil
}

// DecodeRawBytes decodes a raw x86/amd64 machine-code byte slice (mode 32 or 64)
// into Plan 9 asm.Instr values.
func DecodeRawBytes(buf []byte, mode int) ([]asm.Instr, error) {
	if mode != 32 && mode != 64 {
		return nil, fmt.Errorf("unsupported x86 decode mode %d", mode)
	}
	var out []asm.Instr
	off := 0
	for off < len(buf) {
		if ins, n, ok, err := decodeVEX(buf[off:], mode); ok {
			if err != nil {
				return nil, fmt.Errorf("offset %d: %w", off, err)
			}
			out = append(out, ins)
			off += n
			continue
		}
		inst, err := x86asm.Decode(buf[off:], mode)
		if err != nil {
			return nil, fmt.Errorf("offset %d: %w", off, err)
		}
		if inst.Op == 0 || inst.Len <= 0 {
			return nil, fmt.Errorf("offset %d: unrecognized x86 byte sequence %x", off, buf[off:])
		}
		text := x86asm.GoSyntax(inst, 0, nil)
		parsed, err := parseDecodedPlan9Line(text)
		if err != nil {
			return nil, fmt.Errorf("offset %d (%q): %w", off, text, err)
		}
		parsed.DecodedFromRaw = true
		out = append(out, parsed)
		off += inst.Len
	}
	return out, nil
}

func isRawDataDirective(op asm.Op) bool {
	switch asm.Op(strings.ToUpper(string(op))) {
	case asm.OpBYTE, asm.OpWORD, asm.OpLONG, asm.OpQUAD:
		return true
	default:
		return false
	}
}

func rawDirectiveBytes(ins asm.Instr) ([]byte, error) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].ImmRaw != "" {
		return nil, fmt.Errorf("raw directive %q requires a constant immediate", ins.Raw)
	}
	v := uint64(ins.Args[0].Imm)
	switch asm.Op(strings.ToUpper(string(ins.Op))) {
	case asm.OpBYTE:
		return []byte{byte(v)}, nil
	case asm.OpWORD:
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(v))
		return b[:], nil
	case asm.OpLONG:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		return b[:], nil
	case asm.OpQUAD:
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v)
		return b[:], nil
	default:
		return nil, fmt.Errorf("unsupported raw directive %s", ins.Op)
	}
}

func parseDecodedPlan9Line(line string) (asm.Instr, error) {
	src := "TEXT _decode(SB),$0-0\n\t" + line + "\n\tRET\n"
	f, err := asm.Parse(asm.ArchAMD64, src)
	if err != nil {
		return asm.Instr{}, err
	}
	if len(f.Funcs) != 1 || len(f.Funcs[0].Instrs) < 2 {
		return asm.Instr{}, fmt.Errorf("failed to parse decoded instruction %q", line)
	}
	return f.Funcs[0].Instrs[1], nil
}

// vexKey indexes 2-byte/3-byte VEX SIMD instructions cleanly without giant switch trees.
type vexKey struct {
	opMap  uint8 // 1=0F, 2=0F38, 3=0F3A
	pp     uint8 // 0=none, 1=66, 2=F3, 3=F2
	opcode uint8
}

type vexEntry struct {
	op     asm.Op
	hasImm bool
	twoOp  bool // true for 2-operand forms where vvvv must be 0 (e.g. VMOVDQU)
}

var vexTable = map[vexKey]vexEntry{
	// map 0F (1), pp=66 (1): packed integer ALU & logical
	{1, 1, 0xFC}: {op: "VPADDB"},
	{1, 1, 0xFD}: {op: "VPADDW"},
	{1, 1, 0xFE}: {op: "VPADDD"},
	{1, 1, 0xD4}: {op: "VPADDQ"},
	{1, 1, 0xF8}: {op: "VPSUBB"},
	{1, 1, 0xF9}: {op: "VPSUBW"},
	{1, 1, 0xFA}: {op: "VPSUBD"},
	{1, 1, 0xFB}: {op: "VPSUBQ"},
	{1, 1, 0xD5}: {op: "VPMULLW"},
	{1, 1, 0xDB}: {op: "VPAND"},
	{1, 1, 0xEB}: {op: "VPOR"},
	{1, 1, 0xEF}: {op: "VPXOR"},
	{1, 1, 0xDA}: {op: "VPMINUB"},
	{1, 1, 0xDE}: {op: "VPMAXUB"},
	{1, 1, 0xEA}: {op: "VPMINSW"},
	{1, 1, 0xEE}: {op: "VPMAXSW"},
	{1, 1, 0x74}: {op: "VPCMPEQB"},
	{1, 1, 0x64}: {op: "VPCMPGTB"},
	{1, 1, 0x70}: {op: "VPSHUFD", hasImm: true, twoOp: true},
	// map 0F (1), pp=none/66: packed FP ALU & logical
	{1, 0, 0x58}: {op: "VADDPS"},
	{1, 1, 0x58}: {op: "VADDPD"},
	{1, 0, 0x5C}: {op: "VSUBPS"},
	{1, 1, 0x5C}: {op: "VSUBPD"},
	{1, 0, 0x59}: {op: "VMULPS"},
	{1, 1, 0x59}: {op: "VMULPD"},
	{1, 0, 0x5E}: {op: "VDIVPS"},
	{1, 1, 0x5E}: {op: "VDIVPD"},
	{1, 0, 0x54}: {op: "VANDPS"},
	{1, 1, 0x54}: {op: "VANDPD"},
	{1, 0, 0x56}: {op: "VORPS"},
	{1, 1, 0x56}: {op: "VORPD"},
	{1, 0, 0x57}: {op: "VXORPS"},
	{1, 1, 0x57}: {op: "VXORPD"},
	// map 0F38 (2), pp=66 (1): SSSE3/SSE4/AVX2/VAES
	{2, 1, 0x00}: {op: "VPSHUFB"},
	{2, 1, 0x40}: {op: "VPMULLD"},
	{2, 1, 0x38}: {op: "VPMINSB"},
	{2, 1, 0x3C}: {op: "VPMAXSB"},
	{2, 1, 0x3A}: {op: "VPMINUW"},
	{2, 1, 0x3E}: {op: "VPMAXUW"},
	{2, 1, 0x39}: {op: "VPMINSD"},
	{2, 1, 0x3D}: {op: "VPMAXSD"},
	{2, 1, 0x3B}: {op: "VPMINUD"},
	{2, 1, 0x3F}: {op: "VPMAXUD"},
	{2, 1, 0x78}: {op: "VPBROADCASTB", twoOp: true},
	{2, 1, 0x59}: {op: "VPBROADCASTQ", twoOp: true},
	// map 0F3A (3), pp=66 (1): imm8 SIMD
	{3, 1, 0x0F}: {op: "VPALIGNR", hasImm: true},
	{3, 1, 0x44}: {op: "VPCLMULQDQ", hasImm: true},
}

// decodeVEX decodes 2-byte (0xC5) and 3-byte (0xC4) VEX-encoded register-register
// SIMD instructions cleanly in Plan 9 operand order.
func decodeVEX(buf []byte, mode int) (asm.Instr, int, bool, error) {
	if len(buf) < 3 || (buf[0] != 0xC5 && buf[0] != 0xC4) {
		return asm.Instr{}, 0, false, nil
	}
	var (
		opMap   uint8
		pp      uint8
		regHigh uint8
		rmHigh  uint8
		vvvv    uint8
		vecL    uint8
		idx     int
	)
	if buf[0] == 0xC5 {
		b1 := buf[1]
		// In 32-bit mode, 0xC5 with mod!=11 (bits 7:6 != 11) is LDS, not VEX.
		if mode == 32 && b1&0xC0 != 0xC0 {
			return asm.Instr{}, 0, false, nil
		}
		opMap = 1 // 0F
		regHigh = (^b1 >> 7) & 1
		vvvv = (^b1 >> 3) & 0x0F
		vecL = (b1 >> 2) & 1
		pp = b1 & 0x03
		idx = 2
	} else {
		if len(buf) < 4 {
			return asm.Instr{}, 0, false, nil
		}
		b1, b2 := buf[1], buf[2]
		if mode == 32 && b1&0xC0 != 0xC0 {
			return asm.Instr{}, 0, false, nil
		}
		regHigh = (^b1 >> 7) & 1
		rmHigh = (^b1 >> 5) & 1
		opMap = b1 & 0x1F
		vvvv = (^b2 >> 3) & 0x0F
		vecL = (b2 >> 2) & 1
		pp = b2 & 0x03
		idx = 3
	}
	if mode == 32 {
		regHigh = 0
		rmHigh = 0
		vvvv &= 0x07
	}
	if idx >= len(buf) {
		return asm.Instr{}, 0, true, fmt.Errorf("truncated VEX instruction")
	}
	opcode := buf[idx]

	// Handle 3-byte VZEROUPPER (C5 F8 77) and VZEROALL (C5 FC 77) (and 4-byte 0xC4 forms)
	// without ModRM before checking ModRM byte length.
	if opMap == 1 && pp == 0 && opcode == 0x77 {
		if vecL == 0 {
			return asm.Instr{Op: "VZEROUPPER", Raw: "VZEROUPPER", DecodedFromRaw: true}, idx + 1, true, nil
		}
		return asm.Instr{Op: "VZEROALL", Raw: "VZEROALL", DecodedFromRaw: true}, idx + 1, true, nil
	}

	if idx+2 > len(buf) {
		return asm.Instr{}, 0, true, fmt.Errorf("truncated VEX instruction")
	}
	modrm := buf[idx+1]
	n := idx + 2

	entry, ok := vexTable[vexKey{opMap: opMap, pp: pp, opcode: opcode}]
	if !ok {
		return asm.Instr{}, 0, true, fmt.Errorf("unsupported VEX opcode map=%d pp=%d op=%#x", opMap, pp, opcode)
	}
	if modrm>>6 != 3 {
		return asm.Instr{}, 0, true, fmt.Errorf("VEX memory ModRM %#x for %s not yet decoded", modrm, entry.op)
	}
	dstIdx := int((regHigh << 3) | ((modrm >> 3) & 7))
	src1Idx := int((rmHigh << 3) | (modrm & 7))
	src2Idx := int(vvvv)

	prefix := "X"
	if vecL == 1 {
		prefix = "Y"
	}
	vecReg := func(i int) asm.Operand {
		return asm.Operand{Kind: asm.OpReg, Reg: asm.Reg(fmt.Sprintf("%s%d", prefix, i))}
	}

	var args []asm.Operand
	if entry.hasImm {
		if n >= len(buf) {
			return asm.Instr{}, 0, true, fmt.Errorf("truncated VEX imm8 for %s", entry.op)
		}
		args = append(args, asm.Operand{Kind: asm.OpImm, Imm: int64(buf[n])})
		n++
	}
	if entry.twoOp {
		args = append(args, vecReg(src1Idx), vecReg(dstIdx))
	} else {
		args = append(args, vecReg(src1Idx), vecReg(src2Idx), vecReg(dstIdx))
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = a.String()
	}
	return asm.Instr{
		Op:             entry.op,
		Args:           args,
		Raw:            fmt.Sprintf("%s %s", entry.op, strings.Join(parts, ", ")),
		DecodedFromRaw: true,
	}, n, true, nil
}
