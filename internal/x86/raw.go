package x86

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/goversion"
	"golang.org/x/arch/x86/x86asm"
)

// PrepareFile normalizes executable bytes and target ABI operands before
// selecting a lowering path. Unchanged files are returned without copying.
func PrepareFile(file *asm.File, goarch, triple string) (*asm.File, error) {
	result := file
	target := ""
	if matchesX86Target(goarch, triple) {
		triple = strings.ToLower(triple)
		parts := strings.Split(triple, "-")
		for _, part := range parts[1:] {
			switch strings.TrimRight(part, "0123456789.") {
			case "windows":
				target = "windows"
			case "linux":
				if !strings.Contains(triple, "android") && !strings.Contains(triple, "ohos") && !strings.Contains(triple, "liteos") {
					target = "linux"
				}
			case "darwin", "macos", "macosx":
				if goarch == "amd64" {
					target = "darwin"
				}
			}
		}
	}
	legacyWindowsTLS := false
	if target == "windows" && goarch == "386" {
		legacy, known, err := classifyVEHDispatch(file)
		if err != nil {
			return nil, err
		}
		version := file.SourceGoVersion
		if known && version == "" {
			legacyWindowsTLS = legacy
		} else {
			if version == "" {
				version = runtime.Version()
			}
			minor, ok := goversion.ParseMinor(version)
			if !ok {
				return nil, fmt.Errorf("%w: invalid Windows/386 source Go version %q", asm.ErrProbeNeedsContext, version)
			}
			legacyWindowsTLS = minor <= 20
			if known && legacyWindowsTLS != legacy {
				return nil, fmt.Errorf("%w: Windows/386 VEH dispatcher disagrees with source Go version %s", asm.ErrProbeNeedsContext, version)
			}
		}
	}
	for i, fn := range file.Funcs {
		if target == "windows" && goarch == "386" && (matchesVEHBody(fn, vehDispatchBody) || matchesVEHBody(fn, legacyVEHBody)) {
			continue
		}
		if b, _ := rawFunctionPayload(fn); b != nil {
			continue
		}
		bound, err := bindPCBranches(fn.Instrs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Sym, err)
		}
		var out []asm.Instr
		if bound != nil {
			fn.Instrs = bound
			out = make([]asm.Instr, 0, len(bound))
		}
		for j := 0; j < len(fn.Instrs); {
			ins := fn.Instrs[j]
			normalized, namedSlot := normalizeExprAddress(ins, fn.FrameSize)
			if namedSlot {
				ins = normalized
			}
			end := j + 1
			var replacement []asm.Instr
			var err error
			if isRawDataDirective(ins.Op) {
				for end < len(fn.Instrs) && isRawDataDirective(fn.Instrs[end].Op) {
					end++
				}
				replacement, err = DecodeRawDirectives(fn.Instrs[j:end], goarch)
			} else {
				replacement, err = goTLSInstructions(ins, goarch, target, legacyWindowsTLS)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", fn.Sym, err)
			}
			if replacement == nil && namedSlot {
				replacement = []asm.Instr{ins}
			}
			if replacement != nil {
				if out == nil {
					out = append(make([]asm.Instr, 0, len(fn.Instrs)), fn.Instrs[:j]...)
				}
				out = append(out, replacement...)
			} else if out != nil {
				out = append(out, ins)
			}
			j = end
		}
		if out != nil {
			if result == file {
				copyFile := *file
				copyFile.Funcs = append([]asm.Func(nil), file.Funcs...)
				result = &copyFile
			}
			result.Funcs[i].Instrs = out
		}
	}
	return result, nil
}

// A named SP slot refers to the top of the virtual Go frame. Resolve a
// parenthesized constant expression that the generic memory parser kept as
// a symbol (e.g. r15-(14*8+8)(SP) in runtime.debugCallV2).
func normalizeExprAddress(ins asm.Instr, frameSize int64) (asm.Instr, bool) {
	changed := false
	for i, arg := range ins.Args {
		if arg.Kind != asm.OpSym || !strings.HasSuffix(arg.Sym, ")") {
			continue
		}
		at := strings.LastIndexByte(arg.Sym, '(')
		if at <= 0 {
			continue
		}
		base, ok := asm.ParseReg(arg.Sym[at+1 : len(arg.Sym)-1])
		if !ok || base == asm.PC || base == "FP" {
			continue
		}
		expr := arg.Sym[:at]
		n, ok := asm.ParseImmExpr(expr)
		if !ok {
			sep := strings.IndexAny(expr, "+-")
			if base != asm.SP || sep <= 0 || strings.ContainsAny(expr[:sep], "/()$* ") {
				continue
			}
			n, ok = asm.ParseImmExpr(expr[sep:])
			if !ok {
				continue
			}
			n += uint64(frameSize)
		}

		if !changed {
			ins.Args = append([]asm.Operand(nil), ins.Args...)
			changed = true
		}
		mem := asm.MemRef{Base: base, Off: int64(n)}
		if base == asm.GS || base == asm.FS {
			mem.Base, mem.Segment = "", base
		}
		ins.Args[i] = asm.Operand{Kind: asm.OpMem, Mem: mem}
	}
	return ins, changed
}

// Go's binary-identification markers are whole functions with one short JMP
// over opaque bytes to RET. Decoding these bytes as instructions would reject
// arbitrary marker payloads or attach instruction semantics to pure data.
func rawFunctionPayload(fn asm.Func) ([]byte, bool) {
	if len(fn.Instrs) < 2 || fn.Instrs[0].Op != asm.OpTEXT || fn.Instrs[1].Op != asm.OpBYTE ||
		len(fn.Instrs[1].Args) != 1 {
		return nil, false
	}
	first := fn.Instrs[1].Args[0].Imm
	if first != 0xeb && first != 0xe8 {
		return nil, false
	}
	var data []byte
	for _, ins := range fn.Instrs[1:] {
		b, err := rawDirectiveBytes(ins)
		if err != nil {
			return nil, false
		}
		data = append(data, b...)
	}
	if len(data) >= 3 && data[0] == 0xeb && int(int8(data[1]))+3 == len(data) && data[len(data)-1] == 0xc3 {
		return data, false
	}
	// The Go compiler emits register retpolines as a self-contained machine
	// code thunk; the hardware return-stack behavior is part of its contract.
	// Only these exact relocation-free encodings can execute as a prologue.
	if len(data) == 14 && bytes.Equal(data[:9], []byte{0xe8, 4, 0, 0, 0, 0xf3, 0x90, 0xeb, 0xfc}) &&
		(data[9] == 0x48 || data[9] == 0x4c) && data[10] == 0x89 && data[11]&0xc7 == 4 &&
		data[12] == 0x24 && data[13] == 0xc3 && !(data[9] == 0x48 && data[11] == 0x24) {
		return data, true
	}
	return nil, false
}

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
		for _, p := range inst.Prefix {
			if p&x86asm.PrefixInvalid != 0 {
				return nil, fmt.Errorf("offset %d: invalid x86 prefix %#x", off, p)
			}
		}
		if inst.Op == 0 || inst.Len <= 0 {
			return nil, fmt.Errorf("offset %d: unrecognized x86 byte sequence %x", off, buf[off:])
		}
		// Raw displacements are relative to machine-code bytes. Plan 9 (PC)
		// operands and CFG labels use instruction positions instead.
		for _, arg := range inst.Args {
			switch v := arg.(type) {
			case x86asm.Rel:
				return nil, fmt.Errorf("offset %d: %w: raw PC-relative branch requires original code layout", off, asm.ErrProbeNeedsContext)
			case x86asm.Mem:
				if v.Base == x86asm.RIP || v.Base == x86asm.EIP {
					return nil, fmt.Errorf("offset %d: %w: raw PC-relative memory requires original code layout", off, asm.ErrProbeNeedsContext)
				}
			}
		}
		if inst.Op == x86asm.RET && inst.Args[0] != nil {
			return nil, fmt.Errorf("offset %d: %w: raw RET with stack cleanup requires the callee calling convention", off, asm.ErrProbeNeedsContext)
		}
		text := x86asm.GoSyntax(inst, 0, nil)
		parsed, err := parseDecodedPlan9Line(text)
		if err != nil {
			return nil, fmt.Errorf("offset %d (%q): %w", off, text, err)
		}
		// GoSyntax includes the segment in the displacement text. Recover it
		// from the decoder so it cannot be parsed as a symbolic displacement.
		for _, arg := range inst.Args {
			m, ok := arg.(x86asm.Mem)
			if !ok || m.Segment == 0 {
				continue
			}
			if m.Segment != x86asm.FS && m.Segment != x86asm.GS || inst.Op != x86asm.MOV {
				return nil, fmt.Errorf("offset %d: unsupported segment address in %s", off, inst.Op)
			}
			found := false
			for i := range parsed.Args {
				if parsed.Args[i].Kind != asm.OpMem {
					continue
				}
				parsed.Args[i].Mem.Segment = asm.Reg(m.Segment.String())
				parsed.Args[i].Mem.Off = m.Disp
				found = true
			}
			if !found {
				return nil, fmt.Errorf("offset %d: unsupported segmented operand in %s", off, text)
			}
		}
		switch inst.Op {
		case x86asm.MOVZX, x86asm.MOVSX, x86asm.MOVSXD:
			srcBytes := inst.MemBytes
			if reg, ok := inst.Args[1].(x86asm.Reg); ok {
				switch {
				case reg >= x86asm.AL && reg <= x86asm.R15B:
					srcBytes = 1
				case reg >= x86asm.AX && reg <= x86asm.R15W:
					srcBytes = 2
				case reg >= x86asm.EAX && reg <= x86asm.R15L:
					srcBytes = 4
				}
			}
			suffix := "SX"
			if inst.Op == x86asm.MOVZX {
				suffix = "ZX"
			}
			width := func(b int) string {
				switch b {
				case 1:
					return "B"
				case 2:
					return "W"
				case 4:
					return "L"
				case 8:
					return "Q"
				}
				return ""
			}
			src, dst := width(srcBytes), width(inst.DataSize/8)
			if src == "" || dst == "" {
				return nil, fmt.Errorf("offset %d: invalid %s widths %d/%d", off, inst.Op, srcBytes, inst.DataSize)
			}
			parsed.Op = asm.Op("MOV" + src + dst + suffix)
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
	if len(f.Funcs) != 1 || len(f.Funcs[0].Instrs) != 3 {
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
	op             asm.Op
	hasImm         bool
	blockBroadcast bool // VEX.256.66.0F38.W0: m128 -> YMM
	twoOp          bool // true for 2-operand forms where vvvv must be 0 (e.g. VMOVDQU)
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
	{1, 1, 0xf4}: {op: "VPMULUDQ"},
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
	{2, 1, 0x1a}: {op: "VBROADCASTF128", twoOp: true, blockBroadcast: true},
	{2, 1, 0x5a}: {op: "VBROADCASTI128", twoOp: true, blockBroadcast: true},
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
		if vvvv >= 8 {
			return asm.Instr{}, 0, true, fmt.Errorf("unencodable VEX.vvvv in 32-bit mode")
		}
	}
	if idx >= len(buf) {
		return asm.Instr{}, 0, true, fmt.Errorf("truncated VEX instruction")
	}
	opcode := buf[idx]

	// Handle 3-byte VZEROUPPER (C5 F8 77) and VZEROALL (C5 FC 77) (and 4-byte 0xC4 forms)
	// without ModRM before checking ModRM byte length.
	if opMap == 1 && pp == 0 && opcode == 0x77 {
		if vvvv != 0 {
			return asm.Instr{}, 0, true, fmt.Errorf("reserved VEX.vvvv on VZEROUPPER/VZEROALL")
		}
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
	if entry.twoOp && vvvv != 0 {
		return asm.Instr{}, 0, true, fmt.Errorf("reserved VEX.vvvv on %s", entry.op)
	}
	if entry.blockBroadcast {
		if vecL != 1 || buf[2]&0x80 != 0 || modrm>>6 == 3 {
			return asm.Instr{}, 0, true, fmt.Errorf("invalid m128-to-YMM encoding for %s", entry.op)
		}
		mem, size, err := decodeVEXMemory(buf[idx+1:], buf[1], mode)
		if err != nil {
			return asm.Instr{}, 0, true, err
		}
		dst := asm.Reg(fmt.Sprintf("Y%d", regHigh<<3|(modrm>>3)&7))
		args := []asm.Operand{{Kind: asm.OpMem, Mem: mem}, {Kind: asm.OpReg, Reg: dst}}
		return asm.Instr{Op: entry.op, Args: args, DecodedFromRaw: true, Raw: fmt.Sprintf("%s %s,%s", entry.op, args[0], dst)}, idx + 1 + size, true, nil
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

// Decode the shared ModRM/SIB grammar with x86asm's legacy MOV decoder. VEX
// encodes the REX X/B bits inverted; the instruction's address size is native.
func decodeVEXMemory(body []byte, vex byte, mode int) (asm.MemRef, int, error) {
	var buf [16]byte
	header := 1
	if mode == 64 {
		buf[0] = 0x40 | (^vex >> 5 & 3)
		header = 2
	}
	buf[header-1] = 0x8b
	n := copy(buf[header:], body)
	ins, err := x86asm.Decode(buf[:header+n], mode)
	if err != nil {
		return asm.MemRef{}, 0, err
	}
	m, ok := ins.Args[1].(x86asm.Mem)
	if !ok || ins.Op != x86asm.MOV || ins.Len <= header {
		return asm.MemRef{}, 0, fmt.Errorf("invalid VEX memory operand")
	}
	if m.Base == x86asm.RIP || m.Base == x86asm.EIP {
		return asm.MemRef{}, 0, fmt.Errorf("%w: VEX PC-relative memory requires original code layout", asm.ErrProbeNeedsContext)
	}
	reg := func(r x86asm.Reg) asm.Reg {
		if r == 0 {
			return ""
		}
		regs := [16]asm.Reg{asm.AX, asm.CX, asm.DX, asm.BX, asm.SP, asm.BP, asm.SI, asm.DI, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
		if mode == 64 {
			return regs[r-x86asm.RAX]
		}
		return regs[r-x86asm.EAX]
	}
	off := int64(int32(m.Disp))
	if mode == 32 && m.Base == 0 {
		off = int64(uint32(off))
	}
	mem := asm.MemRef{Base: reg(m.Base), Index: reg(m.Index), Off: off}
	if m.Index != 0 {
		mem.Scale = int64(m.Scale)
	}
	return mem, ins.Len - header, nil
}
