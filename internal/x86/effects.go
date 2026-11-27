package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// ABI0EffectReport summarizes the result of static ABI0 effect checking on an
// x86/amd64 function using the declarative OpTable.
type ABI0EffectReport struct {
	InitializedGP  map[asm.Reg]bool
	InitializedVec map[int]bool
	WrittenResults map[int64]bool
}

type abi0State struct {
	// gpBytesInit records initialized bytes per canonical GP register:
	// bit i (0..7) corresponds to byte i (AL/R8B = bit 0, AH = bit 1,
	// 16-bit = bits 0..1, 32-bit = bits 0..3, 64-bit = bits 0..7).
	gpBytesInit map[asm.Reg]uint8
	// gpBitDef records exact per-bit definedness for canonical GP registers
	// (bit k = 1 means bit k has a defined value; bit k = 0 means undefined,
	// e.g. uninitialized bytes or entry-undefined CF/PF/AF/ZF/SF/OF bits
	// captured by PUSHFQ/LAHF). Every uninitialized byte has its 8 bits set to 0.
	gpBitDef map[asm.Reg]uint64
	// gpBytesTaintedSP records per-byte private stack-pointer provenance:
	// bit i (0..7) = 1 means byte i of the GP register may contain bytes of
	// the function's private SP frame address.
	gpBytesTaintedSP map[asm.Reg]uint8
	// mmxBytesInit/mmxBitDef/mmxBytesTaintedSP track MMX registers M0..M7
	// with the same exact per-byte/per-bit/per-byte-taint rules as GP registers.
	mmxBytesInit      map[int]uint8
	mmxBitDef         map[int]uint64
	mmxBytesTaintedSP map[int]uint8
	// kBytesInit/kBitDef/kBytesTaintedSP track AVX-512 opmask registers K0..K7.
	kBytesInit      map[int]uint8
	kBitDef         map[int]uint64
	kBytesTaintedSP map[int]uint8
	// vecBytesInit records initialized bytes per XMM/YMM/ZMM register:
	// bits 0..15 = XMM, bits 0..31 = YMM, bits 0..63 = ZMM.
	vecBytesInit map[int]uint64
	// vecByteBitDef tracks exact per-bit definedness for ALL 64 bytes of each
	// XMM/YMM/ZMM register so moving undefined bits through any lane cannot
	// forge defined bits.
	vecByteBitDef     map[int][64]uint8
	vecBytesTaintedSP map[int]uint64
	vecFromRaw        map[int]bool
	// x87StackInit/Def/Taint track the 8-deep x87 FP stack (ST(0)..ST(7) = F0..F7);
	// x87SWBitDef tracks per-bit definedness of the 16-bit x87 status word
	// (sticky exceptions 0x003f, SF 0x0040, ES 0x0080, C0 0x0100, C1 0x0200,
	// C2 0x0400, TOP 0x3800, C3 0x4000, B 0x8000); x87CWBitDef tracks per-bit
	// definedness of the 16-bit x87 control word (PC 0x0300, RC 0x0c00, masks 0x003f).
	x87StackInit  [8]bool
	x87StackDef   [8]bool
	x87StackTaint [8]bool
	x87SWBitDef   uint16
	x87CWBitDef   uint16
	// fpBytesInit records initialized byte offsets in the FP frame
	// (pre-populated with declared parameter slot bytes plus written result bytes).
	fpBytesInit      map[int64]bool
	fpByteBitDef     map[int64]uint8
	fpBytesTaintedSP map[int64]bool
	// spBytesInit records initialized byte offsets in the private SP stack frame
	// (relative to initial SP at function entry; indexed by spOffset + mem.Off).
	spBytesInit      map[int64]bool
	spByteBitDef     map[int64]uint8
	spBytesTaintedSP map[int64]bool
	spOffset         int64
	// Architectural status/control flag definedness tracked independently
	// (covering every live bit packed/unpacked by x86FlagSlots()):
	//   - cfInit: Carry Flag (CF, RFLAGS bit 0)
	//   - pfInit: Parity Flag (PF, RFLAGS bit 2)
	//   - afInit: Auxiliary Carry Flag (AF, RFLAGS bit 4)
	//   - zfInit: Zero Flag (ZF, RFLAGS bit 6) — preserved by BT/BTS/BTR/BTC
	//   - sfInit: Sign Flag (SF, RFLAGS bit 7)
	//   - dfInit: Direction Flag (DF, RFLAGS bit 10) — Go ABI0 guarantees DF=0 at entry
	//   - ofInit: Overflow Flag (OF, RFLAGS bit 11)
	//   - idInit: Identification Flag (ID, RFLAGS bit 21) — initialized 0 in lowered IR
	cfInit bool
	pfInit bool
	afInit bool
	zfInit bool
	sfInit bool
	dfInit bool
	ofInit bool
	idInit bool
}

// flagsLowByteBitMask returns the exact per-bit definedness of RFLAGS byte 0
// (bits 0..7, also copied into AH by LAHF):
//   - bit 0 (0x01): CF
//   - bit 2 (0x04): PF
//   - bit 4 (0x10): AF
//   - bit 6 (0x40): ZF
//   - bit 7 (0x80): SF
//   - bits 1,3,5 (0x2a): fixed architectural reserved bits (1, 0, 0)
func (s *abi0State) flagsLowByteBitMask() uint8 {
	m := uint8(0x2a)
	if s.cfInit {
		m |= 0x01
	}
	if s.pfInit {
		m |= 0x04
	}
	if s.afInit {
		m |= 0x10
	}
	if s.zfInit {
		m |= 0x40
	}
	if s.sfInit {
		m |= 0x80
	}
	return m
}

// flagsHighByteBitMask returns the exact per-bit definedness of RFLAGS byte 1
// (bits 8..15): bit 10 (0x04) is DF, bit 11 (0x08) is OF; all other user-mode
// bits (including IF bit 9 = 0x02) are architecturally defined.
func (s *abi0State) flagsHighByteBitMask() uint8 {
	m := uint8(0xf3)
	if s.dfInit {
		m |= 0x04
	}
	if s.ofInit {
		m |= 0x08
	}
	return m
}

// flagsByte2BitMask returns the exact per-bit definedness of RFLAGS byte 2
// (bits 16..23): bit 21 (byte-2 bit 5 = 0x20) is ID.
func (s *abi0State) flagsByte2BitMask() uint8 {
	m := uint8(0xdf)
	if s.idInit {
		m |= 0x20
	}
	return m
}

func (s *abi0State) setFlagsFromBytes(b0, b1 uint8) {
	s.cfInit = (b0 & 0x01) != 0
	s.pfInit = (b0 & 0x04) != 0
	s.afInit = (b0 & 0x10) != 0
	s.zfInit = (b0 & 0x40) != 0
	s.sfInit = (b0 & 0x80) != 0
	s.dfInit = (b1 & 0x04) != 0
	s.ofInit = (b1 & 0x08) != 0
}

func (s *abi0State) clearCallerSaved() {
	s.gpBytesInit = map[asm.Reg]uint8{}
	s.gpBitDef = map[asm.Reg]uint64{}
	s.gpBytesTaintedSP = map[asm.Reg]uint8{}
	s.mmxBytesInit = map[int]uint8{}
	s.mmxBitDef = map[int]uint64{}
	s.mmxBytesTaintedSP = map[int]uint8{}
	s.kBytesInit = map[int]uint8{}
	s.kBitDef = map[int]uint64{}
	s.kBytesTaintedSP = map[int]uint8{}
	s.vecBytesInit = map[int]uint64{}
	s.vecByteBitDef = map[int][64]uint8{}
	s.vecBytesTaintedSP = map[int]uint64{}
	s.vecFromRaw = map[int]bool{}
	s.x87StackInit = [8]bool{}
	s.x87StackDef = [8]bool{}
	s.x87StackTaint = [8]bool{}
	s.x87SWBitDef = 0xffff
	s.x87CWBitDef = 0xffff
	s.cfInit = false
	s.pfInit = false
	s.afInit = false
	s.zfInit = false
	s.sfInit = false
	s.ofInit = false
	s.dfInit = true
	s.idInit = true
}

const (
	x87SWMaskExc      uint16 = 0x003f // sticky IE|DE|ZE|OE|UE|PE (cleared by FCLEX/FINIT)
	x87SWMaskIEDE     uint16 = 0x0003 // sticky IE|DE
	x87SWMaskStackFlt uint16 = 0x0241 // C1|SF|IE (unmodeled #IS tag-word fault bits)
	x87SWMaskC1       uint16 = 0x0200 // non-sticky C1
	x87SWMaskCC       uint16 = 0x4500 // C3|C2|C0 condition codes
	x87SWMaskFCLEX    uint16 = 0x80ff // bits cleared to 0 by FCLEX (B|ES|SF|PE..IE)
	x87CWMaskPC       uint16 = 0x0300 // Precision Control (bits 9:8)
	x87CWMaskRC       uint16 = 0x0c00 // Rounding Control (bits 11:10)
)

// pushX87 pushes one entry onto the 8-deep x87 stack and returns true if all 8
// slots were already occupied (unmodeled hardware #IS stack overflow).
func (s *abi0State) pushX87(init, def, taint bool) (overflow bool) {
	overflow = s.x87StackInit[7]
	for i := 7; i > 0; i-- {
		s.x87StackInit[i] = s.x87StackInit[i-1]
		s.x87StackDef[i] = s.x87StackDef[i-1]
		s.x87StackTaint[i] = s.x87StackTaint[i-1]
	}
	s.x87StackInit[0] = init
	s.x87StackDef[0] = init && def && !overflow
	s.x87StackTaint[0] = taint
	if overflow {
		s.x87SWBitDef &^= x87SWMaskStackFlt
	}
	return overflow
}

func (s *abi0State) popX87() (init, def, taint bool) {
	init, def, taint = s.x87StackInit[0], s.x87StackDef[0], s.x87StackTaint[0]
	if !init {
		s.x87SWBitDef &^= x87SWMaskStackFlt
	}
	for i := 0; i < 7; i++ {
		s.x87StackInit[i] = s.x87StackInit[i+1]
		s.x87StackDef[i] = s.x87StackDef[i+1]
		s.x87StackTaint[i] = s.x87StackTaint[i+1]
	}
	s.x87StackInit[7] = false
	s.x87StackDef[7] = false
	s.x87StackTaint[7] = false
	return init, def, taint
}

func (s *abi0State) clone() *abi0State {
	out := &abi0State{
		gpBytesInit:       make(map[asm.Reg]uint8, len(s.gpBytesInit)),
		gpBitDef:          make(map[asm.Reg]uint64, len(s.gpBitDef)),
		gpBytesTaintedSP:  make(map[asm.Reg]uint8, len(s.gpBytesTaintedSP)),
		mmxBytesInit:      make(map[int]uint8, len(s.mmxBytesInit)),
		mmxBitDef:         make(map[int]uint64, len(s.mmxBitDef)),
		mmxBytesTaintedSP: make(map[int]uint8, len(s.mmxBytesTaintedSP)),
		kBytesInit:        make(map[int]uint8, len(s.kBytesInit)),
		kBitDef:           make(map[int]uint64, len(s.kBitDef)),
		kBytesTaintedSP:   make(map[int]uint8, len(s.kBytesTaintedSP)),
		vecBytesInit:      make(map[int]uint64, len(s.vecBytesInit)),
		vecByteBitDef:     make(map[int][64]uint8, len(s.vecByteBitDef)),
		vecBytesTaintedSP: make(map[int]uint64, len(s.vecBytesTaintedSP)),
		vecFromRaw:        make(map[int]bool, len(s.vecFromRaw)),
		x87StackInit:      s.x87StackInit,
		x87StackDef:       s.x87StackDef,
		x87StackTaint:     s.x87StackTaint,
		x87SWBitDef:       s.x87SWBitDef,
		x87CWBitDef:       s.x87CWBitDef,
		fpBytesInit:       make(map[int64]bool, len(s.fpBytesInit)),
		fpByteBitDef:      make(map[int64]uint8, len(s.fpByteBitDef)),
		fpBytesTaintedSP:  make(map[int64]bool, len(s.fpBytesTaintedSP)),
		spBytesInit:       make(map[int64]bool, len(s.spBytesInit)),
		spByteBitDef:      make(map[int64]uint8, len(s.spByteBitDef)),
		spBytesTaintedSP:  make(map[int64]bool, len(s.spBytesTaintedSP)),
		spOffset:          s.spOffset,
		cfInit:            s.cfInit,
		pfInit:            s.pfInit,
		afInit:            s.afInit,
		zfInit:            s.zfInit,
		sfInit:            s.sfInit,
		dfInit:            s.dfInit,
		ofInit:            s.ofInit,
		idInit:            s.idInit,
	}
	for k, v := range s.gpBytesInit {
		out.gpBytesInit[k] = v
	}
	for k, v := range s.gpBitDef {
		out.gpBitDef[k] = v
	}
	for k, v := range s.gpBytesTaintedSP {
		out.gpBytesTaintedSP[k] = v
	}
	for k, v := range s.mmxBytesInit {
		out.mmxBytesInit[k] = v
	}
	for k, v := range s.mmxBitDef {
		out.mmxBitDef[k] = v
	}
	for k, v := range s.mmxBytesTaintedSP {
		out.mmxBytesTaintedSP[k] = v
	}
	for k, v := range s.kBytesInit {
		out.kBytesInit[k] = v
	}
	for k, v := range s.kBitDef {
		out.kBitDef[k] = v
	}
	for k, v := range s.kBytesTaintedSP {
		out.kBytesTaintedSP[k] = v
	}
	for k, v := range s.vecBytesInit {
		out.vecBytesInit[k] = v
	}
	for k, v := range s.vecByteBitDef {
		out.vecByteBitDef[k] = v
	}
	for k, v := range s.vecBytesTaintedSP {
		out.vecBytesTaintedSP[k] = v
	}
	for k, v := range s.vecFromRaw {
		out.vecFromRaw[k] = v
	}
	for k, v := range s.fpBytesInit {
		out.fpBytesInit[k] = v
	}
	for k, v := range s.fpByteBitDef {
		out.fpByteBitDef[k] = v
	}
	for k, v := range s.fpBytesTaintedSP {
		out.fpBytesTaintedSP[k] = v
	}
	for k, v := range s.spBytesInit {
		out.spBytesInit[k] = v
	}
	for k, v := range s.spByteBitDef {
		out.spByteBitDef[k] = v
	}
	for k, v := range s.spBytesTaintedSP {
		out.spBytesTaintedSP[k] = v
	}
	return out
}

// merge combines incoming state `other` into `s` at a CFG join point:
//   - must-initialized byte masks and per-bit definedness masks intersect (&)
//   - may-tainted sets (gp/mmx/k/vec/x87/sp/fp SP taint, vecFromRaw) union (| / ||)
//
// Registers, stack slots, and FP slots all follow the same per-bit intersection rule.
// Returns true if `s` changed.
func (s *abi0State) merge(other *abi0State) bool {
	changed := false
	for k, cur := range s.gpBytesInit {
		inter := cur & other.gpBytesInit[k]
		if inter != cur {
			if inter == 0 {
				delete(s.gpBytesInit, k)
			} else {
				s.gpBytesInit[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.gpBitDef {
		inter := cur & other.gpBitDef[k]
		if inter != cur {
			if inter == 0 {
				delete(s.gpBitDef, k)
			} else {
				s.gpBitDef[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.mmxBytesInit {
		inter := cur & other.mmxBytesInit[k]
		if inter != cur {
			if inter == 0 {
				delete(s.mmxBytesInit, k)
			} else {
				s.mmxBytesInit[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.mmxBitDef {
		inter := cur & other.mmxBitDef[k]
		if inter != cur {
			if inter == 0 {
				delete(s.mmxBitDef, k)
			} else {
				s.mmxBitDef[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.kBytesInit {
		inter := cur & other.kBytesInit[k]
		if inter != cur {
			if inter == 0 {
				delete(s.kBytesInit, k)
			} else {
				s.kBytesInit[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.kBitDef {
		inter := cur & other.kBitDef[k]
		if inter != cur {
			if inter == 0 {
				delete(s.kBitDef, k)
			} else {
				s.kBitDef[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.vecBytesInit {
		inter := cur & other.vecBytesInit[k]
		if inter != cur {
			if inter == 0 {
				delete(s.vecBytesInit, k)
			} else {
				s.vecBytesInit[k] = inter
			}
			changed = true
		}
	}
	for k, cur := range s.vecByteBitDef {
		oth := other.vecByteBitDef[k]
		var inter [64]uint8
		anyNonZero := false
		diff := false
		for b := 0; b < 64; b++ {
			v := cur[b] & oth[b]
			inter[b] = v
			if v != cur[b] {
				diff = true
			}
			if v != 0 {
				anyNonZero = true
			}
		}
		if diff {
			if !anyNonZero {
				delete(s.vecByteBitDef, k)
			} else {
				s.vecByteBitDef[k] = inter
			}
			changed = true
		}
	}
	for i := 0; i < 8; i++ {
		if s.x87StackInit[i] && !other.x87StackInit[i] {
			s.x87StackInit[i] = false
			changed = true
		}
		if s.x87StackDef[i] && !other.x87StackDef[i] {
			s.x87StackDef[i] = false
			changed = true
		}
		if other.x87StackTaint[i] && !s.x87StackTaint[i] {
			s.x87StackTaint[i] = true
			changed = true
		}
	}
	if inter := s.x87SWBitDef & other.x87SWBitDef; inter != s.x87SWBitDef {
		s.x87SWBitDef = inter
		changed = true
	}
	if inter := s.x87CWBitDef & other.x87CWBitDef; inter != s.x87CWBitDef {
		s.x87CWBitDef = inter
		changed = true
	}
	for k := range s.fpBytesInit {
		if !other.fpBytesInit[k] {
			delete(s.fpBytesInit, k)
			changed = true
		}
	}
	for k, cur := range s.fpByteBitDef {
		inter := cur & other.fpByteBitDef[k]
		if inter != cur {
			if inter == 0 {
				delete(s.fpByteBitDef, k)
			} else {
				s.fpByteBitDef[k] = inter
			}
			changed = true
		}
	}
	if s.spOffset != other.spOffset {
		if len(s.spBytesInit) > 0 {
			s.spBytesInit = make(map[int64]bool)
			changed = true
		}
		if len(s.spByteBitDef) > 0 {
			s.spByteBitDef = make(map[int64]uint8)
			changed = true
		}
	} else {
		for k := range s.spBytesInit {
			if !other.spBytesInit[k] {
				delete(s.spBytesInit, k)
				changed = true
			}
		}
		for k, cur := range s.spByteBitDef {
			inter := cur & other.spByteBitDef[k]
			if inter != cur {
				if inter == 0 {
					delete(s.spByteBitDef, k)
				} else {
					s.spByteBitDef[k] = inter
				}
				changed = true
			}
		}
	}
	if s.cfInit && !other.cfInit {
		s.cfInit = false
		changed = true
	}
	if s.pfInit && !other.pfInit {
		s.pfInit = false
		changed = true
	}
	if s.afInit && !other.afInit {
		s.afInit = false
		changed = true
	}
	if s.zfInit && !other.zfInit {
		s.zfInit = false
		changed = true
	}
	if s.sfInit && !other.sfInit {
		s.sfInit = false
		changed = true
	}
	if s.dfInit && !other.dfInit {
		s.dfInit = false
		changed = true
	}
	if s.ofInit && !other.ofInit {
		s.ofInit = false
		changed = true
	}
	if s.idInit && !other.idInit {
		s.idInit = false
		changed = true
	}
	for k, v := range other.gpBytesTaintedSP {
		merged := s.gpBytesTaintedSP[k] | v
		if merged != s.gpBytesTaintedSP[k] {
			s.gpBytesTaintedSP[k] = merged
			changed = true
		}
	}
	for k, v := range other.mmxBytesTaintedSP {
		merged := s.mmxBytesTaintedSP[k] | v
		if merged != s.mmxBytesTaintedSP[k] {
			s.mmxBytesTaintedSP[k] = merged
			changed = true
		}
	}
	for k, v := range other.kBytesTaintedSP {
		merged := s.kBytesTaintedSP[k] | v
		if merged != s.kBytesTaintedSP[k] {
			s.kBytesTaintedSP[k] = merged
			changed = true
		}
	}
	for k, v := range other.vecBytesTaintedSP {
		merged := s.vecBytesTaintedSP[k] | v
		if merged != s.vecBytesTaintedSP[k] {
			s.vecBytesTaintedSP[k] = merged
			changed = true
		}
	}
	for k, v := range other.fpBytesTaintedSP {
		if v && !s.fpBytesTaintedSP[k] {
			s.fpBytesTaintedSP[k] = true
			changed = true
		}
	}
	for k, v := range other.spBytesTaintedSP {
		if v && !s.spBytesTaintedSP[k] {
			s.spBytesTaintedSP[k] = true
			changed = true
		}
	}
	for k, v := range other.vecFromRaw {
		if v && !s.vecFromRaw[k] {
			s.vecFromRaw[k] = true
			changed = true
		}
	}
	return changed
}

type opEvalResult struct {
	byteMask     uint64
	bitDef       uint64
	fullBitDef   [64]uint8
	allBytesInit bool
	allBitsDef   bool
}

func fullBitDefFromLow64(bitDef uint64, byteMask uint64, nBytes int64) [64]uint8 {
	var out [64]uint8
	limit := nBytes
	if limit <= 0 || limit > 8 {
		limit = 8
	}
	for b := int64(0); b < limit; b++ {
		if (byteMask & (uint64(1) << uint(b))) == 0 {
			continue
		}
		out[b] = uint8(bitDef >> uint(b*8))
	}
	return out
}

func fullBitDefUniform(nBytes int64, val uint8) [64]uint8 {
	var out [64]uint8
	limit := nBytes
	if limit <= 0 || limit > 64 {
		limit = 64
	}
	for b := int64(0); b < limit; b++ {
		out[b] = val
	}
	return out
}

// CheckABI0ResultInit verifies that a Go ABI0 x86/amd64 function obeys
// byte-level register, stack-slot, and FP initialization, private stack-pointer
// confinement, raw-directive provenance, and CFG/byte-exact ABI0 result
// initialization rules before emitting code.
//
// Driven directly by OpTable so adding new instructions automatically participates
// in effect tracking without per-opcode boilerplate.
func CheckABI0ResultInit(fn asm.Func, sig asm.FuncSig, goarch string) (*ABI0EffectReport, error) {
	return CheckABI0ResultInitWithSigs(fn, sig, goarch, nil, nil)
}

// CheckABI0ResultInitWithSigs extends CheckABI0ResultInit with callee ABI0
// signatures so outgoing CALLs can verify outgoing parameter bytes and mark
// callee ABI0 result stack bytes initialized.
func CheckABI0ResultInitWithSigs(fn asm.Func, sig asm.FuncSig, goarch string, resolve func(string) string, sigs map[string]asm.FuncSig) (*ABI0EffectReport, error) {
	instrs, err := DecodeRawDirectives(fn.Instrs, goarch)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", asm.ErrProbeNeedsContext, err)
	}

	wordMask := uint8(0xff)
	wordBitMask := ^uint64(0)
	ptrBytes := int64(8)
	if goarch == "386" {
		wordMask = 0x0f
		wordBitMask = 0xffffffff
		ptrBytes = 4
	}

	// Build CFG label index map and non-label instruction indices (for n(PC) jumps).
	labelIndex := map[string]int{}
	nonLabelIdx := make([]int, 0, len(instrs))
	pcOrderOf := make([]int, len(instrs))
	for i, ins := range instrs {
		pcOrderOf[i] = len(nonLabelIdx)
		if ins.Op == asm.OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpLabel {
			labelIndex[ins.Args[0].Sym] = i
			continue
		}
		if ins.Op == asm.OpTEXT {
			continue
		}
		nonLabelIdx = append(nonLabelIdx, i)
	}

	resolveJumpTarget := func(pc int, opnd asm.Operand) (int, bool, error) {
		switch opnd.Kind {
		case asm.OpLabel:
			if idx, ok := labelIndex[opnd.Sym]; ok {
				return idx, true, nil
			}
			return -1, false, fmt.Errorf("%w: unresolved jump label %q", asm.ErrProbeNeedsContext, opnd.Sym)
		case asm.OpIdent:
			if idx, ok := labelIndex[opnd.Ident]; ok {
				return idx, true, nil
			}
			return -1, false, fmt.Errorf("%w: unresolved jump target %q", asm.ErrProbeNeedsContext, opnd.Ident)
		case asm.OpMem:
			if opnd.Mem.Base == asm.PC {
				targetOrd := pcOrderOf[pc] + int(opnd.Mem.Off)
				if targetOrd < 0 || targetOrd >= len(nonLabelIdx) {
					return -1, false, fmt.Errorf("%w: out-of-range PC-relative jump %s", asm.ErrProbeNeedsContext, opnd.String())
				}
				return nonLabelIdx[targetOrd], true, nil
			}
		case asm.OpSym:
			// Tail-call JMP sym(SB): does not return through local RET.
			return -1, false, nil
		}
		return -1, false, fmt.Errorf("%w: unprovable indirect branch target %s", asm.ErrProbeNeedsContext, opnd.String())
	}

	// Build result byte ranges and parameter byte ranges from sig.Frame.
	resultByteOwned := map[int64]bool{}
	resultSpans := make([]abi0SlotSpan, 0, len(sig.Frame.Results))
	for _, s := range sig.Frame.Results {
		sz := x86ABI0SlotBytes(s.Type, goarch)
		if sz <= 0 {
			return nil, fmt.Errorf("%w: result initialization: unsupported result slot type %q at +%d(FP)", asm.ErrProbeNeedsContext, s.Type, s.Offset)
		}
		resultSpans = append(resultSpans, abi0SlotSpan{offset: s.Offset, size: sz})
		for off := s.Offset; off < s.Offset+sz; off++ {
			resultByteOwned[off] = true
		}
	}

	// Entry state at pc = 0: pre-populate declared parameter FP bytes and ArgRegs.
	entry := &abi0State{
		gpBytesInit:       map[asm.Reg]uint8{},
		gpBitDef:          map[asm.Reg]uint64{},
		gpBytesTaintedSP:  map[asm.Reg]uint8{},
		mmxBytesInit:      map[int]uint8{},
		mmxBitDef:         map[int]uint64{},
		mmxBytesTaintedSP: map[int]uint8{},
		kBytesInit:        map[int]uint8{},
		kBitDef:           map[int]uint64{},
		kBytesTaintedSP:   map[int]uint8{},
		vecBytesInit:      map[int]uint64{},
		vecByteBitDef:     map[int][64]uint8{},
		vecBytesTaintedSP: map[int]uint64{},
		vecFromRaw:        map[int]bool{},
		x87SWBitDef:       0xffff,
		x87CWBitDef:       0xffff,
		fpBytesInit:       map[int64]bool{},
		fpByteBitDef:      map[int64]uint8{},
		fpBytesTaintedSP:  map[int64]bool{},
		spBytesInit:       map[int64]bool{},
		spByteBitDef:      map[int64]uint8{},
		spBytesTaintedSP:  map[int64]bool{},
		dfInit:            true,
		idInit:            true,
	}
	for _, s := range sig.Frame.Params {
		sz := x86ABI0SlotBytes(s.Type, goarch)
		for off := s.Offset; off < s.Offset+sz; off++ {
			entry.fpBytesInit[off] = true
			entry.fpByteBitDef[off] = 0xff
		}
	}
	for _, r := range sig.ArgRegs {
		cr := canonicalGP(r)
		entry.gpBytesInit[cr] = wordMask
		entry.gpBitDef[cr] = wordBitMask
	}

	if len(instrs) == 0 {
		if len(resultSpans) > 0 {
			return nil, fmt.Errorf("%w: empty function leaves result slot +%d(FP) uninitialized", asm.ErrProbeNeedsContext, resultSpans[0].offset)
		}
		return buildABI0Report(entry, resultSpans, wordMask), nil
	}

	inStates := make([]*abi0State, len(instrs))
	inStates[0] = entry
	repPending := make([]bool, len(instrs))
	queue := []int{0}
	inQueue := make([]bool, len(instrs))
	inQueue[0] = true

	enqueue := func(next int, st *abi0State, nextRep bool) {
		if next < 0 || next >= len(instrs) {
			return
		}
		if inStates[next] == nil {
			inStates[next] = st.clone()
			repPending[next] = nextRep
			if !inQueue[next] {
				queue = append(queue, next)
				inQueue[next] = true
			}
			return
		}
		changed := inStates[next].merge(st)
		if nextRep && !repPending[next] {
			repPending[next] = true
			changed = true
		}
		if changed && !inQueue[next] {
			queue = append(queue, next)
			inQueue[next] = true
		}
	}

	checkGPRead := func(st *abi0State, reg asm.Reg, reqMask uint8, raw string) error {
		if reg == asm.SP {
			return nil
		}
		r := canonicalGP(reg)
		if (st.gpBytesInit[r] & reqMask) != reqMask {
			return fmt.Errorf("%w: %s reads uninitialized register bytes of %s (have=0x%02x want=0x%02x)",
				asm.ErrProbeNeedsContext, raw, reg, st.gpBytesInit[r], reqMask)
		}
		reqBits := abi0ByteMaskToBitMask(reqMask)
		if (st.gpBitDef[r] & reqBits) != reqBits {
			return fmt.Errorf("%w: %s reads register %s with undefined bits (have=0x%016x want=0x%016x)",
				asm.ErrProbeNeedsContext, raw, reg, st.gpBitDef[r]&reqBits, reqBits)
		}
		return nil
	}

	// evalOperand evaluates both the exact byte-level initialization bitmask and
	// exact per-bit definedness bitmask across ALL register classes (GP, MMX,
	// AVX-512 K-mask, XMM/YMM/ZMM 64-byte, x87 stack, FP, and SP stack) while
	// enforcing hard safety checks on memory dereferences, FP reads, and SP reads.
	evalOperand := func(st *abi0State, op asm.Operand, readBytes int64, isLEA bool, opName asm.Op, raw string) (opEvalResult, error) {
		switch op.Kind {
		case asm.OpImm, asm.OpSym:
			bm := abi0ByteMaskN(readBytes)
			return opEvalResult{
				byteMask:     bm,
				bitDef:       abi0BitMaskN(readBytes),
				fullBitDef:   fullBitDefUniform(readBytes, 0xff),
				allBytesInit: true,
				allBitsDef:   true,
			}, nil

		case asm.OpReg:
			if op.Reg == asm.SP {
				bm := abi0ByteMaskN(readBytes)
				return opEvalResult{
					byteMask:     bm,
					bitDef:       abi0BitMaskN(readBytes),
					fullBitDef:   fullBitDefUniform(readBytes, 0xff),
					allBytesInit: true,
					allBitsDef:   true,
				}, nil
			}
			if idx, ok := amd64ParseMReg(op.Reg); ok {
				n := readBytes
				if n <= 0 || n > 8 {
					n = 8
				}
				req := uint8(abi0ByteMaskN(n))
				have := st.mmxBytesInit[idx] & req
				reqBits := abi0ByteMaskToBitMask(req)
				haveBits := st.mmxBitDef[idx] & reqBits
				return opEvalResult{
					byteMask:     uint64(have),
					bitDef:       haveBits,
					fullBitDef:   fullBitDefFromLow64(haveBits, uint64(have), n),
					allBytesInit: have == req,
					allBitsDef:   have == req && haveBits == reqBits,
				}, nil
			}
			if idx, ok := amd64ParseKReg(op.Reg); ok {
				n := readBytes
				if n <= 0 || n > 8 {
					n = 8
				}
				req := uint8(abi0ByteMaskN(n))
				have := st.kBytesInit[idx] & req
				reqBits := abi0ByteMaskToBitMask(req)
				haveBits := st.kBitDef[idx] & reqBits
				return opEvalResult{
					byteMask:     uint64(have),
					bitDef:       haveBits,
					fullBitDef:   fullBitDefFromLow64(haveBits, uint64(have), n),
					allBytesInit: have == req,
					allBitsDef:   have == req && haveBits == reqBits,
				}, nil
			}
			if idx, ok := amd64ParseX87Reg(op.Reg); ok {
				n := readBytes
				if n <= 0 {
					n = 8
				}
				if !st.x87StackInit[idx] {
					return opEvalResult{}, nil
				}
				bm := abi0ByteMaskN(n)
				if !st.x87StackDef[idx] {
					return opEvalResult{byteMask: bm, allBytesInit: true, allBitsDef: false}, nil
				}
				return opEvalResult{
					byteMask:     bm,
					bitDef:       abi0BitMaskN(n),
					fullBitDef:   fullBitDefUniform(n, 0xff),
					allBytesInit: true,
					allBitsDef:   true,
				}, nil
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				req := vecRegReadByteMask(op.Reg, opName, readBytes)
				have := st.vecBytesInit[idx] & req
				allInit := have == req
				stored := st.vecByteBitDef[idx]
				var full [64]uint8
				var low64 uint64
				bitsOK := allInit
				for b := 0; b < 64; b++ {
					if (req & (uint64(1) << uint(b))) == 0 {
						continue
					}
					bd := stored[b]
					if (have & (uint64(1) << uint(b))) == 0 {
						bd = 0
					}
					full[b] = bd
					if b < 8 {
						low64 |= uint64(bd) << uint(b*8)
					}
					if bd != 0xff {
						bitsOK = false
					}
				}
				return opEvalResult{
					byteMask:     have,
					bitDef:       low64,
					fullBitDef:   full,
					allBytesInit: allInit,
					allBitsDef:   bitsOK,
				}, nil
			}
			req := gpRegReadByteMask(op.Reg, readBytes, wordMask)
			r := canonicalGP(op.Reg)
			have := st.gpBytesInit[r] & req
			reqBits := abi0ByteMaskToBitMask(req)
			haveBits := st.gpBitDef[r] & reqBits
			alignedBytes := uint64(have)
			alignedBits := haveBits
			if req == 0x02 {
				alignedBytes = uint64((have >> 1) & 0x01)
				alignedBits = (haveBits >> 8) & 0xff
			}
			return opEvalResult{
				byteMask:     alignedBytes,
				bitDef:       alignedBits,
				fullBitDef:   fullBitDefFromLow64(alignedBits, alignedBytes, 8),
				allBytesInit: have == req,
				allBitsDef:   have == req && haveBits == reqBits,
			}, nil

		case asm.OpFP:
			if isLEA {
				return opEvalResult{
					byteMask:     abi0ByteMaskN(ptrBytes),
					bitDef:       abi0BitMaskN(ptrBytes),
					fullBitDef:   fullBitDefUniform(ptrBytes, 0xff),
					allBytesInit: true,
					allBitsDef:   true,
				}, nil
			}
			nBytes := readBytes
			if nBytes <= 0 {
				nBytes = ptrBytes
			}
			var bits uint64
			var full [64]uint8
			bitsOK := true
			for b := int64(0); b < nBytes; b++ {
				off := op.FPOffset + b
				if !st.fpBytesInit[off] {
					return opEvalResult{}, fmt.Errorf("%w: %s reads uninitialized FP byte +%d(FP) (read +%d(FP) width %d)",
						asm.ErrProbeNeedsContext, raw, off, op.FPOffset, nBytes)
				}
				bd := st.fpByteBitDef[off]
				if b < 64 {
					full[b] = bd
				}
				if b < 8 {
					bits |= uint64(bd) << uint(b*8)
				}
				if bd != 0xff {
					bitsOK = false
				}
			}
			return opEvalResult{
				byteMask:     abi0ByteMaskN(nBytes),
				bitDef:       bits,
				fullBitDef:   full,
				allBytesInit: true,
				allBitsDef:   bitsOK,
			}, nil

		case asm.OpMem:
			if op.Mem.Base == asm.SP {
				if isLEA {
					if op.Mem.Index != "" {
						r := canonicalGP(op.Mem.Index)
						if (st.gpBytesInit[r] & wordMask) != wordMask {
							return opEvalResult{}, nil
						}
						if (st.gpBitDef[r] & wordBitMask) != wordBitMask {
							return opEvalResult{byteMask: abi0ByteMaskN(ptrBytes), allBytesInit: true, allBitsDef: false}, nil
						}
					}
					return opEvalResult{
						byteMask:     abi0ByteMaskN(ptrBytes),
						bitDef:       abi0BitMaskN(ptrBytes),
						fullBitDef:   fullBitDefUniform(ptrBytes, 0xff),
						allBytesInit: true,
						allBitsDef:   true,
					}, nil
				}
				if op.Mem.Index != "" {
					// Indexed stack read (e.g. sha256block_amd64.s (SP)(SI*1)):
					// index register must be initialized and bit-defined, and the loaded
					// bytes are conservatively treated as uninitialized so they cannot
					// satisfy an ABI0 result slot or be dereferenced as a pointer.
					if err := checkGPRead(st, op.Mem.Index, wordMask, raw); err != nil {
						return opEvalResult{}, err
					}
					return opEvalResult{}, nil
				}
				nBytes := readBytes
				if nBytes <= 0 {
					nBytes = ptrBytes
				}
				var bits uint64
				var full [64]uint8
				bitsOK := true
				for b := int64(0); b < nBytes; b++ {
					off := op.Mem.Off + b
					slot := st.spOffset + off
					if !st.spBytesInit[slot] {
						return opEvalResult{}, fmt.Errorf("%w: %s reads uninitialized stack byte %d(SP) (read %d(SP) width %d)",
							asm.ErrProbeNeedsContext, raw, off, op.Mem.Off, nBytes)
					}
					bd := st.spByteBitDef[slot]
					if b < 64 {
						full[b] = bd
					}
					if b < 8 {
						bits |= uint64(bd) << uint(b*8)
					}
					if bd != 0xff {
						bitsOK = false
					}
				}
				return opEvalResult{
					byteMask:     abi0ByteMaskN(nBytes),
					bitDef:       bits,
					fullBitDef:   full,
					allBytesInit: true,
					allBitsDef:   bitsOK,
				}, nil
			}
			if isLEA {
				okBytes := true
				okBits := true
				if op.Mem.Base != "" && op.Mem.Base != asm.PC {
					r := canonicalGP(op.Mem.Base)
					if (st.gpBytesInit[r] & wordMask) != wordMask {
						okBytes = false
					}
					if (st.gpBitDef[r] & wordBitMask) != wordBitMask {
						okBits = false
					}
				}
				if op.Mem.Index != "" {
					r := canonicalGP(op.Mem.Index)
					if (st.gpBytesInit[r] & wordMask) != wordMask {
						okBytes = false
					}
					if (st.gpBitDef[r] & wordBitMask) != wordBitMask {
						okBits = false
					}
				}
				if !okBytes {
					return opEvalResult{}, nil
				}
				if !okBits {
					return opEvalResult{byteMask: abi0ByteMaskN(ptrBytes), allBytesInit: true, allBitsDef: false}, nil
				}
				return opEvalResult{
					byteMask:     abi0ByteMaskN(ptrBytes),
					bitDef:       abi0BitMaskN(ptrBytes),
					fullBitDef:   fullBitDefUniform(ptrBytes, 0xff),
					allBytesInit: true,
					allBitsDef:   true,
				}, nil
			}
			if op.Mem.Base != "" && op.Mem.Base != asm.SP && op.Mem.Base != asm.PC {
				if err := checkGPRead(st, op.Mem.Base, wordMask, raw); err != nil {
					return opEvalResult{}, err
				}
			}
			if op.Mem.Index != "" {
				if err := checkGPRead(st, op.Mem.Index, wordMask, raw); err != nil {
					return opEvalResult{}, err
				}
			}
			return opEvalResult{
				byteMask:     abi0ByteMaskN(readBytes),
				bitDef:       abi0BitMaskN(readBytes),
				fullBitDef:   fullBitDefUniform(readBytes, 0xff),
				allBytesInit: true,
				allBitsDef:   true,
			}, nil
		}
		return opEvalResult{
			byteMask:     abi0ByteMaskN(readBytes),
			bitDef:       abi0BitMaskN(readBytes),
			fullBitDef:   fullBitDefUniform(readBytes, 0xff),
			allBytesInit: true,
			allBitsDef:   true,
		}, nil
	}

	// evalOperandTaintSP returns per-byte private SP-frame address taint for op
	// (bit b of mask corresponds to byte b aligned to bit 0 across up to 64 bytes, plus anyTaint).
	evalOperandTaintSP := func(st *abi0State, op asm.Operand, readBytes int64, isLEA bool, opName asm.Op) (mask uint64, anyTaint bool) {
		switch op.Kind {
		case asm.OpReg:
			if op.Reg == asm.SP {
				return uint64(wordMask), true
			}
			if idx, ok := amd64ParseMReg(op.Reg); ok {
				n := readBytes
				if n <= 0 || n > 8 {
					n = 8
				}
				raw := uint64(st.mmxBytesTaintedSP[idx]) & abi0ByteMaskN(n)
				return raw, raw != 0
			}
			if idx, ok := amd64ParseKReg(op.Reg); ok {
				n := readBytes
				if n <= 0 || n > 8 {
					n = 8
				}
				raw := uint64(st.kBytesTaintedSP[idx]) & abi0ByteMaskN(n)
				return raw, raw != 0
			}
			if idx, ok := amd64ParseX87Reg(op.Reg); ok {
				if st.x87StackTaint[idx] {
					n := readBytes
					if n <= 0 || n > 8 {
						n = 8
					}
					return abi0ByteMaskN(n), true
				}
				return 0, false
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				req := vecRegReadByteMask(op.Reg, opName, readBytes)
				raw := st.vecBytesTaintedSP[idx] & req
				return raw, raw != 0
			}
			req := gpRegReadByteMask(op.Reg, readBytes, wordMask)
			raw := st.gpBytesTaintedSP[canonicalGP(op.Reg)] & req
			if req == 0x02 {
				raw = (raw >> 1) & 0x01
			}
			return uint64(raw), raw != 0

		case asm.OpMem:
			if op.Mem.Base == asm.SP {
				if isLEA {
					return uint64(wordMask), true
				}
				nBytes := readBytes
				if nBytes <= 0 {
					nBytes = ptrBytes
				}
				if op.Mem.Index != "" {
					if len(st.spBytesTaintedSP) > 0 {
						n := nBytes
						if n > 64 {
							n = 64
						}
						return abi0ByteMaskN(n), true
					}
					return 0, false
				}
				for b := int64(0); b < nBytes; b++ {
					if st.spBytesTaintedSP[st.spOffset+op.Mem.Off+b] {
						anyTaint = true
						if b < 64 {
							mask |= uint64(1) << uint(b)
						}
					}
				}
				return mask, anyTaint
			}
			if isLEA {
				if op.Mem.Base != "" && op.Mem.Base != asm.PC && st.gpBytesTaintedSP[canonicalGP(op.Mem.Base)] != 0 {
					return uint64(wordMask), true
				}
				if op.Mem.Index != "" && st.gpBytesTaintedSP[canonicalGP(op.Mem.Index)] != 0 {
					return uint64(wordMask), true
				}
			}
			return 0, false

		case asm.OpFP:
			if isLEA {
				return 0, false
			}
			nBytes := readBytes
			if nBytes <= 0 {
				nBytes = ptrBytes
			}
			for b := int64(0); b < nBytes; b++ {
				if st.fpBytesTaintedSP[op.FPOffset+b] {
					anyTaint = true
					if b < 64 {
						mask |= uint64(1) << uint(b)
					}
				}
			}
			return mask, anyTaint
		}
		return 0, false
	}

	writeDstMask := func(st *abi0State, op asm.Operand, writeBytes int64, valMask uint64, valBitDef uint64, fullBitDef [64]uint8, opName asm.Op, spec asm.OpSpec, pureCopy bool, fromRaw bool, taintMask uint64, anyTaint bool, srcIsReg bool) error {
		switch op.Kind {
		case asm.OpReg:
			if op.Reg == asm.SP {
				return nil
			}
			if idx, ok := amd64ParseMReg(op.Reg); ok {
				w := writeBytes
				if w <= 0 || w > 8 {
					w = 8
				}
				wMask := uint8(abi0ByteMaskN(w))
				wBitMask := abi0ByteMaskToBitMask(wMask)
				placed := uint8(valMask) & wMask
				placedBits := valBitDef & wBitMask & abi0ByteMaskToBitMask(placed)
				placedTaint := uint8(taintMask) & wMask
				// MOVD/MOVL into M0..M7 zero-extends upper 4 bytes (known 0 = defined).
				upperZero := uint8(0xff) &^ wMask
				upperZeroBits := ^wBitMask
				st.mmxBytesInit[idx] = placed | upperZero
				st.mmxBitDef[idx] = placedBits | upperZeroBits
				if placedTaint != 0 {
					st.mmxBytesTaintedSP[idx] = placedTaint
				} else {
					delete(st.mmxBytesTaintedSP, idx)
				}
				return nil
			}
			if idx, ok := amd64ParseKReg(op.Reg); ok {
				w := writeBytes
				if w <= 0 || w > 8 {
					w = 8
				}
				wMask := uint8(abi0ByteMaskN(w))
				wBitMask := abi0ByteMaskToBitMask(wMask)
				placed := uint8(valMask) & wMask
				placedBits := valBitDef & wBitMask & abi0ByteMaskToBitMask(placed)
				placedTaint := uint8(taintMask) & wMask
				// Writes to K0..K7 zero-extend upper bytes up to 64 bits (known 0 = defined).
				upperZero := uint8(0xff) &^ wMask
				upperZeroBits := ^wBitMask
				st.kBytesInit[idx] = placed | upperZero
				st.kBitDef[idx] = placedBits | upperZeroBits
				if placedTaint != 0 {
					st.kBytesTaintedSP[idx] = placedTaint
				} else {
					delete(st.kBytesTaintedSP, idx)
				}
				return nil
			}
			if idx, ok := amd64ParseX87Reg(op.Reg); ok {
				w := writeBytes
				if w <= 0 {
					w = 8
				}
				allInit := (valMask & abi0ByteMaskN(w)) == abi0ByteMaskN(w)
				allBits := allInit && (valBitDef&abi0BitMaskN(w)) == abi0BitMaskN(w)
				st.x87StackInit[idx] = allInit
				st.x87StackDef[idx] = allBits
				st.x87StackTaint[idx] = anyTaint
				return nil
			}
			if idx, ok := anyVecRegIndex(op.Reg); ok {
				name := strings.ToUpper(string(opName))
				if dot := strings.IndexByte(name, '.'); dot >= 0 {
					name = name[:dot]
				}
				wMask, zeroUpper := vecRegWriteByteMask(op.Reg, opName, writeBytes, srcIsReg)
				curBD := st.vecByteBitDef[idx]
				if pureCopy {
					lowWidth := vecCopyWidth(op.Reg, name, writeBytes)
					lowMask := abi0ByteMaskN(lowWidth)
					lowBits := valMask & lowMask
					if zeroUpper {
						st.vecBytesInit[idx] = lowBits | ^lowMask
						var nextBD [64]uint8
						for b := int64(0); b < 64; b++ {
							if b < lowWidth {
								if (lowBits & (uint64(1) << uint(b))) != 0 {
									nextBD[b] = fullBitDef[b]
								}
							} else {
								nextBD[b] = 0xff
							}
						}
						st.vecByteBitDef[idx] = nextBD
					} else if (name == "MOVSS" || name == "MOVSD") && srcIsReg {
						st.vecBytesInit[idx] = (st.vecBytesInit[idx] &^ lowMask) | lowBits
						for b := int64(0); b < lowWidth && b < 64; b++ {
							if (lowBits & (uint64(1) << uint(b))) != 0 {
								curBD[b] = fullBitDef[b]
							} else {
								curBD[b] = 0
							}
						}
						st.vecByteBitDef[idx] = curBD
					} else {
						// Legacy SSE write into XMM zeroes bytes [lowWidth..15] and preserves [16..63].
						st.vecBytesInit[idx] = (st.vecBytesInit[idx] &^ uint64(0xffff)) | lowBits | (uint64(0xffff) &^ lowMask)
						for b := int64(0); b < 16; b++ {
							if b < lowWidth {
								if (lowBits & (uint64(1) << uint(b))) != 0 {
									curBD[b] = fullBitDef[b]
								} else {
									curBD[b] = 0
								}
							} else {
								curBD[b] = 0xff
							}
						}
						st.vecByteBitDef[idx] = curBD
					}
				} else if spec.Effect == asm.EffectPreserveUpper {
					lowWidth := int64(8)
					if strings.HasSuffix(name, "SS") {
						lowWidth = 4
					}
					lowMask := abi0ByteMaskN(lowWidth)
					lowBitMask := abi0BitMaskN(lowWidth)
					if (valMask & lowMask) == lowMask {
						st.vecBytesInit[idx] |= lowMask
						allLowBits := (valBitDef & lowBitMask) == lowBitMask
						for b := int64(0); b < lowWidth; b++ {
							if allLowBits {
								curBD[b] = 0xff
							} else {
								curBD[b] = 0
							}
						}
					} else {
						st.vecBytesInit[idx] &^= lowMask
						for b := int64(0); b < lowWidth; b++ {
							curBD[b] = 0
						}
					}
					st.vecByteBitDef[idx] = curBD
				} else {
					allInit := writeBytes <= 0 || (valMask&abi0ByteMaskN(writeBytes)) == abi0ByteMaskN(writeBytes)
					allBits := allInit
					for b := int64(0); b < writeBytes && b < 64 && allBits; b++ {
						if fullBitDef[b] != 0xff {
							allBits = false
						}
					}
					if zeroUpper {
						regMask := vecRegFullByteMask(op.Reg)
						var nextBD [64]uint8
						if allInit {
							st.vecBytesInit[idx] = ^uint64(0)
							for b := 0; b < 64; b++ {
								if (regMask & (uint64(1) << uint(b))) != 0 {
									if allBits {
										nextBD[b] = 0xff
									}
								} else {
									nextBD[b] = 0xff
								}
							}
						} else {
							st.vecBytesInit[idx] = ^regMask
							for b := 0; b < 64; b++ {
								if (regMask & (uint64(1) << uint(b))) == 0 {
									nextBD[b] = 0xff
								}
							}
						}
						st.vecByteBitDef[idx] = nextBD
					} else {
						if allInit {
							st.vecBytesInit[idx] |= wMask
							for b := 0; b < 64; b++ {
								if (wMask & (uint64(1) << uint(b))) != 0 {
									if allBits {
										curBD[b] = 0xff
									} else {
										curBD[b] = 0
									}
								}
							}
						} else {
							st.vecBytesInit[idx] &^= wMask
							for b := 0; b < 64; b++ {
								if (wMask & (uint64(1) << uint(b))) != 0 {
									curBD[b] = 0
								}
							}
						}
						st.vecByteBitDef[idx] = curBD
					}
				}
				var newVecTaint uint64
				if pureCopy {
					lowWidth := vecCopyWidth(op.Reg, name, writeBytes)
					lowMask := abi0ByteMaskN(lowWidth)
					placedTaint := taintMask & lowMask
					if zeroUpper {
						newVecTaint = placedTaint
					} else if (name == "MOVSS" || name == "MOVSD") && srcIsReg {
						newVecTaint = (st.vecBytesTaintedSP[idx] &^ lowMask) | placedTaint
					} else {
						newVecTaint = (st.vecBytesTaintedSP[idx] &^ uint64(0xffff)) | placedTaint
					}
				} else if anyTaint {
					if zeroUpper {
						newVecTaint = vecRegFullByteMask(op.Reg)
					} else {
						newVecTaint = st.vecBytesTaintedSP[idx] | wMask
					}
				} else {
					if zeroUpper {
						newVecTaint = 0
					} else {
						newVecTaint = st.vecBytesTaintedSP[idx] &^ wMask
					}
				}
				if newVecTaint != 0 {
					st.vecBytesTaintedSP[idx] = newVecTaint
				} else {
					delete(st.vecBytesTaintedSP, idx)
				}
				st.vecFromRaw[idx] = fromRaw
				return nil
			}
			r := canonicalGP(op.Reg)
			wMask, clearsUpper := gpRegWriteByteMask(op.Reg, writeBytes, goarch)
			wBitMask := abi0ByteMaskToBitMask(wMask)
			var placed uint8
			var placedBits uint64
			var placedTaint uint8
			if wMask == 0x02 {
				placed = uint8((valMask & 0x01) << 1)
				placedBits = (valBitDef & 0xff) << 8
				placedTaint = uint8((taintMask & 0x01) << 1)
			} else {
				placed = uint8(valMask) & wMask
				placedBits = valBitDef & wBitMask
				placedTaint = uint8(taintMask) & wMask
			}
			// Keep invariant: uninitialized bytes have bit-definedness 0.
			placedBits &= abi0ByteMaskToBitMask(placed)
			if clearsUpper {
				// 32-bit GP writes on amd64 zero-extend upper 4 bytes (known zero = initialized & bit-defined).
				upperZero := wordMask &^ wMask
				upperZeroBits := wordBitMask &^ wBitMask
				st.gpBytesInit[r] = placed | upperZero
				st.gpBitDef[r] = placedBits | upperZeroBits
				if placedTaint != 0 {
					st.gpBytesTaintedSP[r] = placedTaint
				} else {
					delete(st.gpBytesTaintedSP, r)
				}
			} else {
				st.gpBytesInit[r] = (st.gpBytesInit[r] &^ wMask) | placed
				st.gpBitDef[r] = (st.gpBitDef[r] &^ wBitMask) | placedBits
				newTaint := (st.gpBytesTaintedSP[r] &^ wMask) | placedTaint
				if newTaint != 0 {
					st.gpBytesTaintedSP[r] = newTaint
				} else {
					delete(st.gpBytesTaintedSP, r)
				}
			}

		case asm.OpFP:
			if writeBytes <= 0 {
				return nil
			}
			touchesResult := false
			for off := op.FPOffset; off < op.FPOffset+writeBytes; off++ {
				if resultByteOwned[off] {
					touchesResult = true
					break
				}
			}
			if touchesResult {
				if anyTaint {
					return fmt.Errorf("%w: private frame address escapes to result slot +%d(FP)", asm.ErrProbeNeedsContext, op.FPOffset)
				}
				if fromRaw {
					return fmt.Errorf("%w: raw-decoded value written to result slot +%d(FP)", asm.ErrProbeNeedsContext, op.FPOffset)
				}
			}
			for b := int64(0); b < writeBytes; b++ {
				off := op.FPOffset + b
				if b < 64 && (valMask&(uint64(1)<<uint(b))) != 0 {
					st.fpBytesInit[off] = true
					st.fpByteBitDef[off] = fullBitDef[b]
				} else {
					delete(st.fpBytesInit, off)
					delete(st.fpByteBitDef, off)
				}
				byteTainted := false
				if pureCopy && b < 64 {
					byteTainted = (taintMask & (uint64(1) << uint(b))) != 0
				} else {
					byteTainted = anyTaint
				}
				if byteTainted {
					st.fpBytesTaintedSP[off] = true
				} else {
					delete(st.fpBytesTaintedSP, off)
				}
			}

		case asm.OpMem:
			if op.Mem.Base == asm.SP && op.Mem.Index == "" {
				if anyTaint {
					return fmt.Errorf("%w: private frame address escapes to stack slot %d(SP)", asm.ErrProbeNeedsContext, op.Mem.Off)
				}
				nBytes := writeBytes
				if nBytes <= 0 {
					return nil
				}
				start := st.spOffset + op.Mem.Off
				for b := int64(0); b < nBytes; b++ {
					off := start + b
					delete(st.spBytesTaintedSP, off)
					if b < 64 && (valMask&(uint64(1)<<uint(b))) != 0 {
						st.spBytesInit[off] = true
						st.spByteBitDef[off] = fullBitDef[b]
					} else {
						delete(st.spBytesInit, off)
						delete(st.spByteBitDef, off)
					}
				}
				return nil
			}
			// Non-SP external memory store: forbid leaking private SP addresses or
			// storing uninitialized/undefined-flag bits into observable caller memory.
			if anyTaint {
				return fmt.Errorf("%w: private frame address escapes to memory %s", asm.ErrProbeNeedsContext, op.String())
			}
			if writeBytes > 0 {
				limit := writeBytes
				if limit > 64 {
					limit = 64
				}
				for b := int64(0); b < limit; b++ {
					if (valMask & (uint64(1) << uint(b))) == 0 {
						return fmt.Errorf("%w: %s stores uninitialized byte %d to memory %s", asm.ErrProbeNeedsContext, opName, b, op.String())
					}
					if fullBitDef[b] != 0xff {
						return fmt.Errorf("%w: %s stores byte %d with undefined bits (0x%02x) to memory %s", asm.ErrProbeNeedsContext, opName, b, fullBitDef[b], op.String())
					}
				}
			}
		}
		return nil
	}

	var retStates []*abi0State
	var finalState *abi0State

	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		inQueue[pc] = false

		st := inStates[pc].clone()
		curRep := repPending[pc]
		ins := instrs[pc]
		op := asm.Op(strings.ToUpper(string(ins.Op)))

		if op == "REP" || op == "REPN" {
			enqueue(pc+1, st, true)
			continue
		}
		if op == "LOCK" || op == asm.OpTEXT || op == asm.OpLABEL || op == "NOP" || op == "PCALIGN" ||
			op == "NO_LOCAL_POINTERS" || op == "FUNCDATA" || op == "PCDATA" || op == "GO_ARGS" ||
			op == "VZEROUPPER" || op == "VZEROALL" ||
			op == "LFENCE" || op == "SFENCE" || op == "MFENCE" || op == "PAUSE" {
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}
		if op == "CLD" || op == "STD" {
			st.dfInit = true
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}
		if op == "EMMS" {
			st.mmxBytesInit = map[int]uint8{}
			st.mmxBitDef = map[int]uint64{}
			st.mmxBytesTaintedSP = map[int]uint8{}
			st.x87StackInit = [8]bool{}
			st.x87StackDef = [8]bool{}
			st.x87StackTaint = [8]bool{}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		// Any raw-decoded instruction cannot supply proven ABI0 result initialization
		// on its own until explicitly validated against the lowering contract.
		if ins.DecodedFromRaw {
			return nil, fmt.Errorf("%w: decoded raw directive %q requires verified lowering provenance for ABI0 result initialization", asm.ErrProbeNeedsContext, ins.Raw)
		}

		if op == asm.OpRET {
			retStates = append(retStates, st)
			continue
		}

		if op == "UD2" || op == "HLT" || op == "UNDEF" {
			// Trap/halt terminates the path without reaching RET.
			continue
		}

		// Model all x87 instructions via the shared x87_spec.go metadata so the
		// checker and LLVM lowerers share one exact stack/push/pop/constant model.
		if cat := classifyX87Op(op); cat != x87CatUnknown {
			checkMemAddr := func(opnd asm.Operand) error {
				if opnd.Kind != asm.OpMem {
					return nil
				}
				if opnd.Mem.Base != "" && opnd.Mem.Base != asm.SP && opnd.Mem.Base != asm.PC {
					if err := checkGPRead(st, opnd.Mem.Base, wordMask, ins.Raw); err != nil {
						return err
					}
				}
				if opnd.Mem.Index != "" {
					if err := checkGPRead(st, opnd.Mem.Index, wordMask, ins.Raw); err != nil {
						return err
					}
				}
				return nil
			}
			writeX87BitsToDst := func(dst asm.Operand, w int64, initVal bool, bitDef uint64, taintVal bool) error {
				if err := checkMemAddr(dst); err != nil {
					return err
				}
				var vm, bd uint64
				var full [64]uint8
				if initVal {
					vm = abi0ByteMaskN(w)
					bd = bitDef & abi0BitMaskN(w)
					full = fullBitDefFromLow64(bd, vm, w)
				}
				var tm uint64
				if taintVal {
					tm = abi0ByteMaskN(w)
				}
				specF := asm.OpSpec{Op: op, Width: uint16(w * 8), Effect: asm.EffectWriteOnly}
				return writeDstMask(st, dst, w, vm, bd, full, op, specF, false, false, tm, taintVal, true)
			}
			writeX87ToDst := func(dst asm.Operand, w int64, initVal, defVal, taintVal bool) error {
				var bd uint64
				if initVal && defVal {
					bd = abi0BitMaskN(w)
				}
				if w > 8 {
					if err := checkMemAddr(dst); err != nil {
						return err
					}
					var vm uint64
					var full [64]uint8
					if initVal {
						vm = abi0ByteMaskN(w)
						if defVal {
							full = fullBitDefUniform(w, 0xff)
						}
					}
					var tm uint64
					if taintVal {
						tm = abi0ByteMaskN(w)
					}
					specF := asm.OpSpec{Op: op, Width: uint16(w * 8), Effect: asm.EffectWriteOnly}
					return writeDstMask(st, dst, w, vm, bd, full, op, specF, false, false, tm, taintVal, true)
				}
				return writeX87BitsToDst(dst, w, initVal, bd, taintVal)
			}

			switch cat {
			case x87CatConst:
				// All 7 constants in x87ConstSpecs (FLD1, FLDZ, FLDPI, FLDL2E, FLDL2T, FLDLG2, FLDLN2).
				// Irrational constants (SigCeil != "") depend ONLY on live FLDCW RC bits (0x0c00).
				constDef := true
				if cst, ok := x87ConstSpecs[op]; ok && cst.SigCeil != "" {
					constDef = (st.x87CWBitDef & x87CWMaskRC) == x87CWMaskRC
				}
				if !st.pushX87(true, constDef, false) {
					st.x87SWBitDef |= x87SWMaskC1
				}
			case x87CatMove:
				plan := classifyX87Move(op, ins.Args)
				switch plan.Kind {
				case x87MovePushReg:
					srcInit := st.x87StackInit[plan.SrcIdx]
					ovf := st.pushX87(srcInit, st.x87StackDef[plan.SrcIdx], st.x87StackTaint[plan.SrcIdx])
					if !srcInit {
						st.x87SWBitDef &^= x87SWMaskStackFlt
					} else if !ovf {
						st.x87SWBitDef |= x87SWMaskC1
					}
				case x87MoveStoreReg:
					srcInit := st.x87StackInit[plan.SrcIdx]
					st.x87StackInit[plan.DstIdx] = srcInit
					st.x87StackDef[plan.DstIdx] = st.x87StackDef[plan.SrcIdx]
					st.x87StackTaint[plan.DstIdx] = st.x87StackTaint[plan.SrcIdx]
					if !srcInit {
						st.x87SWBitDef &^= x87SWMaskStackFlt
					} else {
						st.x87SWBitDef |= x87SWMaskC1
					}
				case x87MoveStorePopReg:
					// FSTP ST(dstIdx): write ST(dstIdx) = ST(srcIdx) BEFORE popping ST(0).
					srcInit := st.x87StackInit[plan.SrcIdx]
					topInit := st.x87StackInit[0]
					st.x87StackInit[plan.DstIdx] = srcInit
					st.x87StackDef[plan.DstIdx] = st.x87StackDef[plan.SrcIdx]
					st.x87StackTaint[plan.DstIdx] = st.x87StackTaint[plan.SrcIdx]
					_, _, _ = st.popX87()
					if !srcInit || !topInit {
						st.x87SWBitDef &^= x87SWMaskStackFlt
					} else {
						st.x87SWBitDef |= x87SWMaskC1
					}
				case x87MovePushMem, x87MoveLoadMemToReg:
					ev, err := evalOperand(st, ins.Args[plan.MemArg], plan.MemBytes, false, op, ins.Raw)
					if err != nil {
						return nil, err
					}
					_, anyT := evalOperandTaintSP(st, ins.Args[plan.MemArg], plan.MemBytes, false, op)
					if op == "FMOVD" || op == "FMOVF" {
						if !(ev.allBytesInit && ev.allBitsDef) {
							st.x87SWBitDef &^= x87SWMaskIEDE
						}
					}
					if plan.Kind == x87MovePushMem {
						if !st.pushX87(ev.allBytesInit, ev.allBitsDef, anyT) {
							st.x87SWBitDef |= x87SWMaskC1
						}
					} else {
						st.x87StackInit[plan.DstIdx] = ev.allBytesInit
						st.x87StackDef[plan.DstIdx] = ev.allBytesInit && ev.allBitsDef
						st.x87StackTaint[plan.DstIdx] = anyT
						st.x87SWBitDef |= x87SWMaskC1
					}
				case x87MoveStoreMem, x87MoveStorePopMem:
					init0 := st.x87StackInit[plan.SrcIdx]
					def0 := st.x87StackDef[plan.SrcIdx]
					taint0 := st.x87StackTaint[plan.SrcIdx]
					if !init0 {
						st.x87SWBitDef &^= x87SWMaskStackFlt
					}
					if op == "FMOVX" || op == "FMOVXP" {
						if init0 {
							st.x87SWBitDef |= x87SWMaskC1
						}
					} else {
						rcDef := (st.x87CWBitDef & x87CWMaskRC) == x87CWMaskRC
						def0 = def0 && rcDef
						if init0 && def0 {
							st.x87SWBitDef |= x87SWMaskC1
						} else {
							st.x87SWBitDef &^= (x87SWMaskExc | x87SWMaskC1)
						}
					}
					if plan.Pop {
						_, _, _ = st.popX87()
					}
					if err := writeX87ToDst(ins.Args[plan.MemArg], plan.MemBytes, init0, def0, taint0); err != nil {
						return nil, err
					}
				case x87MoveMemToMem:
					if len(ins.Args) == 2 {
						ev, err := evalOperand(st, ins.Args[0], plan.MemBytes, false, op, ins.Raw)
						if err != nil {
							return nil, err
						}
						_, anyT := evalOperandTaintSP(st, ins.Args[0], plan.MemBytes, false, op)
						if plan.Pop {
							_, _, _ = st.popX87()
						}
						if err := writeX87ToDst(ins.Args[1], plan.MemBytes, ev.allBytesInit, ev.allBitsDef, anyT); err != nil {
							return nil, err
						}
					}
				}
			case x87CatSwap:
				if len(ins.Args) == 2 {
					i0, ok0 := x87OperandReg(ins.Args[0])
					i1, ok1 := x87OperandReg(ins.Args[1])
					if ok0 && ok1 {
						bothInit := st.x87StackInit[i0] && st.x87StackInit[i1]
						st.x87StackInit[i0], st.x87StackInit[i1] = st.x87StackInit[i1], st.x87StackInit[i0]
						st.x87StackDef[i0], st.x87StackDef[i1] = st.x87StackDef[i1], st.x87StackDef[i0]
						st.x87StackTaint[i0], st.x87StackTaint[i1] = st.x87StackTaint[i1], st.x87StackTaint[i0]
						if !bothInit {
							st.x87SWBitDef &^= x87SWMaskStackFlt
						} else {
							st.x87SWBitDef |= x87SWMaskC1
						}
					}
				}
			case x87CatArith:
				aspec := x87ArithSpecs[op]
				if len(ins.Args) == 2 {
					ev0, err := evalOperand(st, ins.Args[0], aspec.memBytes, false, op, ins.Raw)
					if err != nil {
						return nil, err
					}
					_, anyT0 := evalOperandTaintSP(st, ins.Args[0], aspec.memBytes, false, op)
					ev1, err := evalOperand(st, ins.Args[1], 8, false, op, ins.Raw)
					if err != nil {
						return nil, err
					}
					_, anyT1 := evalOperandTaintSP(st, ins.Args[1], 8, false, op)
					cwArithDef := (st.x87CWBitDef & (x87CWMaskRC | x87CWMaskPC)) == (x87CWMaskRC | x87CWMaskPC)
					initRes := ev0.allBytesInit && ev1.allBytesInit
					defRes := initRes && ev0.allBitsDef && ev1.allBitsDef && cwArithDef
					taintRes := anyT0 || anyT1
					if !initRes {
						st.x87SWBitDef &^= x87SWMaskStackFlt
					}
					if defRes {
						st.x87SWBitDef |= x87SWMaskC1
					} else {
						st.x87SWBitDef &^= (x87SWMaskExc | x87SWMaskC1)
					}
					if dstIdx, ok := x87OperandReg(ins.Args[1]); ok {
						st.x87StackInit[dstIdx] = initRes
						st.x87StackDef[dstIdx] = defRes
						st.x87StackTaint[dstIdx] = taintRes
					} else {
						if err := writeX87ToDst(ins.Args[1], 8, initRes, defRes, taintRes); err != nil {
							return nil, err
						}
					}
					if aspec.pop {
						_, _, _ = st.popX87()
					}
				}
			case x87CatCmp:
				cspec := x87CmpSpecs[op]
				var lhsOp, rhsOp asm.Operand
				switch len(ins.Args) {
				case 0:
					lhsOp = asm.Operand{Kind: asm.OpReg, Reg: "F0"}
					rhsOp = asm.Operand{Kind: asm.OpReg, Reg: "F1"}
				case 1:
					lhsOp = asm.Operand{Kind: asm.OpReg, Reg: "F0"}
					rhsOp = ins.Args[0]
				case 2:
					if idx, ok := x87OperandReg(ins.Args[1]); ok && idx == 0 {
						lhsOp, rhsOp = ins.Args[1], ins.Args[0]
					} else {
						lhsOp, rhsOp = ins.Args[0], ins.Args[1]
					}
				}
				bothInit := true
				bothDef := true
				if lhsOp.Kind != 0 {
					evL, err := evalOperand(st, lhsOp, cspec.memBytes, false, op, ins.Raw)
					if err != nil {
						return nil, err
					}
					if !evL.allBytesInit {
						bothInit = false
						bothDef = false
					} else if !evL.allBitsDef {
						bothDef = false
					}
				}
				if rhsOp.Kind != 0 {
					evR, err := evalOperand(st, rhsOp, cspec.memBytes, false, op, ins.Raw)
					if err != nil {
						return nil, err
					}
					if !evR.allBytesInit {
						bothInit = false
						bothDef = false
					} else if !evR.allBitsDef {
						bothDef = false
					}
				}
				if !bothInit {
					st.x87SWBitDef &^= x87SWMaskStackFlt
				} else {
					st.x87SWBitDef |= x87SWMaskC1
				}
				if !bothDef {
					st.x87SWBitDef &^= x87SWMaskIEDE
				}
				if cspec.eflags {
					st.cfInit = bothDef
					st.pfInit = bothDef
					st.zfInit = bothDef
					st.ofInit = true
					st.sfInit = true
					st.afInit = true
				} else if bothDef {
					st.x87SWBitDef |= x87SWMaskCC
				} else {
					st.x87SWBitDef &^= x87SWMaskCC
				}
				for i := 0; i < cspec.pops; i++ {
					_, _, _ = st.popX87()
				}
			case x87CatFCMOV:
				if len(ins.Args) == 2 {
					srcIdx, okS := x87OperandReg(ins.Args[0])
					dstIdx, okD := x87OperandReg(ins.Args[1])
					if okS && okD {
						condOK := true
						switch op {
						case "FCMOVB", "FCMOVCS", "FCMOVNB", "FCMOVCC":
							condOK = st.cfInit
						case "FCMOVE", "FCMOVEQ", "FCMOVNE":
							condOK = st.zfInit
						case "FCMOVBE", "FCMOVLS", "FCMOVNBE", "FCMOVHI":
							condOK = st.cfInit && st.zfInit
						case "FCMOVU", "FCMOVUN", "FCMOVNU":
							condOK = st.pfInit
						}
						initRes := st.x87StackInit[srcIdx] && st.x87StackInit[dstIdx] && condOK
						defRes := initRes && st.x87StackDef[srcIdx] && st.x87StackDef[dstIdx]
						taintRes := st.x87StackTaint[srcIdx] || st.x87StackTaint[dstIdx]
						if !st.x87StackInit[srcIdx] || !st.x87StackInit[dstIdx] {
							st.x87SWBitDef &^= x87SWMaskStackFlt
						}
						st.x87StackInit[dstIdx] = initRes
						st.x87StackDef[dstIdx] = defRes
						st.x87StackTaint[dstIdx] = taintRes
					}
				}
			case x87CatUnaryInPlace:
				// Preserves F0 init/taint in place; FSQRT depends on RC|PC, FRNDINT depends on RC,
				// and both update C1 and sticky exceptions (while preserving TOP and C3/C2/C0).
				init0 := st.x87StackInit[0]
				if !init0 {
					st.x87SWBitDef &^= x87SWMaskStackFlt
				}
				switch op {
				case "FSQRT":
					cwDef := (st.x87CWBitDef & (x87CWMaskRC | x87CWMaskPC)) == (x87CWMaskRC | x87CWMaskPC)
					st.x87StackDef[0] = init0 && st.x87StackDef[0] && cwDef
					if st.x87StackDef[0] {
						st.x87SWBitDef |= x87SWMaskC1
					} else {
						st.x87SWBitDef &^= (x87SWMaskExc | x87SWMaskC1)
					}
				case "FRNDINT":
					rcDef := (st.x87CWBitDef & x87CWMaskRC) == x87CWMaskRC
					st.x87StackDef[0] = init0 && st.x87StackDef[0] && rcDef
					if st.x87StackDef[0] {
						st.x87SWBitDef |= x87SWMaskC1
					} else {
						st.x87SWBitDef &^= (x87SWMaskExc | x87SWMaskC1)
					}
				default: // FABS, FCHS
					st.x87StackDef[0] = init0 && st.x87StackDef[0]
					if init0 {
						st.x87SWBitDef |= x87SWMaskC1
					}
				}
			case x87CatStatusTest:
				init0 := st.x87StackInit[0]
				def0 := init0 && st.x87StackDef[0]
				if !init0 {
					st.x87SWBitDef &^= x87SWMaskStackFlt
				} else {
					st.x87SWBitDef |= x87SWMaskC1
				}
				if def0 {
					st.x87SWBitDef |= x87SWMaskCC
				} else {
					st.x87SWBitDef &^= (x87SWMaskCC | x87SWMaskIEDE)
				}
			case x87CatFree:
				if len(ins.Args) == 1 {
					if idx, ok := x87OperandReg(ins.Args[0]); ok {
						st.x87StackInit[idx] = false
						st.x87StackDef[idx] = false
						st.x87StackTaint[idx] = false
					}
				}
			case x87CatRotateUp:
				i0, d0, t0 := st.x87StackInit[0], st.x87StackDef[0], st.x87StackTaint[0]
				for i := 0; i < 7; i++ {
					st.x87StackInit[i] = st.x87StackInit[i+1]
					st.x87StackDef[i] = st.x87StackDef[i+1]
					st.x87StackTaint[i] = st.x87StackTaint[i+1]
				}
				st.x87StackInit[7], st.x87StackDef[7], st.x87StackTaint[7] = i0, d0, t0
				st.x87SWBitDef |= x87SWMaskC1
			case x87CatRotateDown:
				i7, d7, t7 := st.x87StackInit[7], st.x87StackDef[7], st.x87StackTaint[7]
				for i := 7; i > 0; i-- {
					st.x87StackInit[i] = st.x87StackInit[i-1]
					st.x87StackDef[i] = st.x87StackDef[i-1]
					st.x87StackTaint[i] = st.x87StackTaint[i-1]
				}
				st.x87StackInit[0], st.x87StackDef[0], st.x87StackTaint[0] = i7, d7, t7
				st.x87SWBitDef |= x87SWMaskC1
			case x87CatInit:
				st.x87StackInit = [8]bool{}
				st.x87StackDef = [8]bool{}
				st.x87StackTaint = [8]bool{}
				st.x87SWBitDef = 0xffff
				st.x87CWBitDef = 0xffff
			case x87CatNop, x87CatUnsupported:
				// FCLEX clears B|ES|SF|PE..IE (0x80ff) to constant 0 while preserving C3/C2/C1/C0 and TOP.
				if op == "FCLEX" {
					st.x87SWBitDef |= x87SWMaskFCLEX
				}
			case x87CatControlLoad:
				if len(ins.Args) == 1 {
					ev, err := evalOperand(st, ins.Args[0], 2, false, op, ins.Raw)
					if err != nil {
						return nil, err
					}
					if ev.allBytesInit {
						st.x87CWBitDef = uint16(ev.bitDef)
					} else {
						st.x87CWBitDef = 0
					}
				}
			case x87CatControlStore:
				if len(ins.Args) == 1 {
					bitDef := uint64(st.x87CWBitDef)
					if op == "FSTSW" {
						bitDef = uint64(st.x87SWBitDef)
					}
					if err := writeX87BitsToDst(ins.Args[0], 2, true, bitDef, false); err != nil {
						return nil, err
					}
				}
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		// Model stack-pointer displacement, exact per-byte stack-slot
		// initialization, per-bit flag definedness, and per-byte SP taint for
		// PUSH*/POP*/PUSHF*/POPF*/XCHG*.
		switch op {
		case "PUSHFQ", "PUSHFL", "PUSHFW":
			w := int64(8)
			if op == "PUSHFL" {
				w = 4
			} else if op == "PUSHFW" {
				w = 2
			}
			st.spOffset -= w
			b0 := st.flagsLowByteBitMask()
			b1 := st.flagsHighByteBitMask()
			b2 := st.flagsByte2BitMask()
			for b := int64(0); b < w; b++ {
				slot := st.spOffset + b
				st.spBytesInit[slot] = true
				delete(st.spBytesTaintedSP, slot)
				switch b {
				case 0:
					st.spByteBitDef[slot] = b0
				case 1:
					st.spByteBitDef[slot] = b1
				case 2:
					st.spByteBitDef[slot] = b2
				default:
					st.spByteBitDef[slot] = 0xff
				}
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "POPFQ", "POPFL", "POPFW":
			w := int64(8)
			if op == "POPFL" {
				w = 4
			} else if op == "POPFW" {
				w = 2
			}
			b0 := st.spByteBitDef[st.spOffset]
			b1 := st.spByteBitDef[st.spOffset+1]
			b2 := st.spByteBitDef[st.spOffset+2]
			for b := int64(0); b < w; b++ {
				slot := st.spOffset + b
				delete(st.spBytesInit, slot)
				delete(st.spByteBitDef, slot)
				delete(st.spBytesTaintedSP, slot)
			}
			st.spOffset += w
			st.setFlagsFromBytes(b0, b1)
			if w >= 4 {
				st.idInit = (b2 & 0x20) != 0
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "PUSHQ", "PUSHL", "PUSHW":
			w := int64(8)
			if op == "PUSHL" {
				w = 4
			} else if op == "PUSHW" {
				w = 2
			}
			pushMask := abi0ByteMaskN(w)
			pushBitDef := abi0BitMaskN(w)
			var pushTaintMask uint64
			if len(ins.Args) == 1 {
				arg := ins.Args[0]
				ev, err := evalOperand(st, arg, w, false, op, ins.Raw)
				if err != nil {
					return nil, err
				}
				pushMask, pushBitDef = ev.byteMask, ev.bitDef
				pushTaintMask, _ = evalOperandTaintSP(st, arg, w, false, op)
			}
			st.spOffset -= w
			for b := int64(0); b < w; b++ {
				slot := st.spOffset + b
				if (pushMask & (uint64(1) << uint(b))) != 0 {
					st.spBytesInit[slot] = true
					st.spByteBitDef[slot] = uint8(pushBitDef >> uint(b*8))
				} else {
					delete(st.spBytesInit, slot)
					delete(st.spByteBitDef, slot)
				}
				if (pushTaintMask & (uint64(1) << uint(b))) != 0 {
					st.spBytesTaintedSP[slot] = true
				} else {
					delete(st.spBytesTaintedSP, slot)
				}
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "POPQ", "POPL", "POPW":
			w := int64(8)
			if op == "POPL" {
				w = 4
			} else if op == "POPW" {
				w = 2
			}
			var valMask uint64
			var valBitDef uint64
			var fullBD [64]uint8
			var popTaintMask uint64
			var popAnyTaint bool
			for b := int64(0); b < w; b++ {
				slot := st.spOffset + b
				if st.spBytesInit[slot] {
					valMask |= uint64(1) << uint(b)
					bd := st.spByteBitDef[slot]
					valBitDef |= uint64(bd) << uint(b*8)
					fullBD[b] = bd
				}
				if st.spBytesTaintedSP[slot] {
					popAnyTaint = true
					popTaintMask |= uint64(1) << uint(b)
				}
				delete(st.spBytesInit, slot)
				delete(st.spByteBitDef, slot)
				delete(st.spBytesTaintedSP, slot)
			}
			// Intel SDM: POP increments SP before computing an SP-relative destination address.
			st.spOffset += w
			if len(ins.Args) == 1 {
				dst := ins.Args[0]
				if dst.Kind == asm.OpMem {
					if dst.Mem.Base != "" && dst.Mem.Base != asm.SP && dst.Mem.Base != asm.PC {
						if err := checkGPRead(st, dst.Mem.Base, wordMask, ins.Raw); err != nil {
							return nil, err
						}
					}
					if dst.Mem.Index != "" {
						if err := checkGPRead(st, dst.Mem.Index, wordMask, ins.Raw); err != nil {
							return nil, err
						}
					}
				}
				specPop := asm.OpSpec{Op: op, Width: uint16(w * 8), Effect: asm.EffectWriteOnly}
				if err := writeDstMask(st, dst, w, valMask, valBitDef, fullBD, op, specPop, true, false, popTaintMask, popAnyTaint, false); err != nil {
					return nil, err
				}
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		case "XCHGB", "XCHGW", "XCHGL", "XCHGQ":
			if len(ins.Args) == 2 {
				w := int64(8)
				switch op {
				case "XCHGB":
					w = 1
				case "XCHGW":
					w = 2
				case "XCHGL":
					w = 4
				}
				ev0, err := evalOperand(st, ins.Args[0], w, false, op, ins.Raw)
				if err != nil {
					return nil, err
				}
				ev1, err := evalOperand(st, ins.Args[1], w, false, op, ins.Raw)
				if err != nil {
					return nil, err
				}
				tm0, any0 := evalOperandTaintSP(st, ins.Args[0], w, false, op)
				tm1, any1 := evalOperandTaintSP(st, ins.Args[1], w, false, op)
				specXchg := asm.OpSpec{Op: op, Width: uint16(w * 8), Effect: asm.EffectReadWrite}
				if err := writeDstMask(st, ins.Args[0], w, ev1.byteMask, ev1.bitDef, ev1.fullBitDef, op, specXchg, true, false, tm1, any1, ins.Args[1].Kind == asm.OpReg); err != nil {
					return nil, err
				}
				if err := writeDstMask(st, ins.Args[1], w, ev0.byteMask, ev0.bitDef, ev0.fullBitDef, op, specXchg, true, false, tm0, any0, ins.Args[0].Kind == asm.OpReg); err != nil {
					return nil, err
				}
				if pc+1 < len(instrs) {
					enqueue(pc+1, st, false)
				} else {
					finalState = st
				}
				continue
			}
		case "ADDQ", "SUBQ":
			if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpImm && ins.Args[1].Kind == asm.OpReg && ins.Args[1].Reg == asm.SP {
				if op == "ADDQ" {
					st.spOffset += ins.Args[0].Imm
				} else {
					st.spOffset -= ins.Args[0].Imm
				}
				st.cfInit = true
				st.pfInit = true
				st.afInit = true
				st.zfInit = true
				st.sfInit = true
				st.ofInit = true
				if pc+1 < len(instrs) {
					enqueue(pc+1, st, false)
				} else {
					finalState = st
				}
				continue
			}
		}

		if op == "JMP" {
			if len(ins.Args) != 1 {
				return nil, fmt.Errorf("%w: JMP expects one target: %q", asm.ErrProbeNeedsContext, ins.Raw)
			}
			target, isLocal, err := resolveJumpTarget(pc, ins.Args[0])
			if err != nil {
				return nil, err
			}
			if isLocal {
				enqueue(target, st, false)
			}
			// Unconditional JMP never falls through.
			continue
		}

		if isX86CondJumpOp(op) {
			if len(ins.Args) != 1 {
				return nil, fmt.Errorf("%w: %s expects one target: %q", asm.ErrProbeNeedsContext, op, ins.Raw)
			}
			if op == "JCXZ" || op == "JECXZ" || op == "JRCXZ" || op == "LOOP" || op == "LOOPEQ" || op == "LOOPNE" {
				if err := checkGPRead(st, asm.CX, wordMask, ins.Raw); err != nil {
					return nil, err
				}
				if (op == "LOOPEQ" || op == "LOOPNE") && !st.zfInit {
					return nil, fmt.Errorf("%w: %s reads uninitialized flag ZF", asm.ErrProbeNeedsContext, ins.Raw)
				}
			} else if missing := missingCondFlag(st, op); missing != "" {
				return nil, fmt.Errorf("%w: %s reads uninitialized flag %s", asm.ErrProbeNeedsContext, ins.Raw, missing)
			}
			target, isLocal, err := resolveJumpTarget(pc, ins.Args[0])
			if err != nil {
				return nil, err
			}
			if isLocal {
				enqueue(target, st, false)
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			}
			continue
		}

		if op == "CALL" {
			// Outgoing call: validate parameters (byte init, full per-bit definedness,
			// and private-SP confinement) and mark return slots strictly according to
			// the callee signature.
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpSym {
				var csig asm.FuncSig
				var hasSig bool
				if resolve != nil && sigs != nil {
					raw := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
					callee := resolve(raw)
					csig, hasSig = sigs[callee]
				}
				if hasSig {
					if len(csig.ArgRegs) == 0 {
						for _, ps := range csig.Frame.Params {
							sz := x86ABI0SlotBytes(ps.Type, goarch)
							for off := ps.Offset; off < ps.Offset+sz; off++ {
								slot := st.spOffset + off
								if !st.spBytesInit[slot] {
									return nil, fmt.Errorf("%w: %s reads uninitialized outgoing ABI0 arg byte %d(SP)", asm.ErrProbeNeedsContext, ins.Raw, off)
								}
								if st.spByteBitDef[slot] != 0xff {
									return nil, fmt.Errorf("%w: %s reads outgoing ABI0 arg byte %d(SP) with undefined bits (0x%02x)", asm.ErrProbeNeedsContext, ins.Raw, off, st.spByteBitDef[slot])
								}
								if st.spBytesTaintedSP[slot] {
									return nil, fmt.Errorf("%w: private frame address escapes to outgoing ABI0 arg byte %d(SP)", asm.ErrProbeNeedsContext, off)
								}
							}
						}
					} else {
						for _, r := range csig.ArgRegs {
							if err := checkGPRead(st, r, wordMask, ins.Raw); err != nil {
								return nil, err
							}
							if (st.gpBytesTaintedSP[canonicalGP(r)] & wordMask) != 0 {
								return nil, fmt.Errorf("%w: private frame address escapes to outgoing CALL arg %s", asm.ErrProbeNeedsContext, r)
							}
						}
					}
				}
				st.clearCallerSaved()
				if hasSig {
					if len(csig.ArgRegs) == 0 {
						for _, rs := range csig.Frame.Results {
							sz := x86ABI0SlotBytes(rs.Type, goarch)
							for off := rs.Offset; off < rs.Offset+sz; off++ {
								slot := st.spOffset + off
								st.spBytesInit[slot] = true
								st.spByteBitDef[slot] = 0xff
								delete(st.spBytesTaintedSP, slot)
							}
						}
					} else if csig.Ret != "" && csig.Ret != asm.Void {
						sz := x86ABI0SlotBytes(csig.Ret, goarch)
						wMask, clearsUpper := gpRegWriteByteMask(asm.AX, sz, goarch)
						if clearsUpper {
							st.gpBytesInit[asm.AX] = wordMask
							st.gpBitDef[asm.AX] = wordBitMask
						} else if wMask != 0 {
							st.gpBytesInit[asm.AX] = wMask
							st.gpBitDef[asm.AX] = abi0ByteMaskToBitMask(wMask)
						}
					}
				}
			} else if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpReg {
				// Indirect C-ABI/vDSO call (e.g. syscall/asm_linux_amd64.s CALL AX).
				if err := checkGPRead(st, ins.Args[0].Reg, wordMask, ins.Raw); err != nil {
					return nil, err
				}
				st.clearCallerSaved()
				st.gpBytesInit[asm.AX] = wordMask
				st.gpBitDef[asm.AX] = wordBitMask
			} else {
				st.clearCallerSaved()
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		if op == "CLC" || op == "STC" {
			// CLC and STC define CF only; OF/ZF/SF/PF/AF are unaffected.
			st.cfInit = true
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		if op == "CMC" {
			// CMC complements CF in place; CF remains defined iff it was already defined.
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		spec, ok := OpTable.Lookup(op)
		if !ok {
			spec = asm.OpSpec{Op: op, Effect: asm.EffectWriteOnly}
		}

		readBytes, writeBytes := x86ABI0OpWidths(op, spec, ins.Args, goarch)
		isLEA := op == "LEAQ" || op == "LEAL" || op == "LEAW"

		// Self-XOR / self-SUB / self-PCMPEQ / self-KXOR idioms materialize a known
		// constant (0 or all-ones) without depending on prior contents of dst.
		if isZeroingIdiom(op, ins.Args) {
			if err := writeDstMask(st, ins.Args[len(ins.Args)-1], writeBytes, abi0ByteMaskN(writeBytes), abi0BitMaskN(writeBytes), fullBitDefUniform(writeBytes, 0xff), op, spec, false, false, 0, false, true); err != nil {
				return nil, err
			}
			if isX86ClearCFOfOp(op) || isX86GPFlagWriter(op) {
				st.cfInit = true
				st.pfInit = true
				st.zfInit = true
				st.sfInit = true
				st.ofInit = true
				// Intel SDM: SUB defines AF=0; XOR leaves AF undefined.
				if strings.HasPrefix(string(op), "SUB") {
					st.afInit = true
				} else if strings.HasPrefix(string(op), "XOR") {
					st.afInit = false
				}
			}
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		// Lane-accurate vector element/subvector extract, insert, half-register
		// move, and byte-shift instructions preserve exact per-byte init,
		// per-bit definedness, and per-byte SP-taint on only the selected slice
		// so unselected lanes containing undefined bits do not poison valid extracts.
		if handled, err := handleX86VecLaneOp(st, op, ins, goarch, wordMask, wordBitMask, checkGPRead, evalOperand, evalOperandTaintSP, writeDstMask); err != nil {
			return nil, err
		} else if handled {
			if pc+1 < len(instrs) {
				enqueue(pc+1, st, false)
			} else {
				finalState = st
			}
			continue
		}

		if spec.Family == asm.FamilyString && !st.dfInit {
			return nil, fmt.Errorf("%w: %s reads undefined flag DF", asm.ErrProbeNeedsContext, ins.Raw)
		}

		// Check implicit architectural register reads. Memory/trapping ops (string
		// ops, DIV/IDIV, SYSCALL, XLAT) hard-require initialized implicit inputs;
		// nontrapping ALU ops propagate definedness to their outputs.
		impReads, impWrites := implicitRegByteEffects(op, spec, curRep, wordMask)
		allInputsInit := true
		allInputsBitDef := true
		srcAnyTaint := false
		hardImplicit := spec.Family == asm.FamilyString ||
			op == "DIVB" || op == "IDIVB" || op == "DIVW" || op == "IDIVW" ||
			op == "DIVL" || op == "IDIVL" || op == "DIVQ" || op == "IDIVQ" ||
			op == "SYSCALL" || op == "XLAT"
		for _, ir := range impReads {
			if hardImplicit {
				if err := checkGPRead(st, ir.reg, ir.mask, ins.Raw); err != nil {
					return nil, err
				}
			} else if (st.gpBytesInit[ir.reg] & ir.mask) != ir.mask {
				allInputsInit = false
			}
			irBits := abi0ByteMaskToBitMask(ir.mask)
			if (st.gpBitDef[ir.reg] & irBits) != irBits {
				allInputsBitDef = false
			}
			if (st.gpBytesTaintedSP[ir.reg] & ir.mask) != 0 {
				srcAnyTaint = true
			}
		}

		// Flag-consuming instructions require their exact consumed flag(s) to be initialized.
		// For RCL/RCR with an immediate effective count of 0, CF is neither read nor modified.
		if missingCondFlag(st, op) != "" {
			allInputsInit = false
			allInputsBitDef = false
		}
		if needsNonCondCF(op, ins.Args) && !st.cfInit {
			allInputsInit = false
			allInputsBitDef = false
		}
		if (op == "ADOXL" || op == "ADOXQ") && !st.ofInit {
			allInputsInit = false
			allInputsBitDef = false
		}

		// Check source operands. EffectPreserveUpper preserves upper lanes of the
		// destination register; for pure byte-preserving moves we propagate exact
		// per-byte initialization, per-bit definedness, and per-byte SP taint masks.
		n := len(ins.Args)
		readEnd := n - 1
		if spec.Effect == asm.EffectReadOnly || spec.Effect == asm.EffectReadWrite ||
			spec.Effect == asm.EffectPreserveUpper || (spec.Effect == asm.EffectImplicit && !spec.ThreeOp) {
			readEnd = n
		}
		if spec.ThreeOp && spec.Effect == asm.EffectImplicit && n == 3 {
			// MULXL/MULXQ src, hi, lo reads only src (args[0]) and writes both hi and lo.
			readEnd = 1
		}
		if (op == "MOVSS" || op == "MOVSD") && n == 2 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg {
			readEnd = 1
		}
		// Check base/index registers of a memory destination (e.g. MOVQ $1, 8(BX) reads BX!).
		if n > 0 && readEnd < n && ins.Args[n-1].Kind == asm.OpMem {
			dstMem := ins.Args[n-1].Mem
			if dstMem.Base != "" && dstMem.Base != asm.SP && dstMem.Base != asm.PC {
				if err := checkGPRead(st, dstMem.Base, wordMask, ins.Raw); err != nil {
					return nil, err
				}
			}
			if dstMem.Index != "" {
				if err := checkGPRead(st, dstMem.Index, wordMask, ins.Raw); err != nil {
					return nil, err
				}
			}
		}

		pureCopy := isPureByteCopyOp(op, ins.Args)
		var copyMask uint64
		var copyBitDef uint64
		var copyFullBitDef [64]uint8
		var copyTaintMask uint64
		var arg0BitDef uint64
		var dstInBitDef uint64

		srcFromRaw := false
		for i := 0; i < readEnd && i < n; i++ {
			a := ins.Args[i]
			if a.Kind == asm.OpReg {
				if idx, ok := anyVecRegIndex(a.Reg); ok && st.vecFromRaw[idx] {
					srcFromRaw = true
				}
			}
			argReadBytes := readBytes
			if i == n-1 && readEnd == n {
				// Read-modify-write destination reads its own write width.
				argReadBytes = writeBytes
			}
			if i == 0 && isShiftWithCountArg(op) && a.Kind == asm.OpReg {
				// Shift/rotate count in CL/CX only reads byte 0.
				argReadBytes = 1
			}
			// EffectPreserveUpper only reads the low scalar lane of src and preserves
			// upper lanes of dst (which should not poison the low lane).
			if spec.Effect == asm.EffectPreserveUpper && i == n-1 && a.Kind == asm.OpReg {
				continue
			}
			ev, err := evalOperand(st, a, argReadBytes, isLEA, op, ins.Raw)
			if err != nil {
				return nil, err
			}
			tm, anyT := evalOperandTaintSP(st, a, argReadBytes, isLEA, op)
			if anyT {
				srcAnyTaint = true
			}
			if i == 0 {
				arg0BitDef = ev.bitDef
				if pureCopy {
					copyMask = ev.byteMask
					copyBitDef = ev.bitDef
					copyFullBitDef = ev.fullBitDef
					copyTaintMask = tm
				}
			}
			if i == n-1 {
				dstInBitDef = ev.bitDef
			}
			if !ev.allBytesInit {
				allInputsInit = false
			}
			if !ev.allBitsDef {
				allInputsBitDef = false
			}
		}
		if hardImplicit && (!allInputsInit || !allInputsBitDef) {
			return nil, fmt.Errorf("%w: %s reads uninitialized or partially-undefined operand", asm.ErrProbeNeedsContext, ins.Raw)
		}

		// Apply destination writes with exact per-byte init, per-bit definedness,
		// and per-byte SP-taint propagation.
		var dstValMask uint64
		var dstValBitDef uint64
		var dstFullBitDef [64]uint8
		var dstTaintMask uint64
		if pureCopy {
			dstValMask = copyMask
			dstValBitDef = copyBitDef
			dstFullBitDef = copyFullBitDef
			dstTaintMask = copyTaintMask
		} else {
			if allInputsInit {
				dstValMask = abi0ByteMaskN(writeBytes)
			}
			dstValBitDef = computeX86OpBitDef(op, ins.Args, readBytes, writeBytes, arg0BitDef, dstInBitDef, allInputsInit, allInputsBitDef)
			if allInputsInit && allInputsBitDef {
				dstFullBitDef = fullBitDefUniform(writeBytes, 0xff)
			} else {
				dstFullBitDef = fullBitDefFromLow64(dstValBitDef, dstValMask, writeBytes)
			}
			if srcAnyTaint {
				w := writeBytes
				if w <= 0 || w > 64 {
					w = 64
				}
				dstTaintMask = abi0ByteMaskN(w)
			}
		}

		srcIsReg := n >= 2 && ins.Args[0].Kind == asm.OpReg
		if spec.ThreeOp && spec.Effect == asm.EffectImplicit && n == 3 {
			for i := 1; i < n; i++ {
				if err := writeDstMask(st, ins.Args[i], writeBytes, dstValMask, dstValBitDef, dstFullBitDef, op, spec, false, srcFromRaw, dstTaintMask, srcAnyTaint, srcIsReg); err != nil {
					return nil, err
				}
			}
		} else if n > 0 && spec.Effect != asm.EffectReadOnly && spec.Effect != asm.EffectNone && spec.Effect != asm.EffectImplicit {
			if err := writeDstMask(st, ins.Args[n-1], writeBytes, dstValMask, dstValBitDef, dstFullBitDef, op, spec, pureCopy, srcFromRaw, dstTaintMask, srcAnyTaint, srcIsReg); err != nil {
				return nil, err
			}
		}
		for _, iw := range impWrites {
			iwBitMask := abi0ByteMaskToBitMask(iw.mask)
			if allInputsInit && allInputsBitDef {
				if iw.clearsUpper {
					st.gpBytesInit[iw.reg] = wordMask
					st.gpBitDef[iw.reg] = wordBitMask
					if srcAnyTaint {
						st.gpBytesTaintedSP[iw.reg] = iw.mask
					} else {
						delete(st.gpBytesTaintedSP, iw.reg)
					}
				} else {
					st.gpBytesInit[iw.reg] |= iw.mask
					st.gpBitDef[iw.reg] |= iwBitMask
					if srcAnyTaint {
						st.gpBytesTaintedSP[iw.reg] |= iw.mask
					} else {
						st.gpBytesTaintedSP[iw.reg] &^= iw.mask
						if st.gpBytesTaintedSP[iw.reg] == 0 {
							delete(st.gpBytesTaintedSP, iw.reg)
						}
					}
				}
			} else {
				if iw.clearsUpper {
					st.gpBytesInit[iw.reg] = wordMask &^ iw.mask
					st.gpBitDef[iw.reg] = wordBitMask &^ iwBitMask
				} else {
					st.gpBytesInit[iw.reg] &^= iw.mask
					st.gpBitDef[iw.reg] &^= iwBitMask
				}
				if srcAnyTaint {
					st.gpBytesTaintedSP[iw.reg] |= iw.mask
				}
			}
		}
		if op == "LAHF" {
			// Copy exact low-byte status-flag bit-definedness into AH (byte 1 of AX)
			// without touching AL or upper bytes of AX.
			st.gpBytesInit[asm.AX] |= 0x02
			st.gpBitDef[asm.AX] = (st.gpBitDef[asm.AX] &^ 0xff00) | (uint64(st.flagsLowByteBitMask()) << 8)
			st.gpBytesTaintedSP[asm.AX] &^= 0x02
			if st.gpBytesTaintedSP[asm.AX] == 0 {
				delete(st.gpBytesTaintedSP, asm.AX)
			}
		}
		// Update status flags independently per architectural semantics.
		flagsInputsInit := computeX86FlagInputsInit(op, ins.Args, readBytes, writeBytes, arg0BitDef, dstInBitDef, allInputsInit, allInputsBitDef)
		updateX86FlagsAfter(st, op, ins.Args, flagsInputsInit)
		if pc+1 < len(instrs) {
			enqueue(pc+1, st, false)
		} else {
			finalState = st
		}
	}

	// Verify that on EVERY reachable RET (and any fallthrough end), every byte of
	// every declared ABI0 result slot was initialized with all 8 bits defined on
	// ALL paths reaching it.
	if finalState != nil {
		retStates = append(retStates, finalState)
	}
	for _, st := range retStates {
		for _, span := range resultSpans {
			for off := span.offset; off < span.offset+span.size; off++ {
				if !st.fpBytesInit[off] {
					return nil, fmt.Errorf("%w: RET with uninitialized result byte +%d(FP) (result slot +%d(FP) width %d)",
						asm.ErrProbeNeedsContext, off, span.offset, span.size)
				}
				if st.fpByteBitDef[off] != 0xff {
					return nil, fmt.Errorf("%w: RET with undefined bits (0x%02x) in result byte +%d(FP) (result slot +%d(FP) width %d)",
						asm.ErrProbeNeedsContext, st.fpByteBitDef[off], off, span.offset, span.size)
				}
			}
		}
	}

	// Build summary report from the intersection of reachable exit states (or entry if no RET).
	var summary *abi0State
	for _, st := range retStates {
		if summary == nil {
			summary = st.clone()
		} else {
			summary.merge(st)
		}
	}
	if summary == nil {
		summary = entry
	}
	return buildABI0Report(summary, resultSpans, wordMask), nil
}

type abi0SlotSpan struct {
	offset int64
	size   int64
}

func buildABI0Report(summary *abi0State, resultSpans []abi0SlotSpan, wordMask uint8) *ABI0EffectReport {
	initGP := make(map[asm.Reg]bool, len(summary.gpBytesInit))
	for r, mask := range summary.gpBytesInit {
		if (mask & wordMask) == wordMask {
			initGP[r] = true
		}
	}
	initVec := make(map[int]bool, len(summary.vecBytesInit))
	for idx, mask := range summary.vecBytesInit {
		if (mask & 0xffff) == 0xffff {
			initVec[idx] = true
		}
	}
	writtenResults := map[int64]bool{}
	for _, span := range resultSpans {
		allInit := true
		for off := span.offset; off < span.offset+span.size; off++ {
			if !summary.fpBytesInit[off] {
				allInit = false
				break
			}
		}
		if allInit {
			writtenResults[span.offset] = true
		}
	}
	return &ABI0EffectReport{
		InitializedGP:  initGP,
		InitializedVec: initVec,
		WrittenResults: writtenResults,
	}
}

func gpRegReadByteMask(r asm.Reg, readBytes int64, wordMask uint8) uint8 {
	up := asm.Reg(strings.ToUpper(strings.TrimSpace(string(r))))
	if _, shift, ok := amd64ByteAlias(up); ok {
		if shift == 8 {
			return 0x02
		}
		return 0x01
	}
	switch readBytes {
	case 1:
		return 0x01
	case 2:
		return 0x03
	case 4:
		return 0x0f
	case 8:
		return wordMask
	default:
		return wordMask
	}
}

func gpRegWriteByteMask(r asm.Reg, writeBytes int64, goarch string) (mask uint8, clearsUpper bool) {
	up := asm.Reg(strings.ToUpper(strings.TrimSpace(string(r))))
	if _, shift, ok := amd64ByteAlias(up); ok {
		if shift == 8 {
			return 0x02, false
		}
		return 0x01, false
	}
	switch writeBytes {
	case 1:
		return 0x01, false
	case 2:
		return 0x03, false
	case 4:
		// 32-bit GP writes zero-extend to 64 bits on amd64, and fill the full word on 386.
		return 0x0f, true
	case 8:
		return 0xff, true
	default:
		if goarch == "386" {
			return 0x0f, true
		}
		return 0xff, true
	}
}

func vecRegReadByteMask(r asm.Reg, op asm.Op, readBytes int64) uint64 {
	if isAMD64ZReg(r) {
		return ^uint64(0)
	}
	if isAMD64YReg(r) {
		return 0xffffffff
	}
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	switch name {
	case "MOVSS", "VMOVSS", "ADDSS", "SUBSS", "MULSS", "DIVSS", "SQRTSS", "MINSS", "MAXSS",
		"UCOMISS", "COMISS", "CVTSS2SD", "CVTSS2SI", "CVTTSS2SI", "CVTSS2SIL", "CVTSS2SIQ",
		"CVTTSS2SIL", "CVTTSS2SIQ", "MOVD", "VMOVD", "MOVL":
		return 0x0f
	case "MOVSD", "VMOVSD", "ADDSD", "SUBSD", "MULSD", "DIVSD", "SQRTSD", "MINSD", "MAXSD",
		"UCOMISD", "COMISD", "CVTSD2SS", "CVTSD2SI", "CVTTSD2SI", "CVTSD2SIL", "CVTSD2SIQ",
		"CVTTSD2SIL", "CVTTSD2SIQ", "MOVQ", "VMOVQ":
		return 0xff
	}
	if readBytes == 4 {
		return 0x0f
	}
	if readBytes == 8 {
		return 0xff
	}
	return 0xffff
}

func vecRegWriteByteMask(r asm.Reg, op asm.Op, writeBytes int64, srcIsReg bool) (mask uint64, zeroUpper bool) {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	// VEX/EVEX instructions write their vector width and zero all upper bytes up to ZMM.
	if strings.HasPrefix(name, "V") {
		return ^uint64(0), true
	}
	// Legacy SSE scalar reg-to-reg MOVSS/MOVSD preserves upper bytes of XMM.
	if name == "MOVSS" && srcIsReg {
		return 0x0f, false
	}
	if name == "MOVSD" && srcIsReg {
		return 0xff, false
	}
	// All other legacy SSE writes (including MOVSS/MOVSD mem->reg, MOVL/MOVQ->XMM, MOVOU, PXOR, ...)
	// define all 16 bytes of the XMM register.
	return 0xffff, false
}

func isShiftWithCountArg(op asm.Op) bool {
	switch op {
	case "SHLB", "SHLW", "SHLL", "SHLQ",
		"SALB", "SALW", "SALL", "SALQ",
		"SHRB", "SHRW", "SHRL", "SHRQ",
		"SARB", "SARW", "SARL", "SARQ",
		"ROLB", "ROLW", "ROLL", "ROLQ",
		"RORB", "RORW", "RORL", "RORQ",
		"RCLB", "RCLW", "RCLL", "RCLQ",
		"RCRB", "RCRW", "RCRL", "RCRQ",
		"SHLDW", "SHLDL", "SHLDQ",
		"SHRDW", "SHRDL", "SHRDQ":
		return true
	default:
		return false
	}
}

func isX86CondJumpOp(op asm.Op) bool {
	switch op {
	case "JE", "JEQ", "JZ", "JNE", "JNZ",
		"JL", "JLT", "JLE", "JG", "JGT", "JGE",
		"JB", "JLO", "JBE", "JNA", "JLS", "JA", "JHI", "JAE", "JHS", "JNB", "JNAE", "JNBE", "JNGE", "JNL", "JNG", "JNLE",
		"JC", "JNC", "JCC", "JCS",
		"JS", "JNS", "JMI", "JPL",
		"JO", "JNO", "JOS", "JOC",
		"JP", "JPE", "JNP", "JPO", "JPS", "JPC",
		"JCXZ", "JECXZ", "JRCXZ", "LOOP", "LOOPEQ", "LOOPNE":
		return true
	default:
		return false
	}
}

func x86ABI0SlotBytes(ty asm.LLVMType, goarch string) int64 {
	switch ty {
	case asm.I1, asm.I8:
		return 1
	case asm.I16:
		return 2
	case asm.I32, "float":
		return 4
	case asm.I64, "double":
		return 8
	case asm.Ptr:
		if goarch == "386" {
			return 4
		}
		return 8
	default:
		return int64(x86FrameTypeSize(ty))
	}
}

func x86ABI0OpWidths(op asm.Op, spec asm.OpSpec, args []asm.Operand, goarch string) (readBytes, writeBytes int64) {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	// Explicit widening / narrowing integer moves have distinct source and destination widths.
	switch name {
	case "MOVBWZX", "MOVBWSX":
		return 1, 2
	case "MOVBLZX", "MOVBLSX":
		return 1, 4
	case "MOVBQZX", "MOVBQSX":
		return 1, 8
	case "MOVWLZX", "MOVWLSX":
		return 2, 4
	case "MOVWQZX", "MOVWQSX":
		return 2, 8
	case "MOVLQZX", "MOVLQSX":
		return 4, 8
	case "KMOVB":
		// KMOVB k, r32 zero-extends to 32/64 bits on GP destination.
		if len(args) == 2 && args[1].Kind == asm.OpReg && !isAMD64KReg(args[1].Reg) {
			return 1, 4
		}
		return 1, 1
	case "KMOVW":
		// KMOVW k, r32 zero-extends to 32/64 bits on GP destination.
		if len(args) == 2 && args[1].Kind == asm.OpReg && !isAMD64KReg(args[1].Reg) {
			return 2, 4
		}
		return 2, 2
	case "PMOVMSKB", "VPMOVMSKB", "MOVMSKPS", "VMOVMSKPS", "MOVMSKPD", "VMOVMSKPD":
		return 16, 4
	case "PEXTRB", "VPEXTRB", "PEXTRW", "VPEXTRW", "PEXTRD", "VPEXTRD":
		if len(args) >= 2 && args[len(args)-1].Kind == asm.OpReg {
			return 16, 4
		}
	case "PEXTRQ", "VPEXTRQ":
		if len(args) >= 2 && args[len(args)-1].Kind == asm.OpReg {
			return 16, 8
		}
	case "CVTSI2SSL", "CVTSI2SDL", "CVTSS2SIL", "CVTSD2SIL", "CVTTSS2SIL", "CVTTSD2SIL",
		"VCVTSI2SSL", "VCVTSI2SDL", "VCVTSS2SIL", "VCVTSD2SIL", "VCVTTSS2SIL", "VCVTTSD2SIL":
		return 4, 4
	case "CVTSI2SSQ", "CVTSI2SDQ", "CVTSS2SIQ", "CVTSD2SIQ", "CVTTSS2SIQ", "CVTTSD2SIQ",
		"VCVTSI2SSQ", "VCVTSI2SDQ", "VCVTSS2SIQ", "VCVTSD2SIQ", "VCVTTSS2SIQ", "VCVTTSD2SIQ":
		return 8, 8
	}
	if spec.SrcWidth > 0 && spec.Width > 0 {
		return int64(spec.SrcWidth) / 8, int64(spec.Width) / 8
	}
	w := x86ABI0WriteBytes(op, spec, args)
	if w > 0 {
		return w, w
	}
	if goarch == "386" {
		return 4, 4
	}
	return 8, 8
}

func x86ABI0WriteBytes(op asm.Op, spec asm.OpSpec, args []asm.Operand) int64 {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	if spec.Width > 0 {
		return int64(spec.Width) / 8
	}
	// Vector stores/loads: infer width from vector register if present.
	for _, a := range args {
		if a.Kind == asm.OpReg {
			if isAMD64ZReg(a.Reg) {
				return 64
			}
			if isAMD64YReg(a.Reg) {
				return 32
			}
			if isAMD64XReg(a.Reg) {
				switch name {
				case "MOVSS", "VMOVSS", "MOVD", "VMOVD", "MOVL":
					return 4
				case "MOVSD", "VMOVSD", "MOVQ", "VMOVQ", "MOVHPS", "MOVLPS", "MOVHPD", "MOVLPD":
					return 8
				default:
					return 16
				}
			}
			if isAMD64MReg(a.Reg) {
				if name == "MOVD" || name == "MOVL" {
					return 4
				}
				return 8
			}
		}
	}
	// SETcc writes 1 byte.
	if strings.HasPrefix(name, "SET") {
		return 1
	}
	if strings.HasPrefix(name, "CMOV") {
		switch {
		case strings.HasPrefix(name, "CMOVW"):
			return 2
		case strings.HasPrefix(name, "CMOVL"):
			return 4
		case strings.HasPrefix(name, "CMOVQ"):
			return 8
		}
	}
	switch name {
	case "MOVB", "ADDB", "SUBB", "ANDB", "ORB", "XORB", "ADCB", "SBBB", "CMPB", "TESTB",
		"INCB", "DECB", "NEGB", "NOTB", "XCHGB", "XADDB", "CMPXCHGB",
		"SHLB", "SHRB", "SARB", "ROLB", "RORB", "RCLB", "RCRB", "SALB", "KMOVB":
		return 1
	case "MOVW", "ADDW", "SUBW", "ANDW", "ORW", "XORW", "ADCW", "SBBW", "CMPW", "TESTW",
		"INCW", "DECW", "NEGW", "NOTW", "XCHGW", "XADDW", "CMPXCHGW", "IMULW", "MULW",
		"SHLW", "SHRW", "SARW", "ROLW", "RORW", "RCLW", "RCRW", "SALW", "SHLDW", "SHRDW",
		"BTWW", "BTW", "BTSW", "BTRW", "BTCW", "BSFW", "BSRW", "POPCNTW", "LZCNTW", "TZCNTW",
		"FSTCW", "FSTSW", "FMOVW", "FMOVWP", "MOVBEW", "LEAW", "KMOVW":
		return 2
	case "MOVL", "MOVSS", "VMOVSS", "ADDL", "SUBL", "ANDL", "ORL", "XORL", "ADCL", "SBBL", "CMPL", "TESTL",
		"INCL", "DECL", "NEGL", "NOTL", "XCHGL", "XADDL", "CMPXCHGL", "IMULL", "MULL", "MULXL",
		"SHLL", "SHRL", "SARL", "ROLL", "RORL", "RCLL", "RCRL", "SALL", "SHLDL", "SHRDL",
		"BTL", "BTSL", "BTRL", "BTCL", "BSFL", "BSRL", "POPCNTL", "LZCNTL", "TZCNTL", "ANDNL", "BEXTRL",
		"BLSIL", "BLSMSKL", "BLSRL", "BZHIL", "PEXPL", "PDEPL", "PEXTL", "RORXL", "SARXL", "SHLXL", "SHRXL",
		"BSWAPL", "FMOVF", "FMOVFP", "FMOVL", "FMOVLP", "MOVBEL", "MOVNTI", "MOVNTIL", "LEAL", "KMOVD", "MOVD":
		return 4
	case "MOVQ", "MOVSD", "VMOVSD", "ADDQ", "SUBQ", "ANDQ", "ORQ", "XORQ", "ADCQ", "SBBQ", "CMPQ", "TESTQ",
		"INCQ", "DECQ", "NEGQ", "NOTQ", "XCHGQ", "XADDQ", "CMPXCHGQ", "IMULQ", "MULQ", "MULXQ",
		"SHLQ", "SHRQ", "SARQ", "ROLQ", "RORQ", "RCLQ", "RCRQ", "SALQ", "SHLDQ", "SHRDQ",
		"BTQ", "BTSQ", "BTRQ", "BTCQ", "BSFQ", "BSRQ", "POPCNTQ", "LZCNTQ", "TZCNTQ", "ANDNQ", "BEXTRQ",
		"BLSIQ", "BLSMSKQ", "BLSRQ", "BZHIQ", "PDEPQ", "PEXTQ", "RORXQ", "SARXQ", "SHLXQ", "SHRXQ",
		"BSWAPQ", "FMOVD", "FMOVDP", "FMOVV", "FMOVVP", "MOVBEQ", "MOVNTIQ", "LEAQ", "KMOVQ", "ADCXQ", "ADOXQ":
		return 8
	case "MOVO", "MOVOU", "MOVOA", "MOVUPS", "MOVUPD", "MOVAPS", "MOVAPD", "MOVDQU", "MOVDQA", "MOVNTDQ", "MOVNTDQA", "MOVNTPS", "MOVNTPD":
		return 16
	}
	return 0
}

type regMaskEffect struct {
	reg         asm.Reg
	mask        uint8
	clearsUpper bool
}

func implicitRegByteEffects(op asm.Op, spec asm.OpSpec, repeated bool, wordMask uint8) (reads []regMaskEffect, writes []regMaskEffect) {
	full := func(r asm.Reg) regMaskEffect { return regMaskEffect{reg: r, mask: wordMask, clearsUpper: true} }
	part := func(r asm.Reg, m uint8, clear bool) regMaskEffect {
		return regMaskEffect{reg: r, mask: m, clearsUpper: clear}
	}

	switch spec.Family {
	case asm.FamilyString:
		if repeated {
			reads = append(reads, full(asm.CX))
			writes = append(writes, full(asm.CX))
		}
		axMask := wordMask
		axClear := true
		switch spec.Width {
		case 8:
			axMask, axClear = 0x01, false
		case 16:
			axMask, axClear = 0x03, false
		case 32:
			axMask, axClear = 0x0f, true
		}
		switch spec.LLVMOp {
		case "movs", "cmps":
			reads = append(reads, full(asm.SI), full(asm.DI))
			writes = append(writes, full(asm.SI), full(asm.DI))
		case "stos", "scas":
			reads = append(reads, part(asm.AX, axMask, false), full(asm.DI))
			writes = append(writes, full(asm.DI))
		case "lods":
			reads = append(reads, full(asm.SI))
			writes = append(writes, part(asm.AX, axMask, axClear), full(asm.SI))
		}
		return reads, writes
	}

	switch op {
	case "MULB":
		return []regMaskEffect{part(asm.AX, 0x01, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "MULW":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false), part(asm.DX, 0x03, false)}
	case "MULL":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{part(asm.AX, 0x0f, true), part(asm.DX, 0x0f, true)}
	case "MULQ":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "MULXL":
		return []regMaskEffect{part(asm.DX, 0x0f, false)}, nil
	case "MULXQ":
		return []regMaskEffect{full(asm.DX)}, nil
	case "DIVB", "IDIVB":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "DIVW", "IDIVW":
		return []regMaskEffect{part(asm.AX, 0x03, false), part(asm.DX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false), part(asm.DX, 0x03, false)}
	case "DIVL", "IDIVL":
		return []regMaskEffect{part(asm.AX, 0x0f, false), part(asm.DX, 0x0f, false)}, []regMaskEffect{part(asm.AX, 0x0f, true), part(asm.DX, 0x0f, true)}
	case "DIVQ", "IDIVQ":
		return []regMaskEffect{full(asm.AX), full(asm.DX)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "CWD":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.DX, 0x03, false)}
	case "CDQ":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{part(asm.DX, 0x0f, true)}
	case "CQO":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.DX)}
	case "CBW":
		return []regMaskEffect{part(asm.AX, 0x01, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "CWDE":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x0f, true)}
	case "CDQE":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{full(asm.AX)}
	case "CPUID":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{full(asm.AX), full(asm.BX), full(asm.CX), full(asm.DX)}
	case "XGETBV":
		return []regMaskEffect{part(asm.CX, 0x0f, false)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "RDTSC":
		return nil, []regMaskEffect{full(asm.AX), full(asm.DX)}
	case "RDTSCP":
		return nil, []regMaskEffect{full(asm.AX), full(asm.DX), full(asm.CX)}
	case "SYSCALL":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.AX), full(asm.DX), full(asm.CX)}
	case "LAHF":
		return nil, []regMaskEffect{part(asm.AX, 0x02, false)}
	case "SAHF":
		return []regMaskEffect{part(asm.AX, 0x02, false)}, nil
	case "PCMPESTRI":
		return []regMaskEffect{part(asm.AX, 0x0f, false), part(asm.DX, 0x0f, false)}, []regMaskEffect{part(asm.CX, 0x0f, true)}
	case "XLAT":
		return []regMaskEffect{part(asm.AX, 0x01, false), full(asm.BX)}, []regMaskEffect{part(asm.AX, 0x01, false)}
	case "CMPXCHGB":
		return []regMaskEffect{part(asm.AX, 0x01, false)}, []regMaskEffect{part(asm.AX, 0x01, false)}
	case "CMPXCHGW":
		return []regMaskEffect{part(asm.AX, 0x03, false)}, []regMaskEffect{part(asm.AX, 0x03, false)}
	case "CMPXCHGL":
		return []regMaskEffect{part(asm.AX, 0x0f, false)}, []regMaskEffect{part(asm.AX, 0x0f, true)}
	case "CMPXCHGQ":
		return []regMaskEffect{full(asm.AX)}, []regMaskEffect{full(asm.AX)}
	case "CMPXCHG8B":
		return []regMaskEffect{part(asm.AX, 0x0f, false), part(asm.DX, 0x0f, false), part(asm.BX, 0x0f, false), part(asm.CX, 0x0f, false)},
			[]regMaskEffect{part(asm.AX, 0x0f, true), part(asm.DX, 0x0f, true)}
	case "CMPXCHG16B":
		return []regMaskEffect{full(asm.AX), full(asm.DX), full(asm.BX), full(asm.CX)}, []regMaskEffect{full(asm.AX), full(asm.DX)}
	}

	if spec.Implicit != asm.ImplicitNone {
		for _, pair := range []struct {
			mask asm.RegMask
			reg  asm.Reg
		}{
			{asm.ImplicitAX, asm.AX},
			{asm.ImplicitBX, asm.BX},
			{asm.ImplicitCX, asm.CX},
			{asm.ImplicitDX, asm.DX},
			{asm.ImplicitSI, asm.SI},
			{asm.ImplicitDI, asm.DI},
		} {
			if spec.Implicit&pair.mask != 0 {
				writes = append(writes, full(pair.reg))
			}
		}
	}
	return reads, writes
}

func isZeroingIdiom(op asm.Op, args []asm.Operand) bool {
	if len(args) == 2 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[0].Reg == args[1].Reg {
		switch op {
		case "XORQ", "XORL", "XORW", "XORB", "SUBQ", "SUBL", "SUBW", "SUBB",
			"PXOR", "XORPS", "XORPD", "PCMPEQB", "PCMPEQW", "PCMPEQD", "PCMPEQQ":
			return true
		}
	}
	if len(args) == 3 && args[0].Kind == asm.OpReg && args[1].Kind == asm.OpReg && args[2].Kind == asm.OpReg &&
		args[0].Reg == args[1].Reg {
		switch op {
		case "VPXOR", "VPXORD", "VPXORQ", "VXORPS", "VXORPD",
			"VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ",
			"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ",
			"KXORB", "KXORW", "KXORD", "KXORQ",
			"KXNORB", "KXNORW", "KXNORD", "KXNORQ":
			return true
		}
	}
	return false
}

func anyVecRegIndex(r asm.Reg) (int, bool) {
	if idx, ok := amd64ParseXReg(r); ok {
		return idx, true
	}
	if idx, ok := amd64ParseYReg(r); ok {
		return idx, true
	}
	if idx, ok := amd64ParseZReg(r); ok {
		return idx, true
	}
	return 0, false
}

func canonicalGP(r asm.Reg) asm.Reg {
	up := asm.Reg(strings.ToUpper(strings.TrimSpace(string(r))))
	if base, _, ok := amd64ByteAlias(up); ok {
		return base
	}
	if parsed, ok := asm.ParseReg(string(up)); ok {
		if base, _, ok := amd64ByteAlias(parsed); ok {
			return base
		}
		return parsed
	}
	return up
}

func abi0ByteMaskN(n int64) uint64 {
	if n <= 0 {
		return 0
	}
	if n >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(n)) - 1
}

func abi0BitMaskN(n int64) uint64 {
	if n <= 0 {
		return 0
	}
	if n >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(n*8)) - 1
}

func abi0ByteMaskToBitMask(byteMask uint8) uint64 {
	var out uint64
	for b := uint(0); b < 8; b++ {
		if (byteMask & (1 << b)) != 0 {
			out |= uint64(0xff) << (b * 8)
		}
	}
	return out
}

// computeX86OpBitDef computes the exact per-bit definedness of the destination
// value produced by op so bitwise/shift/extend operations on saved RFLAGS/LAHF
// snapshots update only the bits they deterministically define and never forge
// undefined status-flag bits (CF/PF/ZF/SF/OF).
func computeX86OpBitDef(op asm.Op, args []asm.Operand, readBytes, writeBytes int64, srcBitDef, dstBitDef uint64, allInputsInit, allInputsBitDef bool) uint64 {
	if !allInputsInit {
		return 0
	}
	wBitMask := abi0BitMaskN(writeBytes)
	rBitMask := abi0BitMaskN(readBytes)
	switch op {
	case "MOVBWZX", "MOVBLZX", "MOVBQZX", "MOVWLZX", "MOVWQZX", "MOVLQZX", "KMOVB", "KMOVW":
		return (srcBitDef & rBitMask) | (wBitMask &^ rBitMask)
	case "MOVBWSX", "MOVBLSX", "MOVBQSX", "MOVWLSX", "MOVWQSX", "MOVLQSX":
		if readBytes > 0 && readBytes <= 8 {
			signBit := uint64(1) << uint(readBytes*8-1)
			if (srcBitDef & signBit) != 0 {
				return (srcBitDef & rBitMask) | (wBitMask &^ rBitMask)
			}
		}
		return srcBitDef & rBitMask
	case "ANDB", "ANDW", "ANDL", "ANDQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			imm := uint64(args[0].Imm) & wBitMask
			return ((^imm) | dstBitDef) & wBitMask
		}
		return srcBitDef & dstBitDef & wBitMask
	case "ORB", "ORW", "ORL", "ORQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			imm := uint64(args[0].Imm) & wBitMask
			return (imm | dstBitDef) & wBitMask
		}
		return srcBitDef & dstBitDef & wBitMask
	case "XORB", "XORW", "XORL", "XORQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			return dstBitDef & wBitMask
		}
		return srcBitDef & dstBitDef & wBitMask
	case "NOTB", "NOTW", "NOTL", "NOTQ":
		return dstBitDef & wBitMask
	case "SHLB", "SHLW", "SHLL", "SHLQ", "SALB", "SALW", "SALL", "SALQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			if eff, ok := x86ShiftEffectiveImmCount(op, args); ok {
				if eff >= writeBytes*8 {
					return wBitMask
				}
				lowZero := (uint64(1) << uint(eff)) - 1
				return ((dstBitDef << uint(eff)) | lowZero) & wBitMask
			}
		}
	case "SHRB", "SHRW", "SHRL", "SHRQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			if eff, ok := x86ShiftEffectiveImmCount(op, args); ok {
				if eff >= writeBytes*8 {
					return wBitMask
				}
				d := dstBitDef & wBitMask
				hiZero := wBitMask &^ (wBitMask >> uint(eff))
				return ((d >> uint(eff)) | hiZero) & wBitMask
			}
		}
	case "BTSW", "BTSL", "BTSQ", "BTRW", "BTRL", "BTRQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm && writeBytes > 0 && writeBytes <= 8 {
			bit := uint(args[0].Imm) & uint(writeBytes*8-1)
			return (dstBitDef | (uint64(1) << bit)) & wBitMask
		}
	case "BTCW", "BTCL", "BTCQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			return dstBitDef & wBitMask
		}
	}
	if allInputsBitDef {
		return wBitMask
	}
	return 0
}

// computeX86FlagInputsInit determines whether the bits actually observed by an
// instruction's flag update are defined (e.g. TESTQ $0x200, AX only observes
// bit 9 of AX, while TESTQ $1, AX observes entry-undefined CF bit 0).
func computeX86FlagInputsInit(op asm.Op, args []asm.Operand, readBytes, writeBytes int64, arg0BitDef, dstBitDef uint64, allInputsInit, allInputsBitDef bool) bool {
	if !allInputsInit {
		return false
	}
	if allInputsBitDef {
		return true
	}
	switch op {
	case "TESTB", "TESTW", "TESTL", "TESTQ":
		rBitMask := abi0BitMaskN(readBytes)
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			imm := uint64(args[0].Imm) & rBitMask
			return (dstBitDef & imm) == imm
		}
		if len(args) == 2 && args[1].Kind == asm.OpImm {
			imm := uint64(args[1].Imm) & rBitMask
			return (arg0BitDef & imm) == imm
		}
	case "ANDB", "ANDW", "ANDL", "ANDQ":
		wBitMask := abi0BitMaskN(writeBytes)
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			imm := uint64(args[0].Imm) & wBitMask
			return (dstBitDef & imm) == imm
		}
	case "ORB", "ORW", "ORL", "ORQ":
		wBitMask := abi0BitMaskN(writeBytes)
		if len(args) == 2 && args[0].Kind == asm.OpImm {
			imm := uint64(args[0].Imm) & wBitMask
			return ((dstBitDef | imm) & wBitMask) == wBitMask
		}
	case "BTB", "BTW", "BTL", "BTQ",
		"BTSW", "BTSL", "BTSQ", "BTRW", "BTRL", "BTRQ", "BTCW", "BTCL", "BTCQ":
		if len(args) == 2 && args[0].Kind == asm.OpImm && readBytes > 0 && readBytes <= 8 {
			bit := uint(args[0].Imm) & uint(readBytes*8-1)
			return (dstBitDef & (uint64(1) << bit)) != 0
		}
	}
	return false
}

func vecRegFullByteMask(r asm.Reg) uint64 {
	if isAMD64ZReg(r) {
		return ^uint64(0)
	}
	if isAMD64YReg(r) {
		return 0xffffffff
	}
	return 0xffff
}

func vecCopyWidth(r asm.Reg, name string, writeBytes int64) int64 {
	switch name {
	case "MOVSS", "VMOVSS", "MOVD", "VMOVD", "MOVL":
		return 4
	case "MOVSD", "VMOVSD", "MOVQ", "VMOVQ":
		return 8
	}
	if isAMD64ZReg(r) {
		return 64
	}
	if isAMD64YReg(r) {
		return 32
	}
	if writeBytes > 0 && writeBytes <= 64 {
		return writeBytes
	}
	return 16
}

func isPureByteCopyOp(op asm.Op, args []asm.Operand) bool {
	if len(args) != 2 {
		return false
	}
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	switch name {
	case "MOVB", "MOVW", "MOVL", "MOVQ", "MOVD",
		"KMOVD", "KMOVQ",
		"MOVO", "MOVOU", "MOVOA", "MOVUPS", "MOVUPD", "MOVAPS", "MOVAPD",
		"MOVDQU", "MOVDQA", "MOVNTDQ", "MOVNTDQA", "MOVNTPS", "MOVNTPD",
		"MOVSS", "MOVSD",
		"VMOVD", "VMOVQ", "VMOVSS", "VMOVSD",
		"VMOVUPS", "VMOVUPD", "VMOVAPS", "VMOVAPD",
		"VMOVDQU", "VMOVDQA", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64",
		"VMOVDQA32", "VMOVDQA64":
		return true
	case "KMOVB", "KMOVW":
		// Pure byte copy when dst is a K-mask register or memory; k->gp widens
		// with zero-extension via computeX86OpBitDef.
		return args[1].Kind != asm.OpReg || isAMD64KReg(args[1].Reg)
	}
	return false
}

func isX86ClearCFOfOp(op asm.Op) bool {
	switch op {
	case "TESTB", "TESTW", "TESTL", "TESTQ",
		"ANDB", "ANDW", "ANDL", "ANDQ",
		"ORB", "ORW", "ORL", "ORQ",
		"XORB", "XORW", "XORL", "XORQ":
		return true
	}
	return false
}

func isX86GPFlagWriter(op asm.Op) bool {
	switch op {
	case "ADDB", "ADDW", "ADDL", "ADDQ",
		"SUBB", "SUBW", "SUBL", "SUBQ",
		"ADCB", "ADCW", "ADCL", "ADCQ",
		"SBBB", "SBBW", "SBBL", "SBBQ",
		"CMPB", "CMPW", "CMPL", "CMPQ",
		"INCB", "INCW", "INCL", "INCQ",
		"DECB", "DECW", "DECL", "DECQ",
		"NEGB", "NEGW", "NEGL", "NEGQ",
		"MULB", "MULW", "MULL", "MULQ",
		"IMULB", "IMULW", "IMULL", "IMULQ",
		"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHGQ", "CMPXCHG8B", "CMPXCHG16B",
		"XADDB", "XADDW", "XADDL", "XADDQ",
		"BTB", "BTW", "BTL", "BTQ",
		"BTSW", "BTSL", "BTSQ", "BTRW", "BTRL", "BTRQ", "BTCW", "BTCL", "BTCQ",
		"SHLB", "SHLW", "SHLL", "SHLQ", "SALB", "SALW", "SALL", "SALQ",
		"SHRB", "SHRW", "SHRL", "SHRQ", "SARB", "SARW", "SARL", "SARQ",
		"ROLB", "ROLW", "ROLL", "ROLQ", "RORB", "RORW", "RORL", "RORQ",
		"RCLB", "RCLW", "RCLL", "RCLQ", "RCRB", "RCRW", "RCRL", "RCRQ",
		"SHLDW", "SHLDL", "SHLDQ", "SHRDW", "SHRDL", "SHRDQ",
		"ANDNL", "ANDNQ", "BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ",
		"BEXTRL", "BEXTRQ", "BZHIL", "BZHIQ",
		"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ",
		"TZCNTW", "TZCNTL", "TZCNTQ", "LZCNTW", "LZCNTL", "LZCNTQ",
		"POPCNTW", "POPCNTL", "POPCNTQ",
		"CMPSB", "CMPSW", "CMPSL", "CMPSQ", "SCASB", "SCASW", "SCASL", "SCASQ",
		"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM",
		"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM",
		"RDRAND", "RDRANDW", "RDRANDL", "RDRANDQ",
		"RDSEED", "RDSEEDW", "RDSEEDL", "RDSEEDQ",
		"KORTESTB", "KORTESTW", "KORTESTD", "KORTESTQ",
		"KTESTB", "KTESTW", "KTESTD", "KTESTQ",
		"COMISS", "COMISD", "UCOMISS", "UCOMISD", "PTEST",
		"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD", "VPTEST", "VTESTPS", "VTESTPD",
		"FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP",
		"SAHF", "POPFL", "POPFQ", "POPFW", "CMC":
		return true
	}
	return false
}

func isX86FlagCondJumpOp(op asm.Op) bool {
	if !isX86CondJumpOp(op) {
		return false
	}
	switch op {
	case "JCXZ", "JECXZ", "JRCXZ", "LOOP", "LOOPEQ", "LOOPNE":
		return false
	default:
		return true
	}
}

// x86ShiftEffectiveImmCount computes the architectural masked shift/rotate
// count for an immediate or implicit-1 shift/rotate instruction. ok is false
// when the count is dynamic (e.g., in CL).
func x86ShiftEffectiveImmCount(op asm.Op, args []asm.Operand) (eff int64, ok bool) {
	if len(args) == 1 {
		// One-operand Plan 9 shift/rotate forms use an implicit count of 1.
		return 1, true
	}
	if len(args) < 2 || args[0].Kind != asm.OpImm {
		return 0, false
	}
	mask := int64(0x1f)
	if strings.HasSuffix(string(op), "Q") {
		mask = 0x3f
	}
	eff = args[0].Imm & mask
	switch op {
	case "RCLB", "RCRB":
		eff %= 9
	case "RCLW", "RCRW":
		eff %= 17
	}
	return eff, true
}

func updateX86FlagsAfter(st *abi0State, op asm.Op, args []asm.Operand, allInputsInit bool) {
	if isX86ClearCFOfOp(op) {
		// Intel SDM: TEST/AND/OR/XOR unconditionally clear CF=0 and OF=0,
		// set ZF/SF/PF from result, and leave AF undefined.
		st.cfInit = true
		st.ofInit = true
		st.afInit = false
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
		return
	}
	switch op {
	case "SYSCALL":
		// On Darwin/BSD amd64, SYSCALL returns error status in CF (tested via JCC).
		st.cfInit = true
		return
	case "ADCXL", "ADCXQ":
		// ADCX updates CF only; OF/AF/ZF/SF/PF are preserved.
		st.cfInit = allInputsInit
		return
	case "ADOXL", "ADOXQ":
		// ADOX updates OF only; CF/AF/ZF/SF/PF are preserved.
		st.ofInit = allInputsInit
		return
	case "INCB", "INCW", "INCL", "INCQ", "DECB", "DECW", "DECL", "DECQ":
		// INC/DEC preserve CF and update OF/AF/ZF/SF/PF.
		st.ofInit = allInputsInit
		st.afInit = allInputsInit
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
		return
	case "CMPXCHG8B", "CMPXCHG16B":
		// Intel SDM: CMPXCHG8B/16B modify ZF only.
		st.zfInit = allInputsInit
		return
	case "BTB", "BTW", "BTL", "BTQ",
		"BTSW", "BTSL", "BTSQ", "BTRW", "BTRL", "BTRQ", "BTCW", "BTCL", "BTCQ":
		// Intel SDM: BT/BTS/BTR/BTC set CF from bit, preserve ZF, and leave OF/SF/AF/PF undefined.
		st.cfInit = allInputsInit
		st.ofInit = false
		st.afInit = false
		st.sfInit = false
		st.pfInit = false
		return
	case "SHLB", "SHLW", "SHLL", "SHLQ", "SALB", "SALW", "SALL", "SALQ",
		"SHRB", "SHRW", "SHRL", "SHRQ", "SARB", "SARW", "SARL", "SARQ",
		"SHLDW", "SHLDL", "SHLDQ", "SHRDW", "SHRDL", "SHRDQ":
		if eff, isImm := x86ShiftEffectiveImmCount(op, args); isImm {
			if eff == 0 {
				// Intel SDM: effective shift count 0 leaves all flags unaffected.
				return
			}
			isDouble16 := (op == "SHLDW" || op == "SHRDW") || ((op == "SHLW" || op == "SHRW") && len(args) == 3)
			if isDouble16 && eff > 16 {
				// Intel SDM: 16-bit SHLD/SHRD with effective count > 16 leaves result and flags undefined.
				st.cfInit = false
				st.ofInit = false
				st.afInit = false
				st.zfInit = false
				st.sfInit = false
				st.pfInit = false
				return
			}
			st.cfInit = allInputsInit
			st.ofInit = allInputsInit && eff == 1
			st.afInit = false
			st.zfInit = allInputsInit
			st.sfInit = allInputsInit
			st.pfInit = allInputsInit
			return
		}
		// Dynamic CL count may be 0 (preserving flags) or >1 (leaving OF/AF undefined).
		st.cfInit = st.cfInit && allInputsInit
		st.ofInit = false
		st.afInit = false
		st.zfInit = st.zfInit && allInputsInit
		st.sfInit = st.sfInit && allInputsInit
		st.pfInit = st.pfInit && allInputsInit
		return
	case "ROLB", "ROLW", "ROLL", "ROLQ", "RORB", "RORW", "RORL", "RORQ",
		"RCLB", "RCLW", "RCLL", "RCLQ", "RCRB", "RCRW", "RCRL", "RCRQ":
		if eff, isImm := x86ShiftEffectiveImmCount(op, args); isImm {
			if eff == 0 {
				// Intel SDM: effective rotate count 0 leaves all flags unaffected.
				return
			}
			// Rotates update CF (and OF only for effective count 1); AF/ZF/SF/PF are preserved.
			st.cfInit = allInputsInit
			st.ofInit = allInputsInit && eff == 1
			return
		}
		st.cfInit = st.cfInit && allInputsInit
		st.ofInit = false
		return
	case "MULB", "MULW", "MULL", "MULQ", "IMULB", "IMULW", "IMULL", "IMULQ":
		st.cfInit = allInputsInit
		st.ofInit = allInputsInit
		st.afInit = false
		st.zfInit = false
		st.sfInit = false
		st.pfInit = false
		return
	case "BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ":
		st.cfInit = false
		st.ofInit = false
		st.afInit = false
		st.zfInit = allInputsInit
		st.sfInit = false
		st.pfInit = false
		return
	case "TZCNTW", "TZCNTL", "TZCNTQ", "LZCNTW", "LZCNTL", "LZCNTQ":
		st.cfInit = allInputsInit
		st.ofInit = false
		st.afInit = false
		st.zfInit = allInputsInit
		st.sfInit = false
		st.pfInit = false
		return
	case "POPCNTW", "POPCNTL", "POPCNTQ":
		// Intel SDM: POPCNT sets ZF from source==0 and clears OF/SF/AF/CF/PF to 0.
		st.cfInit = true
		st.ofInit = true
		st.afInit = true
		st.zfInit = allInputsInit
		st.sfInit = true
		st.pfInit = true
		return
	case "ANDNL", "ANDNQ", "BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ", "BZHIL", "BZHIQ":
		st.cfInit = allInputsInit
		st.ofInit = true
		st.afInit = false
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = false
		return
	case "BEXTRL", "BEXTRQ":
		st.cfInit = true
		st.ofInit = true
		st.afInit = false
		st.zfInit = allInputsInit
		st.sfInit = false
		st.pfInit = false
		return
	case "RDRAND", "RDRANDW", "RDRANDL", "RDRANDQ",
		"RDSEED", "RDSEEDW", "RDSEEDL", "RDSEEDQ",
		"XTEST":
		st.cfInit = true
		st.ofInit = true
		st.afInit = true
		st.zfInit = true
		st.sfInit = true
		st.pfInit = true
		return
	case "COMISS", "COMISD", "UCOMISS", "UCOMISD",
		"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD",
		"FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP":
		// Intel SDM: sets ZF/PF/CF from comparison and clears OF/SF/AF to 0.
		st.cfInit = allInputsInit
		st.ofInit = true
		st.afInit = true
		st.zfInit = allInputsInit
		st.sfInit = true
		st.pfInit = allInputsInit
		return
	case "PTEST", "VPTEST", "VTESTPS", "VTESTPD",
		"KORTESTB", "KORTESTW", "KORTESTD", "KORTESTQ",
		"KTESTB", "KTESTW", "KTESTD", "KTESTQ":
		// Intel SDM: sets ZF/CF and clears OF/SF/AF/PF to 0.
		st.cfInit = allInputsInit
		st.ofInit = true
		st.afInit = true
		st.zfInit = allInputsInit
		st.sfInit = true
		st.pfInit = true
		return
	case "SAHF":
		// SAHF loads SF/ZF/AF/PF/CF from AH (byte 1 of AX); OF is preserved.
		// Always derive exact flag definedness from the per-bit definedness of AH
		// so partial writes to AL or LAHF; SAHF never forge undefined entry flags.
		ah := uint8(st.gpBitDef[asm.AX] >> 8)
		st.cfInit = (ah & 0x01) != 0
		st.pfInit = (ah & 0x04) != 0
		st.afInit = (ah & 0x10) != 0
		st.zfInit = (ah & 0x40) != 0
		st.sfInit = (ah & 0x80) != 0
		return
	}
	if isX86GPFlagWriter(op) {
		st.cfInit = allInputsInit
		st.ofInit = allInputsInit
		st.afInit = allInputsInit
		st.zfInit = allInputsInit
		st.sfInit = allInputsInit
		st.pfInit = allInputsInit
	}
}

func x86CondSuffix(op asm.Op) (string, bool) {
	s := string(op)
	if strings.HasPrefix(s, "SET") && len(s) > 3 {
		return s[3:], true
	}
	for _, pfx := range []string{"CMOVW", "CMOVL", "CMOVQ"} {
		if strings.HasPrefix(s, pfx) && len(s) > len(pfx) {
			return s[len(pfx):], true
		}
	}
	if strings.HasPrefix(s, "J") && len(s) > 1 &&
		op != "JMP" && op != "JCXZ" && op != "JECXZ" && op != "JRCXZ" && isX86CondJumpOp(op) {
		return s[1:], true
	}
	return "", false
}

// x86CondRequiredFlags returns the exact set of architectural status flags
// consumed by a condition-code suffix (shared across Jcc, SETcc, and CMOVcc).
func x86CondRequiredFlags(cc string) (needCF, needOF, needZF, needSF, needPF bool) {
	switch cc {
	case "E", "EQ", "Z", "NE", "NZ":
		return false, false, true, false, false
	case "S", "NS", "MI", "PL":
		return false, false, false, true, false
	case "P", "PE", "NP", "PO", "PS", "PC":
		return false, false, false, false, true
	case "C", "NC", "CS", "CC", "B", "NB", "AE", "NAE", "LO", "HS":
		return true, false, false, false, false
	case "O", "NO", "OS", "OC":
		return false, true, false, false, false
	case "BE", "NA", "A", "NBE", "LS", "HI":
		return true, false, true, false, false
	case "L", "LT", "GE", "NGE", "NL":
		return false, true, false, true, false
	case "LE", "G", "GT", "NG", "NLE":
		return false, true, true, true, false
	default:
		return false, false, false, false, false
	}
}

// missingCondFlag checks whether any status flag required by a conditional
// instruction (Jcc, SETcc, or CMOVcc) is uninitialized in st.
func missingCondFlag(st *abi0State, op asm.Op) string {
	cc, ok := x86CondSuffix(op)
	if !ok {
		return ""
	}
	needCF, needOF, needZF, needSF, needPF := x86CondRequiredFlags(cc)
	if needCF && !st.cfInit {
		return "CF"
	}
	if needOF && !st.ofInit {
		return "OF"
	}
	if needZF && !st.zfInit {
		return "ZF"
	}
	if needSF && !st.sfInit {
		return "SF"
	}
	if needPF && !st.pfInit {
		return "PF"
	}
	return ""
}

func needsNonCondCF(op asm.Op, args []asm.Operand) bool {
	switch op {
	case "ADCB", "ADCW", "ADCL", "ADCQ",
		"SBBB", "SBBW", "SBBL", "SBBQ",
		"ADCXL", "ADCXQ":
		return true
	case "RCLB", "RCLW", "RCLL", "RCLQ",
		"RCRB", "RCRW", "RCRL", "RCRQ":
		if eff, isImm := x86ShiftEffectiveImmCount(op, args); isImm && eff == 0 {
			return false
		}
		return true
	}
	return false
}
