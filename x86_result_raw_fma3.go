package plan9asm

import "reflect"

// Physical generation is independent of the named spelling, encoded grammar
// extensions and FP16's MAP6 owner. Zero cannot assert an original VEX form.
type x86RawFMA3Encoding uint8

const (
	x86RawFMA3Absent x86RawFMA3Encoding = iota
	x86RawFMA3VEX
	x86RawFMA3EVEX
)

type x86RawFMA3Identity struct {
	arch     string
	encoding x86RawFMA3Encoding
	encoded  bool
}

func x86FMA3RawIdentity(ins Instr, arch string) x86RawFMA3Identity {
	form, known, err := amd64FMA3Properties(ins, arch)
	if !known || err != nil || form.spec.rawOnly ||
		ins.x86FMA3Encoding != x86RawFMA3VEX && ins.x86FMA3Encoding != x86RawFMA3EVEX {
		return x86RawFMA3Identity{}
	}
	return x86RawFMA3Identity{arch, ins.x86FMA3Encoding, ins.x86Encoded}
}

func x86RawFMA3EncodingSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	identity := x86FMA3RawIdentity(ins, arch)
	return origin != nil && identity.encoding != x86RawFMA3Absent && identity.arch == arch && origin.fma3 == identity &&
		origin.op == ins.Op && origin.vectorBytes == ins.x86VectorBytes &&
		origin.addressBits == ins.x86AddressBits &&
		(reflect.DeepEqual(origin.args, ins.Args) || x86RawLiteralSourceIdentity(ins, arch))
}

func x86RawFMA3Source(ins Instr, arch string) bool {
	return x86RawFMA3EncodingSource(ins, arch) && x86RawOrdinaryVectorSource(ins, arch)
}

// The DATA image and canonical raw RET keep their independent existing owner.
// An exact FMA encoding cannot substitute an arbitrary symbolic native read.
func x86RawFMA3LiteralForm(ins Instr, arch string) bool {
	if !x86RawFMA3EncodingSource(ins, arch) || !x86RawLiteralSourceIdentity(ins, arch) {
		return false
	}
	form, known, err := amd64FMA3Properties(ins, arch)
	return known && err == nil && !form.spec.rawOnly && form.memory == 0 &&
		ins.x86RIPMemoryRead.source == 0 && ins.x86RIPMemoryRead.width == int64(form.memoryBytes)
}

// An authenticated FMA changes its vector destination and MXCSR, not DF, ID
// or private FLAGS storage. Preserving those independent facts supplies no
// arithmetic inputs, memory backing, entry authority or inert-data predicate.
func x86FMA3PreservesPrivateSourceState(ins Instr, arch string) bool {
	return x86RawFMA3Source(ins, arch) || x86RawFMA3LiteralForm(ins, arch)
}

// A restriction selected from immutable original instructions precedes strict
// NUM success too. Removing a mutable origin cannot erase its replay duty.
func x86FMA3RawReplayRequired(fn Func, arch string) bool {
	hasProducer := func(instructions []Instr) bool {
		for _, ins := range instructions {
			form, known, _ := amd64FMA3Properties(ins, arch)
			if known && !form.spec.rawOnly && (ins.x86SourceRaw != nil || ins.x86FMA3Encoding != x86RawFMA3Absent) {
				return true
			}
		}
		return false
	}
	return hasProducer(fn.Instrs) || fn.x86RawReplay != nil && hasProducer(fn.x86RawReplay.decoded)
}
