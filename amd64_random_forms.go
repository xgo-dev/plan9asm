package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type x86HardwareRandomSpec struct {
	native string
	bits   int
}

// All six Go yrdrand rows: one Yrl write, no input operand or suffix.
var x86HardwareRandomSpecs = map[Op]x86HardwareRandomSpec{
	"RDRANDW": {"rdrand", 16}, "RDRANDL": {"rdrand", 32}, "RDRANDQ": {"rdrand", 64},
	"RDSEEDW": {"rdseed", 16}, "RDSEEDL": {"rdseed", 32}, "RDSEEDQ": {"rdseed", 64},
}

func x86HardwareRandomProperties(op Op, ins Instr, arch string) (x86HardwareRandomSpec, bool, error) {
	name := strings.ToUpper(string(op))
	if !strings.HasPrefix(name, "RDRAND") && !strings.HasPrefix(name, "RDSEED") {
		return x86HardwareRandomSpec{}, false, nil
	}
	spec, valid := x86HardwareRandomSpecs[Op(name)]
	if !valid || arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) || len(ins.Args) != 1 ||
		!reflect.DeepEqual(ins.Args[0], Operand{Kind: OpReg, Reg: ins.Args[0].Reg}) ||
		!isX86YrlRegisterForArch(ins.Args[0].Reg, arch) {
		return spec, true, fmt.Errorf("%s %s requires the exact Go W/L/Q hardware-random register form: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

// The instruction writes a machine value and CF availability status. NUM is
// not a successful entropy result or a claim that CF=0 has the same value on
// every vendor. No old destination bytes within the write width are inputs.
func x86TypedHardwareRandomByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86HardwareRandomProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if !x86HardwareRandomPreservesSourceState(ins) {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: hardware-random original/normalized source identity differs", ErrProbeNeedsContext)
	}
	return x86TypedByteEffect{
		operands:     []x86TypedByteOperand{{index: 0, operand: ins.Args[0], width: int64(spec.bits / 8), write: true}},
		flagsDefined: x86ByteFlagsAll, flagsKilled: x86ByteFlagsAll, requiresResultProof: true,
	}, true, nil
}

func x86HardwareRandomPreservesSourceState(ins Instr) bool {
	if _, known, err := x86HardwareRandomProperties(ins.Op, ins, "amd64"); !known || err != nil ||
		ins.x86Encoded || ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	return origin == nil || strings.EqualFold(string(origin.op), string(ins.Op)) && reflect.DeepEqual(origin.args, ins.Args)
}
