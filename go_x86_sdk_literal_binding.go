package plan9asm

import (
	"reflect"
	"strings"
)

type x86SDKLiteralCertificate struct {
	binding     *GoX86NumericalReadBinding
	access      int
	instruction [32]byte
}

func (source *GoX86NumericalReadSource) bindSDKLiteralAccesses(file *File, sigs map[string]FuncSig, symbols map[string]string, arch string) ([]x86SDKLiteralAccess, error) {
	return source.bindSDKLiteralAccessesAtMinimum(file, sigs, symbols, arch, nil)
}

func (source *GoX86NumericalReadSource) bindSDKLiteralAccessesAtMinimum(file *File, sigs map[string]FuncSig, symbols map[string]string, arch string, minimum *numericalSDKLiteralMinimumJoin) ([]x86SDKLiteralAccess, error) {
	if source.literals == nil {
		return nil, nil
	}
	literals := make(map[string]int64)
	for _, global := range file.Globl {
		literals[global.Sym] = global.Size
	}
	var result []x86SDKLiteralAccess
	for _, fn := range file.Funcs {
		candidate := false
		for _, ins := range fn.Instrs {
			for index := range ins.Args {
				if form, valid := x86SDKLiteralOperandProperties(ins, index, arch); valid && literals[form.symbol] > 0 &&
					(form.address || form.memory.Index != "") {
					candidate = true
				}
			}
		}
		if !candidate {
			continue // Existing fixed-offset consumers retain their own byte proof.
		}
		var floors map[string]uint32
		if minimum != nil {
			floors = minimum.Minima
		}
		facts, err := proveX86SDKLiteralAccessesWithMinima(fn, sigs[symbols[fn.Sym]], arch, literals, floors)
		if err != nil {
			return nil, err
		}
		result = append(result, facts...)
	}
	return result, nil
}

func joinSDKLiteralCertificates(file *File, binding *GoX86NumericalReadBinding) error {
	for index, fact := range binding.literalAccesses {
		matches := 0
		for f := range file.Funcs {
			fn := &file.Funcs[f]
			if binding.resolve(fn.Sym) != fact.Function || fact.Instruction < 0 || fact.Instruction >= len(fn.Instrs) {
				continue
			}
			ins := &fn.Instrs[fact.Instruction]
			if !reflect.DeepEqual(*ins, fact.Original) || ins.x86SDKLiteral != nil {
				return numericalSBContext("original private literal access/ordinal differs")
			}
			digest, err := fixedLocalInstructionDigest(*ins)
			if err != nil {
				return err
			}
			ins.x86SDKLiteral = &x86SDKLiteralCertificate{binding: binding, access: index, instruction: digest}
			matches++
		}
		if matches != 1 {
			return numericalSBContext("private literal access lacks its unique complete source function")
		}
	}
	return nil
}

func certifiedSDKLiteralAccess(ins Instr, arch string) (x86SDKLiteralAccess, bool) {
	cert := ins.x86SDKLiteral
	if cert == nil || cert.binding == nil || cert.binding.originalBinding != cert.binding ||
		cert.binding.source == nil || cert.binding.source.identity != cert.binding.source ||
		cert.binding.source.revoked.Load() ||
		cert.binding.source.role != numericalSBSDKSource || cert.binding.source.literals == nil ||
		arch != cert.binding.options.Goarch || cert.access < 0 || cert.access >= len(cert.binding.literalAccesses) {
		return x86SDKLiteralAccess{}, false
	}
	fact := cert.binding.literalAccesses[cert.access]
	joined := cert.binding.source.literals
	if joined.owner == nil || joined.owner.identity != joined.owner || joined.source == nil || joined.source.identity != joined.source {
		return x86SDKLiteralAccess{}, false
	}
	digest, err := fixedLocalInstructionDigest(ins)
	if err != nil || digest != cert.instruction || fact.Operand < 0 || fact.Operand >= len(ins.Args) || fact.Minimum < 0 || fact.Maximum < fact.Minimum {
		return x86SDKLiteralAccess{}, false
	}
	name := numericalNativeName(strings.TrimSuffix(fact.Symbol, "<>"), cert.binding.source.request.PackagePath)
	extent := int64(-1)
	for _, image := range joined.Initializers.Initializers {
		if image.SourceOrdinal == joined.SourceOrdinal && image.Definition.Name == name {
			if extent >= 0 {
				return x86SDKLiteralAccess{}, false
			}
			extent = int64(len(image.Initial))
		}
	}
	if extent < 0 || fact.Width < 0 || fact.LowBits == nil && (fact.Width > extent || fact.Maximum > extent-fact.Width) {
		return x86SDKLiteralAccess{}, false
	}
	if fact.LowBits != nil {
		if !cert.binding.literalMinimum.live() || fact.LowBits.Symbol != fact.Symbol ||
			fact.Width != fact.LowBits.Bytes || fact.LowBits.Operation != ins.Op || !validSDKLiteralLowBitForm(ins, fact.LowBits, arch) {
			return x86SDKLiteralAccess{}, false
		}
	} else if fact.Address {
		form, valid := x86SDKLiteralOperandProperties(ins, fact.Operand, arch)
		if !valid || !form.address || form.symbol != fact.Symbol || fact.Width != 0 {
			return x86SDKLiteralAccess{}, false
		}
	} else {
		width, write, valid := x86InstructionMemoryShape(x86SourceMoveInstruction(ins, arch), fact.Operand, arch)
		if !valid || write || width != fact.Width || width <= 0 {
			return x86SDKLiteralAccess{}, false
		}
	}
	return fact, true
}

func verifyNormalizedSDKLiteralAccesses(file *File, options Options) error {
	binding := options.NumericalReads
	seen := make(map[int]bool)
	for _, fn := range file.Funcs {
		for ordinal, ins := range fn.Instrs {
			if ins.x86SDKLiteral == nil {
				continue
			}
			cert := ins.x86SDKLiteral
			fact, valid := certifiedSDKLiteralAccess(ins, options.Goarch)
			if !valid || cert.binding != binding || seen[cert.access] || options.ResolveSym(fn.Sym) != fact.Function || ordinal != fact.Instruction {
				return numericalSBContext("normalized private literal function/ordinal/operand differs")
			}
			seen[cert.access] = true
		}
	}
	if len(seen) != len(binding.literalAccesses) {
		return numericalSBContext("normalized private literal access inventory differs")
	}
	return nil
}

func x86ResultSDKLiteralStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if ins.x86SDKLiteral == nil {
		return false, false
	}
	fact, valid := certifiedSDKLiteralAccess(ins, arch)
	if !valid {
		return false, true
	}
	if fact.LowBits != nil {
		return x86ResultSDKLiteralLowBitStep(ins, fact.LowBits, state, arch), true
	}
	if fact.Address {
		root, _, valid := x86ResultGP(ins.Args[1].Reg, x86ResultPointerWord(arch), arch)
		if valid {
			state.gp[root], state.pointerGP[root] = 0, true // Opaque address, not numerical bits.
		}
		return valid, true
	}
	next := state.clone()
	next.loweredStaticReads = state.loweredStaticReads
	next.literalMemoryOperand, next.literalMemoryBytes = &ins.Args[fact.Operand], fact.Width
	ins.x86SDKLiteral = nil
	accepted := x86ScalarFPResultTransfer(x86SourceMoveInstruction(ins, arch), &next, owned, resultOffset, arch)
	next.literalMemoryOperand, next.literalMemoryBytes = nil, 0
	if accepted {
		*state = next
	}
	return accepted, true
}
