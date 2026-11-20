package plan9asm

import "reflect"

// A live numerical certificate is metadata on its exact original instruction,
// not a change to Go's AUTO spelling. Only that authenticated metadata may be
// projected away for source replay; raw/native/literal roles remain unchanged.
// This observation creates neither numerical bytes nor a physical frame.
func x86ResultAUTOReplayInstructions(fn Func, arch string) ([]Instr, error) {
	var binding *GoX86NumericalReadBinding
	for _, ins := range fn.Instrs {
		if cert := ins.x86NumericalRead; cert != nil {
			if cert.binding == nil || binding != nil && binding != cert.binding {
				return nil, numericalSBContext("AUTO replay has missing or mixed original numerical bindings")
			}
			binding = cert.binding
		}
	}
	if binding == nil {
		return fn.Instrs, nil // Retain the exact ordinary source comparison.
	}
	if err := binding.verify(); err != nil {
		return nil, err
	}
	if arch != binding.options.Goarch || binding.source.file == nil {
		return nil, numericalSBContext("AUTO replay differs from the live numerical source mode")
	}
	instructions := append([]Instr(nil), fn.Instrs...)
	for ordinal, ins := range instructions {
		if ins.x86NumericalRead == nil {
			continue
		}
		read, _, valid := numericalCertifiedRead(ins, arch)
		ins.x86NumericalRead = nil
		if !valid || read.Instruction != ordinal || read.Function != binding.symbols[fn.Sym] ||
			!reflect.DeepEqual(ins, read.Original) {
			return nil, numericalSBContext("AUTO replay changed the actual original numerical instruction/ordinal")
		}
		instructions[ordinal] = ins
	}
	matches := 0
	for _, original := range binding.source.file.Funcs {
		if original.Sym != fn.Sym {
			continue
		}
		if original.FrameSize != fn.FrameSize || original.ArgSize != fn.ArgSize ||
			!reflect.DeepEqual(original.Instrs, instructions) {
			return nil, numericalSBContext("AUTO replay changed the complete actual numerical source TEXT")
		}
		matches++
	}
	if matches != 1 {
		return nil, numericalSBContext("AUTO replay has no unique actual numerical source TEXT")
	}
	return instructions, nil
}
