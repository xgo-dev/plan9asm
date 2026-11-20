package plan9asm

// GoAMD64FixedLocalFrameBindingNeeded is a source-role query, not a frame or
// memory certificate. The complete actual-object factory and fixed-local
// proof must independently succeed before any instruction gains backing.
// One optional typed declaration set keeps complete ABI0 forwarding adapters
// on their existing call route. Missing or ambiguous options retain the query's
// original conservative behavior and grant no source or translation permission.
func GoAMD64FixedLocalFrameBindingNeeded(file *File, goarch string, options ...Options) bool {
	if file == nil || file.Arch != ArchAMD64 || goarch != "amd64" {
		return false
	}
	for _, fn := range file.Funcs {
		if fn.FrameSize <= 0 {
			continue
		}
		if len(options) == 1 && x86ABI0OutgoingForwarder(fn, options[0]) {
			continue
		}
		bases := fixedLocalCandidateBases(fn)
		for _, ins := range fn.Instrs {
			// The final candidate role requires possible physical-frame memory. Avoid
			// parsing allocating effects for register-only or unrelated inputs;
			// this negative filter grants neither grammar nor storage permission.
			localMemory := false
			for _, operand := range ins.Args {
				if operand.Kind == OpMem && bases.has(operand.Mem) {
					localMemory = true
					break
				}
			}
			if !localMemory {
				continue
			}
			memory, eligible := -1, false
			physicalOnly := false
			if _, _, known, err := x86SwapProperties(ins, goarch); known {
				eligible, physicalOnly = err == nil, true
				for index, operand := range ins.Args {
					if operand.Kind == OpMem {
						memory = index
					}
				}
			} else if _, known, err := x86ScalarRegisterLoadProperties(ins.Op, ins, goarch); known {
				memory, eligible, physicalOnly = 0, err == nil, true
			} else if _, known, err := x86ScalarRegisterStoreProperties(ins.Op, ins, goarch); known {
				memory, eligible, physicalOnly = 1, err == nil, true
			} else if form, known, err := fixedLocalConversionProperties(ins); known {
				memory, eligible = form.memory, err == nil && !form.mmx
			} else if form, known, err := fixedLocalScalarLaneProperties(ins); known {
				memory, eligible = form.memory, err == nil
			} else if form, known, err := amd64PackedVectorMoveProperties(ins, goarch); known {
				memory, eligible = form.memory, err == nil && !form.undefinedOpcode()
				physicalOnly = !form.spec.aligned
			} else if form, known, err := x86NonTemporalVectorProperties(ins.Op, ins, goarch); known {
				memory, eligible = form.move.memory, err == nil && !form.trap
			} else if form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, goarch); known {
				memory, eligible = form.memory, err == nil
				physicalOnly = !form.aligned
			} else if form, known, err := x86SHAProperties(ins.Op, ins, goarch); known {
				memory, eligible = form.memory, err == nil
			} else if form, known, err := x86AESProperties(ins.Op, ins, goarch); known {
				memory, eligible = form.memory, err == nil && form.byteWidth == 16
			} else if effect, known, err := fixedLocalVectorByteEffect(ins); known {
				eligible = err == nil
				for _, operand := range effect.operands {
					if operand.operand.Kind == OpMem {
						memory = operand.index
					}
				}
			} else if form, known, err := x86FloatCompareProperties(ins, goarch); known {
				memory, eligible = form.memory, err == nil && form.legacy && !form.scalar && form.byteWidth == 16
			} else if form, known, err := x86ConditionalMoveProperties(ins.Op, ins, goarch); known {
				memory, eligible = 0, err == nil && form.source.Kind == OpMem
			} else if effect, known, err := fixedLocalGPByteEffect(ins); known {
				eligible, physicalOnly = err == nil && !effect.dynamicMemory, true
				for _, operand := range effect.operands {
					if operand.operand.Kind == OpMem && (operand.read || operand.write) {
						memory = operand.index
					}
				}
			}
			if eligible && memory >= 0 && memory < len(ins.Args) {
				source := ins.Args[memory]
				// Static SB and incoming native GP addresses keep their existing
				// contracts. Virtual FP is not original local native storage.
				if source.Kind == OpMem && bases.has(source.Mem) {
					if physicalOnly {
						// Scalar and unaligned transport can use logical AUTO. Only
						// physical SP/BP needs this additional source observer; the
						// existing parser retains the distinct named displacement.
						address, err := fixedLocalMemoryAddress(ins, memory, fn.FrameSize)
						if err != nil || address != source.Mem {
							continue
						}
					}
					return true
				}
			}
		}
	}
	return false
}

type fixedLocalCandidateBaseSet uint16

func fixedLocalCandidateRegister(reg Reg) (int, bool) {
	if reg == SP {
		return 4, true
	}
	if reg == BP {
		return 5, true
	}
	index, _, valid := x86ResultGP(reg, 8, "amd64")
	return index, valid
}

func (bases fixedLocalCandidateBaseSet) has(memory MemRef) bool {
	for _, reg := range []Reg{memory.Base, memory.Index} {
		if index, valid := fixedLocalCandidateRegister(reg); valid && bases&(1<<uint(index)) != 0 {
			return true
		}
	}
	return false
}

// This small syntactic closure only selects the independent frame observer.
// It is deliberately insensitive to CFG order and overwrites: reaching values,
// bounds and every actual access must still pass the complete frame proof.
func fixedLocalCandidateBases(fn Func) fixedLocalCandidateBaseSet {
	var dependencies [16]fixedLocalCandidateBaseSet
	for _, ins := range fn.Instrs {
		if form, width, known, err := x86SwapProperties(ins, "amd64"); known {
			if err == nil && width == 8 && form.other.Kind == OpReg {
				first, firstValid := fixedLocalCandidateRegister(form.register.Reg)
				last, lastValid := fixedLocalCandidateRegister(form.other.Reg)
				if firstValid && lastValid {
					dependencies[first] |= 1 << uint(last)
					dependencies[last] |= 1 << uint(first)
				}
			}
			continue
		}
		op := x86SourceMoveInstruction(ins, "amd64").Op
		if op != "MOVQ" && op != "LEAQ" {
			continue
		}
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			continue
		}
		destination, valid := fixedLocalCandidateRegister(ins.Args[1].Reg)
		if !valid {
			continue
		}
		var sources [2]Reg
		if op == "MOVQ" && ins.Args[0].Kind == OpReg {
			sources[0] = ins.Args[0].Reg
		} else if ins.Op == "LEAQ" && ins.Args[0].Kind == OpMem {
			width, err := x86LEAOperandWidth(ins, "amd64")
			address, addressErr := fixedLocalMemoryAddress(ins, 0, fn.FrameSize)
			if err != nil || width != 8 || addressErr != nil || address != ins.Args[0].Mem {
				continue
			}
			sources = [2]Reg{address.Base, address.Index}
		}
		for _, reg := range sources {
			if source, valid := fixedLocalCandidateRegister(reg); valid {
				dependencies[destination] |= 1 << uint(source)
			}
		}
	}
	bases := fixedLocalCandidateBaseSet(1<<4 | 1<<5)
	for {
		previous := bases
		for destination, sources := range dependencies {
			if sources&bases != 0 {
				bases |= 1 << uint(destination)
			}
		}
		if bases == previous {
			return bases
		}
	}
}
