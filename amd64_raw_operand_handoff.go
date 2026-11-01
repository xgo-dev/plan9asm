package plan9asm

import (
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// parseDecodedX86PhysicalInstruction is the private decoder handoff, not a Go
// source grammar extension. GoSyntax orders operands and selects the audited
// mnemonic; the actual decoder Mem supplies the physical address. In
// particular, FS:..., default DS/ES, and RIP are not source register groups.
// Prefix, PC-relative layout, and address-size admission remain the caller's
// independent checks. No memory/caller/frame certificate is manufactured here.
func parseDecodedX86PhysicalInstruction(inst x86asm.Inst, syntax string) ([]Instr, error) {
	physical := normalizeDecodedX86LEASegments(normalizeDecodedX86MemoryDisplacements(inst))
	const marker = "__plan9asm_decoded_memory_"
	if strings.Contains(syntax, marker) {
		return nil, fmt.Errorf("decoded syntax collides with private memory placeholder")
	}
	type memoryBinding struct {
		name    string
		operand Operand
	}
	bindings := make(map[string]memoryBinding)
	byName := make(map[string]Operand)
	memoryCount := 0
	for _, arg := range physical.Args {
		memory, ok := arg.(x86asm.Mem)
		if !ok {
			continue
		}
		operand, err := decodedX86PhysicalMemory(memory)
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("%s%d", marker, memoryCount)
		memoryCount++
		byName[name] = operand
		// Use the same pinned formatter only to locate this complete operand
		// token. Never interpret its text as a public memory/address role.
		probe := physical
		probe.Op = x86asm.NOP
		probe.Prefix = x86asm.Prefixes{}
		probe.Args = x86asm.Args{memory}
		text := x86asm.GoSyntax(probe, 0, nil)
		space := strings.IndexByte(text, ' ')
		if space < 0 {
			return nil, fmt.Errorf("decoder formatter omitted its physical memory operand")
		}
		text = text[space+1:]
		spellings := []string{text, strings.TrimPrefix(normalizeDecodedX86SegmentMemorySyntax("NOP "+text), "NOP ")}
		for _, spelling := range spellings {
			if prior, exists := bindings[spelling]; exists && prior.operand.Mem != operand.Mem {
				return nil, fmt.Errorf("ambiguous decoded physical memory %q", spelling)
			}
			bindings[spelling] = memoryBinding{name: name, operand: operand}
		}
	}
	for _, prefix := range physical.Prefix {
		if memoryCount == 0 || prefix&(x86asm.PrefixIgnored|x86asm.PrefixImplicit) != 0 {
			continue
		}
		switch prefix & 0xff {
		case x86asm.PrefixES, x86asm.PrefixCS, x86asm.PrefixSS, x86asm.PrefixDS, x86asm.PrefixFS, x86asm.PrefixGS:
			bound := false
			for _, argument := range physical.Args {
				if memory, ok := argument.(x86asm.Mem); ok && memory.Segment.String() == prefix.String() {
					bound = true
				}
			}
			if !bound {
				// A later operand-size prefix can hide this unused segment
				// in GoSyntax. Absence from text is not an ignored witness.
				return nil, fmt.Errorf("%w: raw %s has an unbound physical %s segment prefix", ErrProbeNeedsContext, inst.Op, prefix)
			}
		}
	}

	parts := strings.Split(syntax, ";")
	consumed := 0
	for i, part := range parts {
		part = strings.TrimSpace(part)
		// GoSyntax prints an architecturally ignored segment before the
		// opcode (for example FS SCASB). Drop only that actual metadata-tagged
		// prefix, not a used segment, an invalid prefix, or a textual guess.
		for _, prefix := range physical.Prefix {
			switch prefix & 0xff {
			case x86asm.PrefixES, x86asm.PrefixCS, x86asm.PrefixSS, x86asm.PrefixDS, x86asm.PrefixFS, x86asm.PrefixGS:
				if !strings.HasPrefix(part, prefix.String()+" ") {
					continue
				}
				if prefix&x86asm.PrefixIgnored == 0 {
					return nil, fmt.Errorf("%w: raw %s has an unbound physical %s segment prefix", ErrProbeNeedsContext, inst.Op, prefix)
				}
				part = strings.TrimPrefix(part, prefix.String()+" ")
			}
		}
		space := strings.IndexByte(part, ' ')
		if space >= 0 {
			args := splitTopLevelCSV(part[space+1:])
			for j, arg := range args {
				if binding, ok := bindings[strings.TrimSpace(arg)]; ok {
					args[j] = binding.name
					consumed++
				}
			}
			part = part[:space+1] + strings.Join(args, ", ")
		}
		parts[i] = part
	}
	if consumed != memoryCount {
		return nil, fmt.Errorf("decoded physical memory handoff consumed %d operands, want %d", consumed, memoryCount)
	}
	instructions, err := parseDecodedX86Instruction(strings.Join(parts, "; "))
	if err != nil {
		return nil, err
	}
	if len(instructions) != len(parts) {
		return nil, fmt.Errorf("decoded instruction/prefix handoff changed instruction count")
	}
	restored := 0
	for i := range instructions {
		for j, arg := range instructions[i].Args {
			if arg.Kind != OpIdent {
				continue
			}
			if operand, ok := byName[arg.Ident]; ok {
				instructions[i].Args[j] = operand
				restored++
			}
		}
		instructions[i].Raw = strings.TrimSpace(strings.Split(syntax, ";")[i])
	}
	if restored != memoryCount {
		return nil, fmt.Errorf("decoded physical memory handoff restored %d operands, want %d", restored, memoryCount)
	}
	return instructions, nil
}

// The pinned decoder appends L to these environment-load mnemonics, whereas
// Go's complete ysvrs_mo rows use FLDENV/FRSTOR for the 32-bit layout. Bind the
// real opcode, full prefix metadata, and complete encoding before dropping
// that formatter suffix. The 14/94-byte operand-size override is not this
// 28/108-byte Go layout and remains unsupported.
func decodedX86X87EnvironmentLoad(inst x86asm.Inst, encoding []byte) (Op, bool, error) {
	if inst.Op != x86asm.FLDENV && inst.Op != x86asm.FRSTOR {
		return "", false, nil
	}
	witness, err := x86asm.Decode(encoding, inst.Mode)
	witness = normalizeDecodedX86LEASegments(normalizeDecodedX86MemoryDisplacements(witness))
	memory, hasMemory := inst.Args[0].(x86asm.Mem)
	witnessMemory, hasWitnessMemory := witness.Args[0].(x86asm.Mem)
	if err != nil || witness.Len != len(encoding) || witness.Len != inst.Len ||
		witness.Op != inst.Op || witness.Opcode != inst.Opcode || witness.Prefix != inst.Prefix ||
		witness.DataSize != inst.DataSize || witness.AddrSize != inst.AddrSize || witness.MemBytes != inst.MemBytes ||
		!hasMemory || !hasWitnessMemory || memory != witnessMemory ||
		inst.Args[1] != nil || inst.Args[2] != nil || inst.Args[3] != nil {
		return "", true, fmt.Errorf("%w: raw x87 environment load lacks its complete decoder encoding", ErrProbeNeedsContext)
	}
	if inst.DataSize != 32 {
		return "", true, fmt.Errorf("raw %s uses a %d-bit environment layout not represented by Go %s", inst.Op, inst.DataSize, inst.Op)
	}
	return Op(inst.Op.String()), true, nil
}

func decodedX86PhysicalMemory(memory x86asm.Mem) (Operand, error) {
	register := func(reg x86asm.Reg) (Reg, error) {
		if reg == 0 {
			return "", nil
		}
		if reg == x86asm.RIP {
			return Reg("IP"), nil // Consumed only by the separate RIP layout proof.
		}
		text := x86asm.GoSyntax(x86asm.Inst{Op: x86asm.NOP, Args: x86asm.Args{reg}}, 0, nil)
		space := strings.IndexByte(text, ' ')
		if space < 0 {
			return "", fmt.Errorf("decoder formatter omitted its physical address register")
		}
		text = text[space+1:]
		value, ok := parseReg(text)
		if !ok {
			return "", fmt.Errorf("unsupported decoded physical address register %s", reg)
		}
		return value, nil
	}
	base, err := register(memory.Base)
	if err != nil {
		return Operand{}, err
	}
	index, err := register(memory.Index)
	if err != nil {
		return Operand{}, err
	}
	segment := Reg("")
	switch memory.Segment {
	case 0:
	case x86asm.ES, x86asm.CS, x86asm.SS, x86asm.DS, x86asm.FS, x86asm.GS:
		segment = Reg(memory.Segment.String())
	default:
		return Operand{}, fmt.Errorf("unsupported decoded physical segment %s", memory.Segment)
	}
	return Operand{Kind: OpMem, Mem: MemRef{Base: base, Index: index, Scale: int64(memory.Scale), Off: memory.Disp, Segment: segment}}, nil
}
