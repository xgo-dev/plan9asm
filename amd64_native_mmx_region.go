package plan9asm

import (
	"fmt"
	"strings"
)

var x86NativeMMXGPRegisters = [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI,
	"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}

func (c *amd64Ctx) lowerNativeMMXRegionAt(block, ordinal int, ins Instr) (bool, error) {
	plan := c.nativeMMXRegion
	if plan == nil || ordinal < plan.begin || ordinal > plan.end {
		return false, nil
	}
	if block != 0 || len(c.blocks) != 1 || !plan.matchesInstruction(ordinal, ins) {
		return true, fmt.Errorf("%w: native MMX source position changed", ErrProbeNeedsContext)
	}
	if ordinal != plan.begin {
		return true, nil // The complete sealed sequence was emitted at its first instruction.
	}
	if !plan.matches(c.fpScalarSource, c.fpSourceSig, c.goarch, c.targetTriple) {
		return true, fmt.Errorf("%w: native MMX source/declaration binding changed", ErrProbeNeedsContext)
	}
	return true, c.emitNativeMMXRegion(plan)
}

// These names differ between Go's operand-width notation and Intel/LLVM's
// spelling. The operand and encoding rows still come from the shared complete
// x86LegacyMMXReadSpecs; this selector grants no additional form or input.
func x86NativeMMXIntegerMnemonic(op Op) string {
	switch op {
	case "PACKSSLW":
		return "packssdw"
	case "PADDL":
		return "paddd"
	case "PCMPEQL":
		return "pcmpeqd"
	case "PCMPGTL":
		return "pcmpgtd"
	case "PMADDWL":
		return "pmaddwd"
	case "PMULULQ":
		return "pmuludq"
	case "PUNPCKHWL":
		return "punpckhwd"
	case "PUNPCKHLQ":
		return "punpckhdq"
	case "PUNPCKLWL":
		return "punpcklwd"
	case "PUNPCKLLQ":
		return "punpckldq"
	case "PSLLL":
		return "pslld"
	case "PSRLL":
		return "psrld"
	case "PSRAL":
		return "psrad"
	}
	return strings.ToLower(string(op))
}

func (c *amd64Ctx) emitNativeMMXRegion(plan *x86NativeMMXRegion) error {
	gpBase := (plan.fpExtent + 15) &^ 15
	xBase := gpBase + int64(len(x86NativeMMXGPRegisters))*8
	extent := xBase
	for index := range plan.xRead {
		if plan.xRead[index] || plan.xWritten[index] {
			extent = xBase + 16*int64(index+1)
		}
	}
	image := "%" + c.newTmp()
	fmt.Fprintf(c.b, "  %s = alloca [%d x i8], align 16\n", image, extent)
	pointer := func(offset int64) string {
		name := "%" + c.newTmp()
		fmt.Fprintf(c.b, "  %s = getelementptr i8, ptr %s, i64 %d\n", name, image, offset)
		return name
	}
	// This image gathers only declared logical numeric fields. Its address is
	// private to the asm region: source GPs, native pointers and later effects
	// cannot acquire it as a frame, contiguous caller storage or a GC root.
	var fields []FrameSlot
	for _, slots := range [][]FrameSlot{c.sig.Frame.Params, c.sig.Frame.Results} {
		for _, slot := range slots {
			width := x86FrameScalarBytes(slot.Type, c.goarch)
			touched := false
			for offset := slot.Offset; offset < slot.Offset+width; offset++ {
				touched = touched || plan.fpRead[offset] || plan.fpWritten[offset]
			}
			if !touched {
				continue
			}
			value, err := c.loadFPVectorBytes(slot.Offset, int(width))
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1\n", width, value, pointer(slot.Offset))
			fields = append(fields, slot)
		}
	}
	for index, reg := range x86NativeMMXGPRegisters {
		if !plan.gpRead[index] && !plan.gpWritten[index] {
			continue
		}
		value, err := c.loadReg(reg)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", value, pointer(gpBase+8*int64(index)))
	}
	for index := range plan.xRead {
		if !plan.xRead[index] && !plan.xWritten[index] {
			continue
		}
		value, err := c.loadX(Reg(fmt.Sprintf("X%d", index)))
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", value, pointer(xBase+16*int64(index)))
	}
	assembly, err := x86NativeMMXAssembly(plan, gpBase, xBase)
	if err != nil {
		return err
	}
	scratch := []string{"r10", "r11", "xmm15"}
	if c.goarch == "386" {
		scratch = []string{"eax", "edx", "xmm7"}
	}
	constraints := []string{"r"}
	for _, site := range plan.sites {
		if site.maskStore != nil {
			constraints = append(constraints, "~{di}")
			break
		}
	}
	for _, reg := range scratch {
		constraints = append(constraints, "~{"+reg+"}")
	}
	for index := 0; index < 8; index++ {
		constraints = append(constraints, fmt.Sprintf("~{mm%d}", index))
		name := "st"
		if index != 0 {
			name = fmt.Sprintf("st(%d)", index)
		}
		constraints = append(constraints, "~{"+name+"}")
	}
	constraints = append(constraints, "~{fpsr}", "~{memory}")
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(ptr %s)\n", assembly, strings.Join(constraints, ","), image)
	for _, slot := range fields {
		width := x86FrameScalarBytes(slot.Type, c.goarch)
		written := false
		for offset := slot.Offset; offset < slot.Offset+width; offset++ {
			written = written || plan.fpWritten[offset]
		}
		if written {
			value := "%" + c.newTmp()
			fmt.Fprintf(c.b, "  %s = load <%d x i8>, ptr %s, align 1\n", value, width, pointer(slot.Offset))
			if err := c.storeFPVectorBytes(slot.Offset, int(width), value, ""); err != nil {
				return err
			}
		}
	}
	for index, reg := range x86NativeMMXGPRegisters {
		if plan.gpWritten[index] {
			value := "%" + c.newTmp()
			fmt.Fprintf(c.b, "  %s = load i64, ptr %s, align 1\n", value, pointer(gpBase+8*int64(index)))
			if err := c.storeReg(reg, value); err != nil {
				return err
			}
		}
	}
	for index, written := range plan.xWritten {
		if written {
			value := "%" + c.newTmp()
			fmt.Fprintf(c.b, "  %s = load <16 x i8>, ptr %s, align 1\n", value, pointer(xBase+16*int64(index)))
			if err := c.storeLegacyPackedLogical(Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", index))}, value); err != nil {
				return err
			}
		}
	}
	if !plan.matches(c.fpScalarSource, c.fpSourceSig, c.goarch, c.targetTriple) {
		return fmt.Errorf("%w: native MMX source changed while emitting its region", ErrProbeNeedsContext)
	}
	return nil
}

func x86NativeMMXAssembly(plan *x86NativeMMXRegion, gpBase, xBase int64) (string, error) {
	word, data, address, vector := "movq", "%r10", "%r11", "%xmm15"
	if plan.arch == "386" {
		word, data, address, vector = "movl", "%eax", "%edx", "%xmm7"
	}
	var code []string
	gp := func(reg Reg) (int64, error) {
		index, _, valid := x86ResultGP(reg, x86ResultPointerWord(plan.arch), plan.arch)
		if !valid {
			return 0, fmt.Errorf("%w: MMX region lost a typed GP identity", ErrProbeNeedsContext)
		}
		return gpBase + int64(index)*8, nil
	}
	memory := func(operand Operand) (string, error) {
		if operand.Kind == OpFP {
			return fmt.Sprintf("%d($0)", operand.FPOffset), nil
		}
		if operand.Kind != OpMem {
			return "", fmt.Errorf("%w: MMX memory lost its source operand class", ErrProbeNeedsContext)
		}
		base, err := gp(operand.Mem.Base)
		if err != nil {
			return "", err
		}
		code = append(code, fmt.Sprintf("%s %d($0), %s", word, base, address))
		if operand.Mem.Index != "" {
			index, err := gp(operand.Mem.Index)
			if err != nil {
				return "", err
			}
			code = append(code, fmt.Sprintf("%s %d($0), %s", word, index, data),
				fmt.Sprintf("lea %d(%s,%s,%d), %s", operand.Mem.Off, address, data, operand.Mem.Scale, address))
			return "(" + address + ")", nil
		}
		return fmt.Sprintf("%d(%s)", operand.Mem.Off, address), nil
	}
	for ordinal := plan.begin; ordinal <= plan.end; ordinal++ {
		site := plan.sites[ordinal]
		if site.instruction.Op == "EMMS" {
			code = append(code, "emms")
			continue
		}
		if form := site.word; form != nil {
			mnemonic := "movq"
			if form.bytes == 4 {
				mnemonic = "movd"
			}
			if form.nonTemporal {
				mnemonic = "movntq"
			}
			if form.targetM {
				source := ""
				if form.sourceX {
					index, _ := amd64ParseXReg(form.source.Reg)
					code = append(code, fmt.Sprintf("movdqu %d($0), %s", xBase+int64(index)*16, vector))
					mnemonic, source = "movdq2q", vector
				} else if form.source.Kind == OpReg {
					offset, err := gp(form.source.Reg)
					if err != nil {
						return "", err
					}
					load, reg := word, data
					if form.bytes == 4 {
						load, reg = "movl", "%eax"
						if plan.arch == "amd64" {
							reg = "%r10d"
						}
					}
					code = append(code, fmt.Sprintf("%s %d($0), %s", load, offset, reg))
					source = reg
				} else {
					var err error
					source, err = memory(form.source)
					if err != nil {
						return "", err
					}
				}
				index, _ := amd64ParseMReg(form.destination.Reg)
				code = append(code, fmt.Sprintf("%s %s, %%mm%d", mnemonic, source, index))
				continue
			}
			source, _ := amd64ParseMReg(form.source.Reg)
			if form.targetX {
				index, _ := amd64ParseXReg(form.destination.Reg)
				code = append(code, fmt.Sprintf("movq2dq %%mm%d, %s", source, vector),
					fmt.Sprintf("movdqu %s, %d($0)", vector, xBase+int64(index)*16))
			} else if form.destination.Kind == OpReg {
				offset, err := gp(form.destination.Reg)
				if err != nil {
					return "", err
				}
				reg := data
				if form.bytes == 4 && plan.arch == "amd64" {
					reg = "%r10d"
				}
				code = append(code, fmt.Sprintf("%s %%mm%d, %s", mnemonic, source, reg),
					fmt.Sprintf("%s %s, %d($0)", word, data, offset))
				if plan.arch == "386" {
					code = append(code, fmt.Sprintf("movl $$0, %d($0)", offset+4))
				}
			} else {
				destination, err := memory(form.destination)
				if err != nil {
					return "", err
				}
				code = append(code, fmt.Sprintf("%s %%mm%d, %s", mnemonic, source, destination))
			}
			continue
		}
		if site.moveMask != nil {
			offset, err := gp(site.instruction.Args[1].Reg)
			if err != nil {
				return "", err
			}
			bank, _ := amd64ParseMReg(site.instruction.Args[0].Reg)
			reg := "%r10d"
			if plan.arch == "386" {
				reg = "%eax"
			}
			code = append(code, fmt.Sprintf("pmovmskb %%mm%d, %s", bank, reg),
				fmt.Sprintf("%s %s, %d($0)", word, data, offset))
			if plan.arch == "386" {
				code = append(code, fmt.Sprintf("movl $$0, %d($0)", offset+4))
			}
			continue
		}
		if site.maskStore != nil {
			offset, err := gp(DI)
			if err != nil {
				return "", err
			}
			destination := "%rdi"
			if plan.arch == "386" {
				destination = "%edi"
			}
			mask, _ := amd64ParseMReg(site.instruction.Args[0].Reg)
			data, _ := amd64ParseMReg(site.instruction.Args[1].Reg)
			code = append(code, fmt.Sprintf("%s %d($0), %s", word, offset, destination),
				fmt.Sprintf("maskmovq %%mm%d, %%mm%d", mask, data))
			continue
		}
		form := site.integer
		destination, _ := amd64ParseMReg(site.instruction.Args[form.destination].Reg)
		mnemonic := x86NativeMMXIntegerMnemonic(form.canonical)
		if form.source.Kind == OpImm {
			code = append(code, fmt.Sprintf("%s $$%d, %%mm%d", mnemonic, byte(form.source.Imm), destination))
			continue
		}
		source := ""
		if form.source.Kind == OpReg {
			index, _ := amd64ParseMReg(form.source.Reg)
			source = fmt.Sprintf("%%mm%d", index)
		} else {
			var err error
			source, err = memory(form.source)
			if err != nil {
				return "", err
			}
		}
		immediate := ""
		if form.spec.table == x86LegacyMMXShuffle {
			immediate = fmt.Sprintf("$$%d, ", byte(site.instruction.Args[0].Imm))
		}
		code = append(code, fmt.Sprintf("%s %s%s, %%mm%d", mnemonic, immediate, source, destination))
	}
	return strings.Join(code, "; "), nil
}
