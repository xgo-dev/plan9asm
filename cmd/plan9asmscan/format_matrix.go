package main

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// scanOrthogonalFormatMatrix extends the encoder-table oracle with systematic
// orthogonal operand-format expansion across all 5 architectures:
//   - x86/386: every dual reg/mem slot expanded to base+offset, SIB indexed,
//     global symbol(SB), segment-prefixed memory (FS:/GS:), sub-registers
//     (AH..DH, R8B..R15B, SPB/BPB/SIB/DIB, R8W..R15W, R8L..R15L, EAX..EDI),
//     EVEX masks ({K1}, .Z + K1, .BCST, rounding .RN_SAE/.SAE), and LOCK/REP.
//   - arm64: .P/.W pre/post-increment on load/store/pair/vector ops, global
//     sym+8(SB) loads/stores, all 8 vector arrangements (.B8..D2), 3/4-reg
//     lists, indexed/extended memory, 2-op scalar/FP/NEON shorthands, and
//     SVE P0/Z & P0/M predicates.
//   - arm: condition suffixes (.EQ/.NE/.LT), .S flag updates, .P/.W/.U modes,
//     global sym+8(SB) memory, VFP<->GPR bit moves (MOVW F0, R1 / R1, F0),
//     register-shifted operands (R1<<R2, >>, ->, @>), and MOVM modes.
//   - wasm: parameterized operand-format matrix covering immediates, memory
//     offsets, lane indices, 16-lane shuffles, locals, globals, and BrTable.
func scanOrthogonalFormatMatrix(goroot string, arch plan9asm.Arch, goarch string) (
	map[string]*opStat,
	map[string]*formStat,
	[]parseErr,
	int,
	[]encoderFormReport,
	error,
) {
	encoderCatalog, err := loadEncoderForms(goroot, goarch)
	if err != nil {
		return nil, nil, nil, 0, nil, err
	}
	ops := map[string]*opStat{}
	forms := map[string]*formStat{}
	var parseErrs []parseErr
	seenLines := map[string]struct{}{}
	tablesSeen := map[string]struct{}{}

	// Identify x86 opcodes that actually have EVEX mask register classes (Yk/Yknot0)
	// in Go's authoritative encoder table so we test K1/.Z on all maskable ops
	// without synthesizing hardware-illegal masking (e.g. VAESENC with K1).
	maskableX86Ops := map[string]bool{}
	if goarch == "386" || goarch == "amd64" {
		for _, row := range encoderCatalog {
			for _, cls := range row.OperandClasses {
				if cls == "Yk" || cls == "Yknot0" {
					maskableX86Ops[row.Opcode] = true
					break
				}
			}
		}
	}

	probeLine := func(tableLabel, formTag, line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		if _, dup := seenLines[line]; dup {
			return
		}
		seenLines[line] = struct{}{}

		probeSrc := "TEXT plan9asm_probe(SB),NOSPLIT,$0\n" + line + "\nRET\n"
		file, err := plan9asm.Parse(arch, probeSrc)
		if err != nil {
			parseErrs = append(parseErrs, parseErr{
				File: tableLabel + ":" + formTag,
				Err:  fmt.Sprintf("%s -> %v", line, err),
			})
			return
		}
		for _, fn := range file.Funcs {
			for i, ins := range fn.Instrs {
				if i == len(fn.Instrs)-1 && ins.Op == plan9asm.OpRET {
					continue
				}
				if ins.Op == plan9asm.OpLABEL || ins.Op == plan9asm.OpTEXT {
					continue
				}
				addOpStat(ops, string(ins.Op), tableLabel, "format-matrix", 1)
				addFormStat(forms, arch, goarch, ins, tableLabel)
			}
		}
	}

	for _, row := range encoderCatalog {
		if isNonInstructionEncoderOp(row.Opcode) {
			continue
		}
		tableLabel := "format-matrix"
		if len(row.Tables) > 0 {
			tableLabel = row.Tables[0]
		}
		tablesSeen[tableLabel] = struct{}{}

		for _, line := range synthesizeFormatMatrixLines(goarch, row, maskableX86Ops) {
			probeLine(tableLabel, row.Form, line)
		}
	}

	for _, line := range extraOrthogonalFormatLines(goarch) {
		probeLine("format-matrix-extra", line, line)
	}

	return ops, forms, parseErrs, len(tablesSeen), encoderCatalog, nil
}

func synthesizeFormatMatrixLines(goarch string, row encoderFormReport, maskableX86Ops map[string]bool) []string {
	base := synthesizeEncoderLines(goarch, row)
	switch goarch {
	case "386", "amd64":
		return expandX86FormatMatrix(goarch, row, base, maskableX86Ops)
	case "arm64":
		return expandARM64FormatMatrix(row, base)
	case "arm":
		return expandARMFormatMatrix(row, base)
	case "wasm":
		return expandWASMFormatMatrix(row, base)
	default:
		return base
	}
}

func expandX86FormatMatrix(goarch string, row encoderFormReport, base []string, maskableX86Ops map[string]bool) []string {
	out := append([]string(nil), base...)
	op := row.Opcode
	classes := row.OperandClasses
	if op == "END" || len(classes) == 0 || (len(classes) == 1 && classes[0] == "@special") {
		return out
	}
	for _, cls := range classes {
		if cls == "Ytextsize" {
			return nil
		}
	}

	buildWith := func(memSlot int, memExpr string, subReg bool, suffix string, insertK bool) string {
		args := make([]string, 0, len(classes)+1)
		for i, cls := range classes {
			var arg string
			var ok bool
			if i == memSlot {
				arg, ok = memExpr, true
			} else if subReg && goarch == "amd64" && (cls == "Yrb" || cls == "Ymb") {
				regs := []string{"R8B", "AH", "SIB", "R15B"}
				arg, ok = regs[i%len(regs)], true
			} else if subReg && goarch == "amd64" && (cls == "Yrl" || cls == "Yml") {
				regs := []string{"R8", "R9", "R10", "R11"}
				arg, ok = regs[i%len(regs)], true
			} else {
				arg, ok = synthX86Operand(cls, i, false)
			}
			if !ok {
				return ""
			}
			if insertK && i == len(classes)-1 {
				args = append(args, "K1")
			}
			args = append(args, arg)
		}
		return op + suffix + " " + strings.Join(args, ", ")
	}

	// 1. Expand ALL reg/mem slots (not just the first!) with base+off, SIB, and sym(SB).
	hasEVEX := false
	hasVecMem := false
	for i, cls := range classes {
		if strings.Contains(cls, "Evex") || cls == "Yzm" || cls == "Yzr" {
			hasEVEX = true
		}
		if cls == "Ym" || isX86RegOrMemClass(cls) {
			if cls == "Yxm" || cls == "YxmEvex" || cls == "Yym" || cls == "YymEvex" || cls == "Yzm" {
				hasVecMem = true
			}
			if l := buildWith(i, "8(BX)", false, "", false); l != "" {
				out = append(out, l)
			}
			if l := buildWith(i, "8(BX)(SI*4)", false, "", false); l != "" {
				out = append(out, l)
			}
			if l := buildWith(i, "sym+8(SB)", false, "", false); l != "" {
				out = append(out, l)
			}
		}
	}

	// 2. Extended register / sub-register matrix (R8B..R15B, AH, SIB, R8..R11 on amd64).
	if goarch == "amd64" && op != "CMPXCHG8B" && op != "CMPXCHG16B" {
		if l := buildWith(-1, "", true, "", false); l != "" {
			out = append(out, l)
		}
	}

	// 3. EVEX .Z + K1 masking and .BCST broadcast variants on maskable AVX-512 ops.
	hasKClass := false
	for _, cls := range classes {
		if cls == "Yk" || cls == "Yknot0" || cls == "Ykm" {
			hasKClass = true
		}
	}
	if hasEVEX && strings.HasPrefix(op, "V") {
		if hasKClass {
			// Exercise zero-masking .Z on ops that already carry Kmask in the optab row.
			if l := buildWith(-1, "", false, ".Z", false); l != "" {
				out = append(out, l)
			}
		} else if maskableX86Ops[op] && len(classes) >= 2 && (classes[len(classes)-1] == "YxrEvex" || classes[len(classes)-1] == "YyrEvex" || classes[len(classes)-1] == "Yzr") {
			if l := buildWith(-1, "", false, "", true); l != "" {
				out = append(out, l)
			}
			if l := buildWith(-1, "", false, ".Z", true); l != "" {
				out = append(out, l)
			}
		}
		if hasVecMem && !strings.Contains(op, "MOV") && !strings.Contains(op, "COMPRESS") && !strings.Contains(op, "EXPAND") {
			for i, cls := range classes {
				if cls == "YxmEvex" || cls == "YymEvex" || cls == "Yzm" {
					if l := buildWith(i, "8(BX)", false, ".BCST", false); l != "" {
						out = append(out, l)
					}
					break
				}
			}
		}
	}
	return out
}

func expandARM64FormatMatrix(row encoderFormReport, base []string) []string {
	out := append([]string(nil), base...)
	op := row.Opcode
	if op == "END" || len(row.OperandClasses) == 0 {
		return out
	}
	for _, line := range base {
		if strings.Contains(line, ".B16") && !strings.Contains(line, "[") {
			out = append(out,
				strings.ReplaceAll(line, ".B16", ".B8"),
				strings.ReplaceAll(line, ".B16", ".H4"),
				strings.ReplaceAll(line, ".B16", ".H8"),
				strings.ReplaceAll(line, ".B16", ".S2"),
				strings.ReplaceAll(line, ".B16", ".S4"),
				strings.ReplaceAll(line, ".B16", ".D2"),
			)
		}
		if strings.Contains(line, "R1<<1") {
			out = append(out,
				strings.Replace(line, "R1<<1", "R1>>2", 1),
				strings.Replace(line, "R1<<1", "R1->2", 1),
			)
		}
		if strings.Contains(line, "R1.UXTW") {
			out = append(out,
				strings.Replace(line, "R1.UXTW", "R1.UXTW<<2", 1),
				strings.Replace(line, "R1.UXTW", "R1.SXTB<<1", 1),
			)
		}
		if strings.Contains(line, "P0.Z") {
			out = append(out, strings.Replace(line, "P0.Z", "P0/Z", 1))
		}
		if strings.Contains(line, "P0.M") {
			out = append(out, strings.Replace(line, "P0.M", "P0/M", 1))
		}
	}
	return out
}

func expandARMFormatMatrix(row encoderFormReport, base []string) []string {
	out := append([]string(nil), base...)
	op := row.Opcode
	if op == "END" || len(row.OperandClasses) == 0 {
		return out
	}
	for _, line := range base {
		if !strings.HasPrefix(op, "B") && !strings.HasPrefix(op, "DUFF") && !strings.Contains(op, ".") {
			if sp := strings.IndexByte(line, ' '); sp > 0 {
				out = append(out, line[:sp]+".EQ"+line[sp:])
			}
		}
		if strings.Contains(line, "R1<<1") {
			out = append(out,
				strings.Replace(line, "R1<<1", "R1<<R2", 1),
				strings.Replace(line, "R1<<1", "R1>>R2", 1),
				strings.Replace(line, "R1<<1", "R1->R2", 1),
				strings.Replace(line, "R1<<1", "R1@>R2", 1),
			)
		}
		if strings.Contains(line, "4(R1)") && (strings.HasPrefix(op, "MOV") && !strings.HasPrefix(op, "MOVM")) {
			out = append(out, strings.Replace(line, "4(R1)", "sym+8(SB)", 1))
		}
	}
	return out
}

func expandWASMFormatMatrix(row encoderFormReport, base []string) []string {
	op := row.Opcode
	out := append([]string(nil), base...)
	switch {
	case strings.Contains(op, "EXTRACTLANE") || strings.Contains(op, "REPLACELANE"):
		out = append(out, op+" $0")
	case strings.Contains(op, "SHUFFLE"):
		out = append(out, op+" $0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15")
	case strings.Contains(op, "LOAD") && strings.Contains(op, "LANE"),
		strings.Contains(op, "STORE") && strings.Contains(op, "LANE"):
		out = append(out, op+" $0, $0")
	case strings.Contains(op, "LOAD") || strings.Contains(op, "STORE"):
		out = append(out, op+" $8")
	case op == "LOCALGET" || op == "LOCALSET" || op == "LOCALTEE":
		out = append(out, op+" $0")
	case op == "GET" || op == "SET" || op == "TEE":
		out = append(out, op+" 8(SP)")
	case op == "BRTABLE":
		out = append(out, op+" $0, $1, $2")
	}
	return out
}

func extraOrthogonalFormatLines(goarch string) []string {
	switch goarch {
	case "386":
		return []string{
			// Sub-registers and 32-bit named aliases
			"MOVB AH, BL", "MOVB BL, AH", "MOVL EAX, EBX", "ADDL ECX, EDX", "XORL ESI, EDI",
			// Segment overrides + LOCK + REP prefixes across all 32-bit string ops
			"MOVL FS:0(BX), AX", "MOVL GS:0x14(BX), AX", "MOVL 0(TLS), AX",
			"ADDL FS:8(BX), AX", "ADDL AX, GS:8(BX)",
			"LOCK; ADDL $1, 8(BX)", "LOCK; SUBL $1, 8(BX)", "LOCK; ANDL $1, 8(BX)", "LOCK; ORL $1, 8(BX)",
			"LOCK; ORW $1, 8(BX)", "LOCK; ANDW $1, 8(BX)",
			"LOCK; XORL $1, 8(BX)", "LOCK; INCL 8(BX)", "LOCK; DECL 8(BX)",
			"LOCK; BTSL $1, 8(BX)", "LOCK; BTRL $1, 8(BX)", "LOCK; BTCL $1, 8(BX)",
			"LOCK; NEGL 8(BX)", "LOCK; NOTL 8(BX)", "LOCK; ADCL $1, 8(BX)", "LOCK; SBBL $1, 8(BX)",
			"LOCK; XADDL AX, 8(BX)", "LOCK; CMPXCHGL BX, 8(BX)", "LOCK; CMPXCHG8B 8(BX)",
			"LOCK; XADDL AX, sym+8(SB)", "LOCK; CMPXCHGL BX, sym+8(SB)",
			// Character literal immediates
			"MOVL $'a', AX", "CMPL AX, $','", "ADDL $('z'-'a'), AX",
			"REP; MOVSB", "REP; MOVSW", "REP; MOVSL",
			"REP; STOSB", "REP; STOSW", "REP; STOSL",
			"REPN; SCASB", "REPN; SCASW", "REPN; SCASL",
			"REP; CMPSB", "REP; CMPSW", "REP; CMPSL", "REPN; CMPSB",
			"REP; LODSB", "REP; LODSW", "REP; LODSL",
		}
	case "amd64":
		return []string{
			// Extended 8/16/32-bit sub-registers
			"MOVB R8B, R15B", "MOVB SPB, BPB", "MOVB SIB, DIB", "MOVB AH, BL", "MOVB BL, AH",
			"MOVB SPL, BPL", "MOVB SIL, DIL",
			"ADDB R8B, R9B", "XORB SIB, DIB", "CMPB R15B, $1",
			"MOVW R8W, R15W", "MOVL R8L, R15L", "MOVL R8D, R15D", "ADDL R8L, R9L", "ADDL EAX, EBX",
			// Segment overrides + LOCK + REP prefixes
			"MOVQ FS:0(BX), AX", "MOVQ GS:0x30(BX), AX", "MOVL 0(TLS), AX",
			"ADDQ FS:8(BX), AX", "ADDQ AX, GS:8(BX)", "ADDQ AX, FS:8(BX)(SI*4)",
			"LOCK; ADDQ $1, 8(BX)", "LOCK; SUBQ $1, 8(BX)", "LOCK; ANDQ $1, 8(BX)", "LOCK; ORQ $1, 8(BX)",
			"LOCK; ORW $1, 8(BX)", "LOCK; ANDW $1, 8(BX)",
			"LOCK; XORQ $1, 8(BX)", "LOCK; INCQ 8(BX)", "LOCK; DECQ 8(BX)",
			"LOCK; XADDQ AX, 8(BX)", "LOCK; CMPXCHGQ BX, 8(BX)", "LOCK; CMPXCHG16B 8(BX)",
			"LOCK; BTSQ $1, 8(BX)", "LOCK; BTRQ $1, 8(BX)", "LOCK; BTCQ $1, 8(BX)",
			"LOCK; NEGQ 8(BX)", "LOCK; NOTQ 8(BX)", "LOCK; ADCQ $1, 8(BX)", "LOCK; SBBQ $1, 8(BX)",
			"LOCK; ADDQ $1, sym+8(SB)", "LOCK; XADDQ AX, sym+8(SB)", "LOCK; CMPXCHGQ BX, sym+8(SB)",
			// Character literal immediates + symbol-offset control transfer
			"MOVQ $'a', AX", "CMPQ AX, $','", "ADDQ $('z'-'a'), AX",
			"JMP sym+8(SB)", "CALL sym+8(SB)",
			"STD; REP; MOVSB", "CLD; REP; MOVSB", "STD; REP; STOSW",
			"REP; MOVSB", "REP; MOVSW", "REP; MOVSL", "REP; MOVSQ",
			"REP; STOSB", "REP; STOSW", "REP; STOSL", "REP; STOSQ",
			"REPN; SCASB", "REPN; SCASW", "REPN; SCASL", "REPN; SCASQ",
			"REP; CMPSB", "REPN; CMPSQ", "REP; LODSB", "REP; LODSQ",
			// AVX-512 embedded rounding / SAE modifiers
			"VADDPS.RN_SAE Z0, Z1, Z2", "VADDPS.RD_SAE Z0, Z1, Z2", "VADDPS.RU_SAE Z0, Z1, Z2", "VADDPS.RZ_SAE Z0, Z1, Z2",
			"VADDPD.RN_SAE Z0, Z1, K1, Z2", "VADDPD.Z.RN_SAE Z0, Z1, K1, Z2",
			"VFMADD213PS.RN_SAE Z0, Z1, Z2", "VMAXPS.SAE Z0, Z1, Z2",
		}
	case "arm64":
		return []string{
			// Pre/post increment .P / .W across all load/store families
			"MOVD.P 8(R1), R2", "MOVD.W 8(R1), R2", "MOVD.P R2, 8(R1)", "MOVD.W R2, 8(R1)",
			"MOVW.P 4(R1), R2", "MOVW.W 4(R1), R2", "MOVWU.P 4(R1), R2", "MOVWU.W 4(R1), R2",
			"MOVH.P 2(R1), R2", "MOVH.W 2(R1), R2", "MOVHU.P 2(R1), R2", "MOVHU.W 2(R1), R2",
			"MOVB.P 1(R1), R2", "MOVB.W 1(R1), R2", "MOVBU.P 1(R1), R2", "MOVBU.W 1(R1), R2",
			"MOVBW.P 1(R1), R2", "MOVBW.W 1(R1), R2", "MOVHW.P 2(R1), R2", "MOVHW.W 2(R1), R2",
			"FMOVS.P 4(R1), F0", "FMOVS.W 4(R1), F0", "FMOVD.P 8(R1), F0", "FMOVD.W 8(R1), F0",
			"FMOVB.P 1(R1), F0", "FMOVB.W 1(R1), F0", "FMOVH.P 2(R1), F0", "FMOVH.W 2(R1), F0",
			"LDP.P 16(R1), (R2, R3)", "LDP.W 16(R1), (R2, R3)",
			"LDPW.P 8(R1), (R2, R3)", "LDPW.W 8(R1), (R2, R3)",
			"LDPSW.P 8(R1), (R2, R3)", "LDPSW.W 8(R1), (R2, R3)",
			"STP.P (R2, R3), 16(R1)", "STP.W (R2, R3), 16(R1)",
			"STPW.P (R2, R3), 8(R1)", "STPW.W (R2, R3), 8(R1)",
			"FLDPD.P 16(R1), (F0, F1)", "FLDPD.W 16(R1), (F0, F1)",
			"FSTPD.P (F0, F1), 16(R1)", "FSTPD.W (F0, F1), 16(R1)",
			"VLD1.P 16(R1), [V0.B16]", "VLD1.P (R1)(R2), [V0.B16, V1.B16, V2.B16, V3.B16]",
			"VST1.P [V0.B16, V1.B16, V2.B16, V3.B16], 64(R1)",
			// Global symbol(SB) memory loads/stores
			"MOVD sym+8(SB), R1", "MOVD R1, sym+8(SB)",
			"MOVW sym+8(SB), R1", "MOVW R1, sym+8(SB)", "MOVWU sym+8(SB), R1",
			"MOVH sym+8(SB), R1", "MOVH R1, sym+8(SB)", "MOVHU sym+8(SB), R1",
			"MOVB sym+8(SB), R1", "MOVB R1, sym+8(SB)", "MOVBU sym+8(SB), R1",
			"FMOVS sym+8(SB), F0", "FMOVS F0, sym+8(SB)",
			"FMOVD sym+8(SB), F0", "FMOVD F0, sym+8(SB)",
			"FMOVQ sym+8(SB), F0", "FMOVQ F0, sym+8(SB)",
			// 2-op shorthands across scalar ALU, FP, and NEON
			"ADD R1, R2", "SUB R1, R2", "AND R1, R2", "ORR R1, R2", "EOR R1, R2", "BIC R1, R2",
			"ADDW R1, R2", "SUBW R1, R2", "ANDW R1, R2", "ORRW R1, R2", "EORW R1, R2", "BICW R1, R2",
			"LSL R1, R2", "LSR R1, R2", "ASR R1, R2", "ROR R1, R2", "MUL R1, R2", "UDIV R1, R2", "SDIV R1, R2",
			"LSLW R1, R2", "LSRW R1, R2", "ASRW R1, R2", "RORW R1, R2", "MULW R1, R2", "UDIVW R1, R2", "SDIVW R1, R2",
			"VAND V0.B16, V1.B16, V2.B16", "VEOR V0.B16, V1.B16, V2.B16", "VORR V0.B16, V1.B16, V2.B16",
			"VADD V0.S4, V1.S4", "VADD V0.B16, V1.B16, V2.B16", "VADD V0.H8, V1.H8, V2.H8", "VADD V0.D2, V1.D2, V2.D2",
			"FADDS F0, F1", "FSUBS F0, F1", "FMULS F0, F1", "FDIVS F0, F1",
			"FADDD F0, F1", "FSUBD F0, F1", "FMULD F0, F1", "FDIVD F0, F1",
			// Indexed/extended addressing + SVE gather/predicates
			"MOVD (R1)(R2), R3", "MOVD (R1)(R2<<3), R3", "MOVD (R1)(R2.UXTW<<3), R3",
			"MOVD (R1)(R2.SXTW<<3), R3", "MOVW (R1)(R2<<2), R3", "MOVBU (R1)(R2), R3",
			"ZADD Z0.S, P0/M, Z1.S", "ZLD1W (R1)(Z0.S<<2), P0/Z, Z1.S",
			// Character literal immediates
			"MOVD $'a', R1", "ADD $',', R1, R2", "ADD $('z'-'a'), R1, R2",
		}
	case "arm":
		return []string{
			"ADD.EQ R1, R2, R3", "ADD.NE.S R1, R2, R3", "SUB.S.LT R1, R2, R3",
			"MOVW.EQ R1, R2", "MOVW.P 4(R1), R2", "MOVW.W 4(R1), R2", "MOVW.U 4(R1), R2",
			"MOVW.W.U 4(R1), R2", "MOVW.P.U 4(R1), R2", "MOVW.W.U R2, 4(R1)", "MOVW.P.U R2, 4(R1)",
			"MOVW.EQ.P 4(R1), R2", "MOVBU.P 1(R1), R2", "MOVHU.P 2(R1), R2", "MOVB.W.U 1(R1), R2",
			"MOVF.W 4(R1), F0", "MOVD.P.U 8(R1), F0",
			"MOVW $'a', R1", "ADD $',', R1, R2",
			"MOVW F0, R1", "MOVW R1, F0", "MOVW.EQ F0, R1", "MOVW.NE R1, F0",
			"MOVW sym+8(SB), R1", "MOVW R1, sym+8(SB)",
			"MOVB sym+8(SB), R1", "MOVB R1, sym+8(SB)", "MOVBU sym+8(SB), R1",
			"MOVH sym+8(SB), R1", "MOVH R1, sym+8(SB)", "MOVHU sym+8(SB), R1",
			"MOVF sym+8(SB), F0", "MOVF F0, sym+8(SB)", "MOVD sym+8(SB), F0", "MOVD F0, sym+8(SB)",
			"MOVM.IA.W [R0-R3], (R4)", "MOVM.DB.W (R4), [R0-R3]", "MOVM.IB [R0,R2,R4], (R5)",
			"MOVM.DA (R4), [R0,R1]", "MUL.S R1, R2, R3", "BFI.EQ $4, R1, R2", "ADDF.NE F0, F1, F2",
		}
	case "wasm":
		return []string{
			"I32Const $42", "I64Const $42", "F32Const $1", "F64Const $1",
			"LocalGet $0", "LocalSet $0", "LocalTee $0",
			"GlobalGet $0", "GlobalSet $0",
			"I32Load $8", "I64Load $16", "F32Load $4", "F64Load $8",
			"I32Store $8", "I64Store $16", "F32Store $4", "F64Store $8",
			"I8x16Shuffle $0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15",
			"I32x4ExtractLane $3", "I32x4ReplaceLane $3",
			"V128Load32Lane $4, $1", "V128Store32Lane $4, $1",
			"BrTable $0, $1, $2", "MemorySize $0", "MemoryGrow $0", "MemoryCopy $0, $0", "MemoryFill $0",
		}
	}
	return nil
}
