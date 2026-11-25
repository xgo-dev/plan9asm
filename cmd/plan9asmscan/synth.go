package main

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// scanEncoderSynthesized synthesizes canonical Plan 9 instructions from Go's
// official cmd/internal/obj encoder tables and probes every synthesized form
// through plan9asm.Parse + plan9asm.ProbeInstruction.
//
// Unlike -corpus=go-asm (which only exercises instructions present in Go's
// assembler testdata files), -corpus=encoder covers the entire encoder-table
// surface across all 5 supported architectures, exposing unobserved opcodes and
// operand-class combinations.
func scanEncoderSynthesized(goroot string, arch plan9asm.Arch, goarch string) (
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

	for _, row := range encoderCatalog {
		if isNonInstructionEncoderOp(row.Opcode) {
			continue
		}
		tableLabel := "encoder"
		if len(row.Tables) > 0 {
			tableLabel = row.Tables[0]
		}
		tablesSeen[tableLabel] = struct{}{}

		lines := synthesizeEncoderLines(goarch, row)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if _, dup := seenLines[line]; dup {
				continue
			}
			seenLines[line] = struct{}{}

			probeSrc := "TEXT plan9asm_probe(SB),NOSPLIT,$0\n" + line + "\nRET\n"
			file, err := plan9asm.Parse(arch, probeSrc)
			if err != nil {
				parseErrs = append(parseErrs, parseErr{
					File: tableLabel + ":" + row.Form,
					Err:  fmt.Sprintf("%s -> %v", line, err),
				})
				continue
			}
			for _, fn := range file.Funcs {
				for i, ins := range fn.Instrs {
					if i == len(fn.Instrs)-1 && ins.Op == plan9asm.OpRET {
						continue
					}
					if ins.Op == plan9asm.OpLABEL || ins.Op == plan9asm.OpTEXT {
						continue
					}
					addOpStat(ops, string(ins.Op), tableLabel, "encoder-synth", 1)
					addFormStat(forms, arch, goarch, ins, tableLabel)
				}
			}
		}
	}
	return ops, forms, parseErrs, len(tablesSeen), encoderCatalog, nil
}

func isNonInstructionEncoderOp(op string) bool {
	switch strings.ToUpper(strings.TrimSpace(op)) {
	case "", "XXX", "LAST", "TEXT", "DATA", "GLOBL", "FUNCDATA", "PCDATA",
		"USEFIELD", "NOPTR", "RODATA", "DUPOK", "NOSPLIT", "WRAPPER", "NEEDCTXT",
		"LOCAL", "NOPROF", "TLSBSS", "REFLECTMETHOD", "TOPFRAME", "ABIWRAPPER",
		"GETCALLERPC", "VARDEF", "VARKILL", "VARLIVE", "INIT", "HISTORY", "NAME",
		"SIGNAME", "DYNIMPORT", "DYNEXPORT", "PCALIGN", "BYTE", "WORD", "LONG",
		"QUAD", "UNDEF_DIRECTIVE":
		return true
	default:
		return false
	}
}

func synthesizeEncoderLines(goarch string, row encoderFormReport) []string {
	switch goarch {
	case "386", "amd64":
		return synthesizeX86Lines(row)
	case "arm":
		return synthesizeARMLines(row)
	case "arm64":
		return synthesizeARM64Lines(row)
	case "wasm":
		return synthesizeWASMLines(row)
	default:
		return nil
	}
}

func synthesizeX86Lines(row encoderFormReport) []string {
	op := row.Opcode
	if op == "END" {
		return nil
	}
	classes := row.OperandClasses
	if len(classes) == 0 {
		return []string{op}
	}
	if len(classes) == 1 && classes[0] == "@special" {
		switch op {
		case "ADJSP":
			return []string{"ADJSP $8"}
		case "ENTER":
			return []string{"ENTER $8, $0"}
		case "FFREE":
			return []string{"FFREE F0"}
		default:
			return []string{op}
		}
	}
	for _, cls := range classes {
		if cls == "Ytextsize" {
			return nil
		}
	}

	build := func(memSlot int) string {
		args := make([]string, 0, len(classes))
		for i, cls := range classes {
			arg, ok := synthX86Operand(cls, i, i == memSlot)
			if !ok {
				return ""
			}
			args = append(args, arg)
		}
		if len(args) == 0 {
			return op
		}
		return op + " " + strings.Join(args, ", ")
	}

	out := []string{}
	if line := build(-1); line != "" {
		out = append(out, line)
	}
	// If any operand class allows both register and memory (Yml/Ymb/Yxm/Yym/Yzm/Ymm/Ykm),
	// also synthesize the memory variant on the first dual slot so both reg and mem forms
	// are probed.
	for i, cls := range classes {
		if isX86RegOrMemClass(cls) {
			if line := build(i); line != "" && (len(out) == 0 || line != out[0]) {
				out = append(out, line)
			}
			break
		}
	}
	return out
}

func isX86RegOrMemClass(cls string) bool {
	switch cls {
	case "Yml", "Ymb", "Ymm", "Ykm", "Yxm", "YxmEvex", "Yym", "YymEvex", "Yzm":
		return true
	default:
		return false
	}
}

func synthX86Operand(cls string, idx int, asMem bool) (string, bool) {
	gpr := []string{"AX", "BX", "CX", "DX"}
	gpr8 := []string{"AL", "BL", "CL", "DL"}
	switch cls {
	case "Yi0":
		return "$0", true
	case "Yi1", "Yu2", "Yi8", "Yu8", "Yi32", "Yi64":
		return "$1", true
	case "Yal":
		return "AL", true
	case "Yax":
		return "AX", true
	case "Ycl":
		return "CL", true
	case "Ycx":
		return "CX", true
	case "Yrb":
		return gpr8[idx%len(gpr8)], true
	case "Yrl", "Yrx":
		return gpr[idx%len(gpr)], true
	case "Ymb":
		if asMem {
			return "8(BX)", true
		}
		return gpr8[idx%len(gpr8)], true
	case "Yml":
		if asMem {
			return "8(BX)", true
		}
		return gpr[idx%len(gpr)], true
	case "Ym":
		return "8(BX)", true
	case "Yiauto":
		return "$a+0(FP)", true
	case "Ytls":
		return "0(TLS)", true
	case "Yindir":
		return "AX", true
	case "Ybr":
		return "target", true
	case "Yf0":
		return "F0", true
	case "Yrf":
		return fmt.Sprintf("F%d", idx%2), true
	case "Ymr":
		return fmt.Sprintf("M%d", idx%4), true
	case "Ymm":
		if asMem {
			return "8(BX)", true
		}
		return fmt.Sprintf("M%d", idx%4), true
	case "Yxr0":
		return "X0", true
	case "Yxr", "YxrEvex", "YxrEvexMulti4":
		return fmt.Sprintf("X%d", idx%4), true
	case "Yxm", "YxmEvex":
		if asMem {
			return "8(BX)", true
		}
		return fmt.Sprintf("X%d", idx%4), true
	case "Yyr", "YyrEvex":
		return fmt.Sprintf("Y%d", idx%4), true
	case "Yym", "YymEvex":
		if asMem {
			return "8(BX)", true
		}
		return fmt.Sprintf("Y%d", idx%4), true
	case "Yzr", "YzrMulti4":
		return fmt.Sprintf("Z%d", idx%4), true
	case "Yzm":
		if asMem {
			return "8(BX)", true
		}
		return fmt.Sprintf("Z%d", idx%4), true
	case "Yxvm", "YxvmEvex":
		return "(BX)(X0*4)", true
	case "Yyvm", "YyvmEvex":
		return "(BX)(Y0*4)", true
	case "Yzvm":
		return "(BX)(Z0*4)", true
	case "Yk", "Yknot0":
		return fmt.Sprintf("K%d", (idx%3)+1), true
	case "Ykm":
		if asMem {
			return "8(BX)", true
		}
		return fmt.Sprintf("K%d", (idx%3)+1), true
	case "Ycr0", "Ycr2", "Ycr3", "Ycr4", "Ycr8":
		return "CR" + strings.TrimPrefix(cls, "Ycr"), true
	case "Ydr0", "Ydr2", "Ydr3", "Ydr6", "Ydr7":
		return "DR" + strings.TrimPrefix(cls, "Ydr"), true
	case "Ytr6", "Ytr7":
		return "TR" + strings.TrimPrefix(cls, "Ytr"), true
	case "Ycs", "Yds", "Yes", "Yfs", "Ygs", "Yss":
		return strings.ToUpper(strings.TrimPrefix(cls, "Y")), true
	case "Ygdtr", "Yidtr", "Yldtr", "Ymsw", "Ytask":
		return strings.ToUpper(strings.TrimPrefix(cls, "Y")), true
	default:
		return "", false
	}
}

func synthesizeARMLines(row encoderFormReport) []string {
	op := row.Opcode
	if op == "END" {
		return nil
	}
	if len(row.OperandClasses) == 0 {
		return []string{op}
	}
	args := make([]string, 0, len(row.OperandClasses))
	for i, entry := range row.OperandClasses {
		_, cls, ok := strings.Cut(entry, "=")
		if !ok {
			cls = entry
		}
		if cls == "C_TEXTSIZE" {
			return nil
		}
		arg, ok := synthARMOperand(cls, i)
		if !ok {
			return nil
		}
		args = append(args, arg)
	}
	return []string{op + " " + strings.Join(args, ", ")}
}

func synthARMOperand(cls string, idx int) (string, bool) {
	switch cls {
	case "C_REG", "C_SPR":
		return fmt.Sprintf("R%d", idx%4), true
	case "C_FREG":
		return fmt.Sprintf("F%d", idx%4), true
	case "C_RCON", "C_SCON", "C_LCON", "C_NCON", "C_RCON2A", "C_RCON2S":
		return "$4", true
	case "C_SFCON", "C_ZFCON":
		return "$1.0", true
	case "C_SHIFT":
		return "R1<<1", true
	case "C_SHIFTADDR":
		return "(R1)(R2<<1)", true
	case "C_SOREG", "C_LOREG", "C_FOREG", "C_HOREG", "C_ROREG":
		return "4(R1)", true
	case "C_SAUTO", "C_LAUTO", "C_FAUTO", "C_HAUTO":
		return "a+0(FP)", true
	case "C_ADDR", "C_TLS_IE", "C_TLS_LE":
		return "sym(SB)", true
	case "C_LACON", "C_RACON", "C_LCONADDR":
		return "$sym(SB)", true
	case "C_REGLIST":
		return "[R0,R1]", true
	case "C_REGREG":
		return "(R0, R1)", true
	case "C_REGREG2":
		return "R0, R1", true
	case "C_SBRA":
		return "target", true
	case "C_PSR":
		return "CPSR", true
	case "C_FCR":
		return "FPSR", true
	default:
		return "", false
	}
}

func synthesizeARM64Lines(row encoderFormReport) []string {
	op := row.Opcode
	if op == "END" {
		return nil
	}
	if len(row.OperandClasses) == 0 {
		return []string{op}
	}
	if len(row.OperandClasses) == 1 && strings.HasPrefix(row.OperandClasses[0], "args=") {
		return synthesizeARM64InstGenLines(op, strings.TrimPrefix(row.OperandClasses[0], "args="))
	}
	args := make([]string, 0, len(row.OperandClasses))
	for i, entry := range row.OperandClasses {
		role, cls, ok := strings.Cut(entry, "=")
		if !ok {
			cls = entry
		}
		// Go 1.20/1.21 arm64 Optab had 4 operand columns (from, reg, from3, to)
		// followed by a numeric type_ column, which scanFixedEncoderTable parses
		// as to2=<number>. Ignore non-C_* to2 entries for cross-Go compatibility.
		if role == "to2" && !strings.HasPrefix(cls, "C_") {
			continue
		}
		if cls == "C_TEXTSIZE" {
			return nil
		}
		arg, ok := synthARM64OptabOperand(op, cls, i)
		if !ok {
			return nil
		}
		args = append(args, arg)
	}
	if len(args) == 0 {
		return []string{op}
	}
	return []string{op + " " + strings.Join(args, ", ")}
}

func synthARM64OptabOperand(op, cls string, idx int) (string, bool) {
	switch cls {
	case "C_ZREG", "C_REG":
		return fmt.Sprintf("R%d", idx%4), true
	case "C_RSP":
		return "RSP", true
	case "C_FREG":
		return fmt.Sprintf("F%d", idx%4), true
	case "C_VREG":
		return fmt.Sprintf("V%d", idx%4), true
	case "C_ARNG":
		return fmt.Sprintf("V%d.B16", idx%4), true
	case "C_ELEM":
		return fmt.Sprintf("V%d.B[0]", idx%4), true
	case "C_LIST":
		return "[V0.B16, V1.B16]", true
	case "C_PAIR":
		if strings.HasPrefix(op, "F") {
			return "(F0, F1)", true
		}
		return "(R0, R1)", true
	case "C_COND":
		return "EQ", true
	case "C_SHIFT":
		return "R1<<1", true
	case "C_EXTREG":
		return "R1.UXTW", true
	case "C_ZCON":
		return "$0", true
	case "C_ADDCON", "C_ADDCON2", "C_BITCON", "C_MOVCON", "C_MOVCON2", "C_MOVCON3", "C_MBCON", "C_LCON", "C_VCON", "C_NCON", "C_SCON", "C_RCON", "C_CON":
		return "$4", true
	case "C_FCON", "C_SFCON", "C_ZFCON":
		return "$1.0", true
	case "C_ZOREG":
		return "(R1)", true
	case "C_ROFF":
		return "(R1)(R2)", true
	case "C_ADDR", "C_GOTADDR", "C_TLS_IE", "C_TLS_LE", "C_LEXT":
		return "sym(SB)", true
	case "C_AACON", "C_AACON2", "C_LACON", "C_VCONADDR", "C_LCONADDR":
		return "$sym(SB)", true
	case "C_SBRA":
		return "target", true
	case "C_SPR":
		return "NZCV", true
	case "C_SPOP":
		return "ISH", true
	default:
		switch {
		case strings.Contains(cls, "AUTO"):
			return "a+0(FP)", true
		case strings.Contains(cls, "OREG"):
			return "8(R1)", true
		case strings.Contains(cls, "CON"):
			return "$4", true
		default:
			return "", false
		}
	}
}

func synthesizeARM64InstGenLines(op, spec string) []string {
	rawParts := strings.Split(spec, "__")
	args := make([]string, 0, len(rawParts))
	zIdx, pIdx, rIdx, vIdx := 0, 0, 0, 0
	for _, raw := range rawParts {
		tok := strings.Trim(raw, "_")
		if tok == "" {
			continue
		}
		// Skip disambiguator/modifier tokens that are folded into adjacent operands
		// in Go's inst_gen naming convention.
		if isInstGenModifierToken(tok) {
			continue
		}
		arg := synthARM64InstGenToken(tok, &zIdx, &pIdx, &rIdx, &vIdx)
		if arg == "" {
			continue
		}
		args = append(args, arg)
	}
	if len(args) == 0 {
		return []string{op}
	}
	return []string{op + " " + strings.Join(args, ", ")}
}

func isInstGenModifierToken(tok string) bool {
	if len(tok) == 1 && tok[0] >= '0' && tok[0] <= '9' {
		return true
	}
	switch tok {
	case "V2", "MUL_VL", "mod", "shift", "mod_amount":
		return true
	}
	return strings.HasPrefix(tok, "LSL_") || strings.HasPrefix(tok, "mod_") || strings.HasPrefix(tok, "UXTW") || strings.HasPrefix(tok, "SXTW")
}

func synthARM64InstGenToken(tok string, zIdx, pIdx, rIdx, vIdx *int) string {
	switch {
	case tok == "cimm" || tok == "cconst" || tok == "const" || tok == "vl" || tok == "imm" || tok == "amount" || tok == "pattern" || tok == "fbits":
		return "$1"
	case tok == "prfop":
		return "PLDL1KEEP"
	case tok == "PgM":
		return "P0.M"
	case tok == "PgZ" || tok == "PgZM":
		return "P0.Z"
	case tok == "Pg" || tok == "Pv" || tok == "Pt":
		return "P0"
	case tok == "PNgZ":
		return "PN0.Z"
	case tok == "PNg":
		return "PN0"
	case strings.HasPrefix(tok, "PN"):
		reg := fmt.Sprintf("PN%d", (*pIdx)%4)
		*pIdx++
		return reg + arm64InstGenElemSuffix(tok, ".B")
	case strings.HasPrefix(tok, "P") && len(tok) >= 2 && (tok[1] == 'd' || tok[1] == 'n' || tok[1] == 'm' || tok[1] == 't'):
		reg := fmt.Sprintf("P%d", (*pIdx)%4)
		*pIdx++
		return reg + arm64InstGenElemSuffix(tok, ".B")
	case strings.HasPrefix(tok, "Z"):
		// Handle multi-vector list tokens like Zt1_B_Zt2_B
		if strings.Contains(tok, "_Zt2") || strings.Contains(tok, "_Zn2") || strings.Contains(tok, "_Zd2") {
			suf := arm64InstGenElemSuffix(tok, ".S")
			a := fmt.Sprintf("Z%d%s", (*zIdx)%8, suf)
			b := fmt.Sprintf("Z%d%s", (*zIdx+1)%8, suf)
			*zIdx += 2
			return "[" + a + ", " + b + "]"
		}
		reg := fmt.Sprintf("Z%d", (*zIdx)%8)
		*zIdx++
		suf := arm64InstGenElemSuffix(tok, ".S")
		if strings.HasSuffix(tok, "_imm") || strings.HasSuffix(tok, "_index") {
			return reg + suf + "[0]"
		}
		return reg + suf
	case strings.HasPrefix(tok, "V"):
		reg := fmt.Sprintf("V%d", (*vIdx)%4)
		*vIdx++
		if strings.Contains(tok, "_T") || strings.HasSuffix(tok, "_B") || strings.HasSuffix(tok, "_H") || strings.HasSuffix(tok, "_S") || strings.HasSuffix(tok, "_D") {
			return reg + ".S4"
		}
		return reg
	case strings.HasPrefix(tok, "X") || strings.HasPrefix(tok, "W") || strings.HasPrefix(tok, "R"):
		reg := fmt.Sprintf("R%d", (*rIdx)%4)
		*rIdx++
		return reg
	default:
		return "$1"
	}
}

func arm64InstGenElemSuffix(tok, def string) string {
	for _, s := range []struct{ pat, out string }{
		{"_B", ".B"},
		{"_H", ".H"},
		{"_S", ".S"},
		{"_D", ".D"},
		{"_Q", ".Q"},
	} {
		if strings.HasSuffix(tok, s.pat) || strings.Contains(tok, s.pat+"_") {
			return s.out
		}
	}
	return def
}

func synthesizeWASMLines(row encoderFormReport) []string {
	op := row.Opcode
	switch op {
	case "I32CONST", "I64CONST":
		return []string{op + " $1"}
	case "F32CONST", "F64CONST":
		return []string{op + " $1.0"}
	case "V128CONST":
		return []string{op + " $0, $0"}
	case "GET", "SET", "TEE", "LOCALGET", "LOCALSET", "LOCALTEE", "GLOBALGET", "GLOBALSET":
		return []string{op + " R0"}
	case "BR", "BRIF", "BRTABLE":
		return []string{op + " 0"}
	case "CALL":
		return []string{op + " sym(SB)"}
	case "MOVD", "MOVW", "MOVH", "MOVB":
		return []string{op + " R0, R1"}
	case "MEMORYGROW", "MEMORYSIZE", "MEMORYCOPY", "MEMORYFILL":
		return []string{op + " $0"}
	}
	if strings.Contains(op, "LOAD") || strings.Contains(op, "STORE") {
		return []string{op + " $0"}
	}
	return []string{op}
}
