package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// ForeignARM64Functions is the Darwin/ARM64 compatibility routing helper.
func ForeignARM64Functions(src []byte) map[string]bool {
	return ForeignNativeFunctions(src, "arm64")
}

// TranslateNativeARM64Source is the Darwin/ARM64 compatibility entry point.
func TranslateNativeARM64Source(src []byte, imports map[string]string, pkgPath string) (string, []NativeData, error) {
	return TranslateNativeSource(src, NativeOptions{GOOS: "darwin", GOARCH: "arm64", PackagePath: pkgPath, Imports: imports})
}

type nativeARM64 struct{ *nativeEmitter }

func nativeReg(o Operand, bits int, sp bool) (string, error) {
	if o.Kind != OpReg {
		return "", fmt.Errorf("expected native register")
	}
	// The parser preserves the physical stack pointer as RSP. Plain SP is
	// Go's pseudo stack pointer and must not reach this native backend.
	if o.Reg == Reg("RSP") && sp && bits == 64 {
		return "sp", nil
	}
	if o.Reg == ZR {
		if bits == 32 {
			return "wzr", nil
		}
		return "xzr", nil
	}
	name := string(o.Reg)
	if strings.HasPrefix(name, "R") {
		if n, err := strconv.Atoi(name[1:]); err == nil && n >= 0 && n <= 30 && n != 18 {
			prefix := "x"
			if bits == 32 {
				prefix = "w"
			}
			return fmt.Sprintf("%s%d", prefix, n), nil
		}
	}
	return "", fmt.Errorf("unsupported native register %s", o.Reg)
}
func nativeFPReg(o Operand) (string, error) {
	if o.Kind == OpReg && strings.HasPrefix(string(o.Reg), "F") {
		if n, err := strconv.Atoi(string(o.Reg)[1:]); err == nil && n >= 0 && n < 32 {
			return fmt.Sprintf("d%d", n), nil
		}
	}
	return "", fmt.Errorf("expected native floating register")
}
func nativeMemory(o Operand, width int) (string, bool, error) {
	m := o.Mem
	if o.Kind != OpMem || m.Sym != "" || m.OffRaw != "" || m.Index != "" || m.Segment != "" {
		return "", false, fmt.Errorf("native memory requires a constant offset and one base register")
	}
	base, err := nativeReg(Operand{Kind: OpReg, Reg: m.Base}, 64, true)
	if err != nil || base == "xzr" {
		return "", false, fmt.Errorf("invalid native memory base")
	}
	unscaled := false
	if m.Off < 0 || m.Off%int64(width) != 0 || m.Off/int64(width) > 4095 {
		if m.Off < -256 || m.Off > 255 {
			return "", false, fmt.Errorf("native memory offset requires unsupported address expansion")
		}
		unscaled = true
	}
	return fmt.Sprintf("[%s, #%d]", base, m.Off), unscaled, nil
}
func (e *nativeARM64) instruction(out *strings.Builder, ins Instr) error {
	a := ins.Args
	op := string(ins.Op)
	if ins.Op != OpTEXT && ins.Op != OpLABEL {
		_, rest := splitOpcode(ins.Raw)
		parts := splitTopLevelCSV(rest)
		if len(parts) != len(a) {
			return fmt.Errorf("invalid native operand list")
		}
		for i, operand := range a {
			if operand.Kind == OpImm {
				if _, ok := nativeInteger(strings.TrimSpace(parts[i])); !ok {
					return fmt.Errorf("native operand requires a constant integer")
				}
			}
		}
	}

	emit := func(op string, args ...string) { fmt.Fprintf(out, "\t%s %s\n", op, strings.Join(args, ", ")) }
	bad := func() error { return fmt.Errorf("unsupported native operand form for %s", op) }
	switch op {
	case "TEXT":
		return nil
	case "LABEL":
		fmt.Fprintf(out, "%s:\n", e.labels[a[0].Sym])
		return nil
	case "RET":
		if len(a) != 0 {
			return bad()
		}
		emit("ret")
		return nil
	case "JMP", "B", "BL", "CALL":
		if len(a) != 1 {
			return bad()
		}
		dst, err := e.branch(a[0], true)
		if err != nil {
			return err
		}
		inst := "b"
		if op == "BL" || op == "CALL" {
			inst = "bl"
		}
		emit(inst, dst)
		return nil
	case "BEQ", "BNE", "BLT", "BLE", "BGT", "BGE", "BHS", "BLO", "BHI", "BLS", "BMI", "BPL", "BVS", "BVC":
		if len(a) != 1 {
			return bad()
		}
		dst, err := e.branch(a[0], false)
		if err != nil {
			return err
		}
		emit("b."+strings.ToLower(op[1:]), dst)
		return nil
	case "CBZ", "CBNZ":
		if len(a) != 2 {
			return bad()
		}
		reg, err := nativeReg(a[0], 64, false)
		if err != nil {
			return err
		}
		dst, err := e.branch(a[1], false)
		if err != nil {
			return err
		}
		emit(strings.ToLower(op), reg, dst)
		return nil
	case "MOVD", "MOVW", "MOVWU":
		if len(a) != 2 {
			return bad()
		}
		width := 8
		if op != "MOVD" {
			width = 4
		}
		if a[0].Kind == OpMem || a[1].Kind == OpMem {
			mem, reg := a[0], a[1]
			load := true
			if a[1].Kind == OpMem {
				mem, reg = a[1], a[0]
				load = false
			}
			bits := width * 8
			if load && op == "MOVW" {
				bits = 64
			}
			r, err := nativeReg(reg, bits, false)
			if err != nil {
				return err
			}
			addr, unscaled, err := nativeMemory(mem, width)
			if err != nil {
				return err
			}
			inst := "ldr"
			if !load {
				inst = "str"
			}
			if unscaled {
				if load {
					inst = "ldur"
				} else {
					inst = "stur"
				}
			}
			if load && op == "MOVW" {
				inst += "sw"
			}
			emit(inst, r, addr)
			return nil
		}
		dst, err := nativeReg(a[1], 64, op == "MOVD")
		if err != nil {
			return err
		}
		if a[0].Kind == OpImm {
			if op != "MOVD" || dst == "sp" || a[0].ImmRaw != "" {
				return bad()
			}
			// MOVD constant expansion uses only the destination; it never clobbers
			// a hidden scratch register or the condition flags.
			v := uint64(a[0].Imm)
			emit("movz", dst, fmt.Sprintf("#%d", v&65535))
			for shift := 16; shift < 64; shift += 16 {
				if half := (v >> shift) & 65535; half != 0 {
					emit("movk", dst, fmt.Sprintf("#%d", half), fmt.Sprintf("lsl #%d", shift))
				}
			}
			return nil
		}
		bits := 64
		if op != "MOVD" {
			bits = 32
		}
		src, err := nativeReg(a[0], bits, op == "MOVD")
		if err != nil {
			return err
		}
		if op == "MOVW" {
			emit("sxtw", dst, src)
		} else if op == "MOVWU" {
			emit("uxtw", dst, src)
		} else {
			if (src == "sp" && dst == "xzr") || (src == "xzr" && dst == "sp") {
				return bad()
			}
			emit("mov", dst, src)
		}
		return nil
	case "FMOVD":
		if len(a) != 2 {
			return bad()
		}
		src, se := nativeFPReg(a[0])
		dst, de := nativeFPReg(a[1])
		if se != nil && de != nil {
			return bad()
		}
		if se != nil {
			src, se = nativeReg(a[0], 64, false)
		}
		if de != nil {
			dst, de = nativeReg(a[1], 64, false)
		}
		if se != nil || de != nil {
			return bad()
		}
		emit("fmov", dst, src)
		return nil
	case "ADD", "SUB", "CMP", "CMPW", "LSL":
		cmp := op == "CMP" || op == "CMPW"
		if len(a) != 2 && (cmp || len(a) != 3) {
			return bad()
		}
		bits := 64
		if op == "CMPW" {
			bits = 32
		}
		dstOp := a[len(a)-1]
		srcOp := dstOp
		if len(a) == 3 {
			srcOp = a[1]
		}
		allowSP := op == "ADD" || op == "SUB" || cmp
		src, err := nativeReg(srcOp, bits, allowSP)
		if err != nil {
			return err
		}
		dst, err := nativeReg(dstOp, bits, allowSP)
		if err != nil {
			return err
		}
		var rhs string
		if a[0].Kind == OpImm && a[0].ImmRaw == "" {
			limit := int64(4095)
			if op == "LSL" {
				limit = 63
			}
			if a[0].Imm < 0 || a[0].Imm > limit {
				return bad()
			}
			rhs = fmt.Sprintf("#%d", a[0].Imm)
			if src == "xzr" || src == "wzr" || (!cmp && dst == "xzr") {
				return bad()
			}
		} else {
			rhs, err = nativeReg(a[0], bits, false)
			if err != nil {
				return err
			}
			// Register ADD/SUB with SP needs explicit extended-register encoding.
			// Reject it rather than selecting an alias with different register-31 semantics.
			if src == "sp" || dst == "sp" {
				return bad()
			}
		}
		if cmp {
			emit("cmp", src, rhs)
		} else {
			emit(strings.ToLower(op), dst, src, rhs)
		}
		return nil
	}
	return fmt.Errorf("unsupported native instruction %s", op)
}
