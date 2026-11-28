package arm64

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// M5 extended ARM64 specs covering unobserved Go encoder-table opcodes and
// high-frequency x/arch ARM64 Plan 9 families using 100% target-independent LLVM IR.
var arm64M5ExtSpecs = []asm.OpSpec{
	// Scalar remainder & 32-bit negate
	{Op: "REM", Family: asm.FamilyMulDiv, Width: 64, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "srem"},
	{Op: "REMW", Family: asm.FamilyMulDiv, Width: 32, Signed: true, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "srem"},
	{Op: "UREM", Family: asm.FamilyMulDiv, Width: 64, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "urem"},
	{Op: "UREMW", Family: asm.FamilyMulDiv, Width: 32, ThreeOp: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "urem"},
	{Op: "NEGW", Family: asm.FamilyALU, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "negw"},

	// 64-bit zero-extend & immediate moves
	{Op: "UXTB", Family: asm.FamilyMove, Width: 64, SrcWidth: 8, Effect: asm.EffectWriteOnly, LLVMOp: "uext"},
	{Op: "UXTH", Family: asm.FamilyMove, Width: 64, SrcWidth: 16, Effect: asm.EffectWriteOnly, LLVMOp: "uext"},
	{Op: "UXTW", Family: asm.FamilyMove, Width: 64, SrcWidth: 32, Effect: asm.EffectWriteOnly, LLVMOp: "uext"},
	{Op: "MOVN", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "movn"},
	{Op: "MOVNW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movn"},
	{Op: "MOVZ", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "movz"},
	{Op: "MOVZW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movz"},

	// Bitfield move family (BFM/SBFM/UBFM)
	{Op: "BFM", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectReadWrite, LLVMOp: "bfm"},
	{Op: "BFMW", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectReadWrite, LLVMOp: "bfm"},
	{Op: "SBFM", Family: asm.FamilyBit, Width: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "sbfm"},
	{Op: "SBFMW", Family: asm.FamilyBit, Width: 32, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "sbfm"},
	{Op: "UBFM", Family: asm.FamilyBit, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "ubfm"},
	{Op: "UBFMW", Family: asm.FamilyBit, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ubfm"},

	// FP precision conversions (including IEEE FP16 half)
	{Op: "FCVTSD", Family: asm.FamilyFP, Width: 64, SrcWidth: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvt"},
	{Op: "FCVTDS", Family: asm.FamilyFP, Width: 32, SrcWidth: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvt"},
	{Op: "FCVTSH", Family: asm.FamilyFP, Width: 16, SrcWidth: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvt"},
	{Op: "FCVTHS", Family: asm.FamilyFP, Width: 32, SrcWidth: 16, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvt"},
	{Op: "FCVTDH", Family: asm.FamilyFP, Width: 16, SrcWidth: 64, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvt"},
	{Op: "FCVTHD", Family: asm.FamilyFP, Width: 64, SrcWidth: 16, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvt"},

	// Narrow 32-bit sign-extending loads & FP narrow/imm/pair moves (x/arch)
	{Op: "MOVBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movxw"},
	{Op: "MOVHW", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteZeroUpper, LLVMOp: "movxw"},
	{Op: "FMOVB", Family: asm.FamilyFP, Width: 8, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmov_narrow"},
	{Op: "FMOVH", Family: asm.FamilyFP, Width: 16, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmov_narrow"},
	{Op: "FMOV", Family: asm.FamilyFP, Width: 128, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmov_vec"},
	{Op: "LDNP", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "ldnp"},
	{Op: "LDNPW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteZeroUpper, LLVMOp: "ldnp"},
	{Op: "STNP", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "stnp"},
	{Op: "STNPW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "stnp"},

	// Rounding & fixed-point FP <-> Int conversions (x/arch)
	{Op: "FCVTAS", Family: asm.FamilyFP, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_round"},
	{Op: "FCVTAU", Family: asm.FamilyFP, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_round"},
	{Op: "FCVTMS", Family: asm.FamilyFP, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_floor"},
	{Op: "FCVTMU", Family: asm.FamilyFP, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_floor"},
	{Op: "FCVTNS", Family: asm.FamilyFP, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_even"},
	{Op: "FCVTNU", Family: asm.FamilyFP, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_even"},
	{Op: "FCVTPS", Family: asm.FamilyFP, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_ceil"},
	{Op: "FCVTPU", Family: asm.FamilyFP, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_ceil"},
	{Op: "FCVTZS", Family: asm.FamilyFP, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_trunc"},
	{Op: "FCVTZU", Family: asm.FamilyFP, Effect: asm.EffectWriteOnly, LLVMOp: "fcvti_trunc"},
	{Op: "SCVTF", Family: asm.FamilyFP, Signed: true, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "icvtf"},
	{Op: "UCVTF", Family: asm.FamilyFP, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "icvtf"},

	// Scalar/vector FP compare, FMULX, FMUL, NEON saturating doubling mul (x/arch)
	{Op: "FCMEQ", Family: asm.FamilyCompare, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcmp_mask"},
	{Op: "FCMGE", Family: asm.FamilyCompare, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcmp_mask"},
	{Op: "FCMGT", Family: asm.FamilyCompare, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcmp_mask"},
	{Op: "FMULX", Family: asm.FamilyFP, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmulx"},
	{Op: "VFMULX", Family: asm.FamilyFP, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmulx"},
	{Op: "FMUL", Family: asm.FamilyFP, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmul_vec"},
	{Op: "VSQDMLAL", Family: asm.FamilyVecFMA, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "sqdmul"},
	{Op: "VSQDMLSL", Family: asm.FamilyVecFMA, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "sqdmul"},
	{Op: "VSQDMULH", Family: asm.FamilyVecFMA, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqdmul"},
	{Op: "VSQRDMULH", Family: asm.FamilyVecFMA, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqdmul"},
	{Op: "VSQDMULL", Family: asm.FamilyVecFMA, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqdmul"},

	// Structure single-lane load/store (x/arch)
	{Op: "LD2", Family: asm.FamilyMove, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "ldn_lane"},
	{Op: "LD3", Family: asm.FamilyMove, SubOp: 3, Effect: asm.EffectWriteOnly, LLVMOp: "ldn_lane"},
	{Op: "LD4", Family: asm.FamilyMove, SubOp: 4, Effect: asm.EffectWriteOnly, LLVMOp: "ldn_lane"},
	{Op: "ST2", Family: asm.FamilyMove, SubOp: 2, Effect: asm.EffectReadOnly, LLVMOp: "stn_lane"},
	{Op: "ST3", Family: asm.FamilyMove, SubOp: 3, Effect: asm.EffectReadOnly, LLVMOp: "stn_lane"},
	{Op: "ST4", Family: asm.FamilyMove, SubOp: 4, Effect: asm.EffectReadOnly, LLVMOp: "stn_lane"},

	// System / cache / directive ops
	{Op: "AT", Family: asm.FamilySystem, Effect: asm.EffectNone, LLVMOp: "unsupported_sys"},
	{Op: "IC", Family: asm.FamilySystem, Effect: asm.EffectNone, LLVMOp: "unsupported_sys"},
	{Op: "PRFUM", Family: asm.FamilySystem, Effect: asm.EffectReadOnly, LLVMOp: "sys_nop"},
	{Op: "PCALIGNMAX", Family: asm.FamilyNOP, Effect: asm.EffectNone},
	{Op: "DWORD", Family: asm.FamilySystem, Effect: asm.EffectNone, LLVMOp: "unsupported_dword"},
}

var arm64M5ExtTable = asm.NewOpTable(arm64M5ExtSpecs)

func (c *arm64Ctx) lowerM5Ext(op asm.Op, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := arm64M5ExtTable.Lookup(op)
	if !found {
		return false, false, nil
	}
	switch spec.LLVMOp {
	case "", "sys_nop":
		return true, false, nil
	case "unsupported_sys":
		return true, false, fmt.Errorf("arm64: unsupported instruction %s (privileged cache/address-translation instruction is not modeled): %q", op, ins.Raw)
	case "unsupported_dword":
		return true, false, fmt.Errorf("arm64: unsupported instruction DWORD (raw 64-bit data/instruction directive is not modeled): %q", ins.Raw)

	case "srem", "urem":
		return true, false, c.lowerARM64ExtraMulDiv(spec, ins)

	case "negw":
		if len(ins.Args) != 1 && len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 NEGW expects 1 or 2 operands: %q", ins.Raw)
		}
		dstOp := ins.Args[len(ins.Args)-1]
		if dstOp.Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 NEGW dst must be reg: %q", ins.Raw)
		}
		src, err := c.eval32(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 0, %s\n", t, src)
		return true, false, c.storeWidth(dstOp.Reg, "%"+t, 32)

	case "uext":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		v64, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		srcTy := fmt.Sprintf("i%d", spec.SrcWidth)
		tr, ext := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", tr, v64, srcTy)
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", ext, srcTy, tr)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+ext)

	case "movn", "movz":
		if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects $imm[, $shift], dstReg: %q", op, ins.Raw)
		}
		imm := uint64(0)
		if ins.Args[0].Kind == asm.OpImm {
			imm = uint64(ins.Args[0].Imm)
		}
		if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpImm {
			imm <<= uint(ins.Args[1].Imm & 63)
		}
		if spec.LLVMOp == "movn" {
			imm = ^imm
		}
		if spec.Width == 32 {
			imm = uint64(uint32(imm))
		}
		return true, false, c.storeReg(ins.Args[len(ins.Args)-1].Reg, strconv.FormatInt(int64(imm), 10))

	case "bfm", "sbfm", "ubfm":
		if len(ins.Args) != 4 || ins.Args[0].Kind != asm.OpImm || ins.Args[2].Kind != asm.OpImm || ins.Args[3].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects $immr, Rn, $imms, Rd: %q", op, ins.Raw)
		}
		w := uint64(spec.Width)
		ty := fmt.Sprintf("i%d", spec.Width)
		immr := uint64(ins.Args[0].Imm) & (w - 1)
		imms := uint64(ins.Args[2].Imm) & (w - 1)
		src, err := c.evalWidth(ins.Args[1], spec.Width)
		if err != nil {
			return true, false, err
		}
		// Compute extracted/inserted bitfield according to AArch64 BFM/SBFM/UBFM rules.
		var out string
		if imms >= immr {
			width := imms - immr + 1
			mask := ^uint64(0)
			if width < 64 {
				mask = (uint64(1) << width) - 1
			}
			if spec.Width == 32 {
				mask &= 0xffffffff
			}
			sh := src
			if immr > 0 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", t, ty, src, immr)
				sh = "%" + t
			}
			switch spec.LLVMOp {
			case "ubfm":
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", t, ty, sh, int64(mask))
				out = "%" + t
			case "sbfm":
				top := w - (imms + 1)
				lsh := src
				if top > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", t, ty, src, top)
					lsh = "%" + t
				}
				rsh := w - width
				out = lsh
				if rsh > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", t, ty, lsh, rsh)
					out = "%" + t
				}
			default: // bfm
				dstV, err := c.evalWidth(ins.Args[3], spec.Width)
				if err != nil {
					return true, false, err
				}
				kept, ext, merged := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", kept, ty, dstV, int64(^mask))
				fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", ext, ty, sh, int64(mask))
				fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", merged, ty, kept, ext)
				out = "%" + merged
			}
		} else {
			// Insert/shift left: lsb = w - immr, width = imms + 1
			lsb := w - immr
			width := imms + 1
			mask := ^uint64(0)
			if width < 64 {
				mask = (uint64(1) << width) - 1
			}
			if spec.Width == 32 {
				mask &= 0xffffffff
			}
			masked, shifted := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", masked, ty, src, int64(mask))
			fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", shifted, ty, masked, lsb)
			switch spec.LLVMOp {
			case "ubfm":
				out = "%" + shifted
			case "sbfm":
				top := w - (lsb + width)
				lsh := "%" + shifted
				if top > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = shl %s %s, %d\n", t, ty, lsh, top)
					lsh = "%" + t
				}
				rsh := top
				out = lsh
				if rsh > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", t, ty, lsh, rsh)
					out = "%" + t
				}
			default: // bfm
				dstV, err := c.evalWidth(ins.Args[3], spec.Width)
				if err != nil {
					return true, false, err
				}
				clearMask := ^(mask << lsb)
				kept, merged := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", kept, ty, dstV, int64(clearMask))
				fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", merged, ty, kept, shifted)
				out = "%" + merged
			}
		}
		return true, false, c.storeWidth(ins.Args[3].Reg, out, spec.Width)

	case "fcvt":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Fsrc, Fdst: %q", op, ins.Raw)
		}
		fpTy := func(bits uint16) string {
			switch bits {
			case 16:
				return "half"
			case 32:
				return "float"
			default:
				return "double"
			}
		}
		var srcFP string
		if spec.SrcWidth == 16 {
			v64, err := c.eval64(ins.Args[0], false)
			if err != nil {
				return true, false, err
			}
			tr, bc := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", tr, v64)
			fmt.Fprintf(c.b, "  %%%s = bitcast i16 %%%s to half\n", bc, tr)
			srcFP = "%" + bc
		} else {
			var err error
			srcFP, err = c.evalFP(ins.Args[0], spec.SrcWidth)
			if err != nil {
				return true, false, err
			}
		}
		convOp := "fpext"
		if spec.Width < spec.SrcWidth {
			convOp = "fptrunc"
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", res, convOp, fpTy(spec.SrcWidth), srcFP, fpTy(spec.Width))
		if spec.Width == 16 {
			bc, z := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast half %%%s to i16\n", bc, res)
			fmt.Fprintf(c.b, "  %%%s = zext i16 %%%s to i64\n", z, bc)
			return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)
		}
		return true, false, c.storeFP(ins.Args[1], "%"+res, spec.Width)

	case "movxw":
		// MOVBW / MOVHW: sign-extend 8/16 bits to 32-bit, zero-extended into 64-bit reg.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		preInc := strings.Contains(strings.ToUpper(string(ins.Op)), ".W")
		bits := int(spec.SrcWidth)
		src, dst := ins.Args[0], ins.Args[1]
		var raw64 string
		var err error
		if src.Kind == asm.OpMem {
			if preInc {
				addr, base, _, aerr := c.addrI64(src.Mem, false)
				if aerr != nil {
					return true, false, aerr
				}
				if err := c.storeReg(base, addr); err != nil {
					return true, false, err
				}
				pt, ld, z := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
				fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %%%s, align 1\n", ld, bits, pt)
				fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, bits, ld)
				raw64 = "%" + z
			} else {
				raw64, err = c.loadMem(src.Mem, bits, postInc)
			}
		} else {
			raw64, err = c.eval64(src, false)
		}
		if err != nil {
			return true, false, err
		}
		if dst.Kind == asm.OpReg {
			tr, se, z := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, raw64, bits)
			fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", se, bits, tr)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, se)
			return true, false, c.storeReg(dst.Reg, "%"+z)
		}
		if dst.Kind == asm.OpMem {
			return true, false, c.storeMem(dst.Mem, bits, postInc, raw64)
		}
		return true, false, fmt.Errorf("arm64 %s unsupported dst: %q", op, ins.Raw)

	case "fmov_narrow":
		// FMOVB / FMOVH: 8/16-bit FP reg <-> mem/reg move (supports .P/.W).
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		preInc := strings.Contains(strings.ToUpper(string(ins.Op)), ".W")
		bits := int(spec.Width)
		src, dst := ins.Args[0], ins.Args[1]
		var raw64 string
		var err error
		switch src.Kind {
		case asm.OpMem:
			if preInc {
				addr, base, _, aerr := c.addrI64(src.Mem, false)
				if aerr != nil {
					return true, false, aerr
				}
				if err := c.storeReg(base, addr); err != nil {
					return true, false, err
				}
				pt, ld, z := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
				fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %%%s, align 1\n", ld, bits, pt)
				fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, bits, ld)
				raw64 = "%" + z
			} else {
				raw64, err = c.loadMem(src.Mem, bits, postInc)
			}
		case asm.OpSym:
			if fv, ok := arm64ParseDollarFloatFlex(src.Sym); ok {
				raw64 = strconv.FormatUint(uint64(math.Float32bits(float32(fv)))>>16, 10)
			} else {
				p, perr := c.ptrFromSB(src.Sym)
				if perr != nil {
					return true, false, perr
				}
				ld, z := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", ld, bits, p)
				fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, bits, ld)
				raw64 = "%" + z
			}
		default:
			raw64, err = c.eval64(src, false)
		}
		if err != nil {
			return true, false, err
		}
		switch dst.Kind {
		case asm.OpReg:
			tr, z := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, raw64, bits)
			fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, bits, tr)
			return true, false, c.storeReg(dst.Reg, "%"+z)
		case asm.OpMem:
			if preInc {
				addr, base, _, aerr := c.addrI64(dst.Mem, false)
				if aerr != nil {
					return true, false, aerr
				}
				if err := c.storeReg(base, addr); err != nil {
					return true, false, err
				}
				pt, tr := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, addr)
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, raw64, bits)
				fmt.Fprintf(c.b, "  store i%d %%%s, ptr %%%s, align 1\n", bits, tr, pt)
				return true, false, nil
			}
			return true, false, c.storeMem(dst.Mem, bits, postInc, raw64)
		default:
			return true, false, fmt.Errorf("arm64 %s unsupported dst: %q", op, ins.Raw)
		}

	case "fmov_vec":
		// FMOV $imm, Vd.S4/D2/S2/H8 OR FMOV Vn.D[idx], Rd
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 FMOV expects src, dst: %q", ins.Raw)
		}
		if ins.Args[0].Kind == asm.OpReg && strings.Contains(string(ins.Args[0].Reg), "[") {
			bits, err := c.arm64ExtractVecLaneI64(ins.Args[0].Reg, 64)
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeReg(ins.Args[1].Reg, bits)
		}
		sh := parseNEONShape(ins.Args[1].Reg, false)
		fv := 0.0
		if ins.Args[0].Kind == asm.OpImm {
			fv = float64(ins.Args[0].Imm)
		} else if ins.Args[0].Kind == asm.OpSym {
			if f, ok := arm64ParseDollarFloatFlex(ins.Args[0].Sym); ok {
				fv = f
			}
		}
		var elemBitsVal int64
		if sh.elemBits == 64 {
			elemBitsVal = int64(math.Float64bits(fv))
		} else {
			elemBitsVal = int64(int32(math.Float32bits(float32(fv))))
		}
		splat := arm64IntSplat(sh.lanes, sh.elemBits, elemBitsVal)
		return true, false, c.storeVShape(ins.Args[1].Reg, splat, sh)

	case "ldnp", "stnp":
		// Non-temporal pair load/store (accepts 2-arg (r1, r2) and 3-arg mem, r1, r2 forms).
		elemBytes := int64(spec.Width / 8)
		elemTy := fmt.Sprintf("i%d", spec.Width)
		if spec.LLVMOp == "ldnp" {
			var regs []asm.Reg
			if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpRegList && len(ins.Args[1].RegList) == 2 {
				regs = ins.Args[1].RegList
			} else if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
				regs = []asm.Reg{ins.Args[1].Reg, ins.Args[2].Reg}
			} else {
				return true, false, fmt.Errorf("arm64 %s expects mem, (r1, r2): %q", op, ins.Raw)
			}
			ptr, _, _, _, err := c.arm64PairPtr(ins.Args[0], false, false)
			if err != nil {
				return true, false, err
			}
			for i, r := range regs {
				p := ptr
				if i != 0 {
					gp := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", gp, ptr, elemBytes)
					p = "%" + gp
				}
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, elemTy, p)
				val := "%" + ld
				if spec.Width == 32 {
					z := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, ld)
					val = "%" + z
				}
				if err := c.storeReg(r, val); err != nil {
					return true, false, err
				}
			}
			return true, false, nil
		}
		var memOp asm.Operand
		var regs []asm.Reg
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpRegList && len(ins.Args[0].RegList) == 2 {
			regs, memOp = ins.Args[0].RegList, ins.Args[1]
		} else if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpMem && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
			memOp, regs = ins.Args[0], []asm.Reg{ins.Args[1].Reg, ins.Args[2].Reg}
		} else if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpMem {
			regs, memOp = []asm.Reg{ins.Args[0].Reg, ins.Args[1].Reg}, ins.Args[2]
		} else {
			return true, false, fmt.Errorf("arm64 %s expects (r1, r2), mem: %q", op, ins.Raw)
		}
		ptr, _, _, _, err := c.arm64PairPtr(memOp, false, false)
		if err != nil {
			return true, false, err
		}
		for i, r := range regs {
			p := ptr
			if i != 0 {
				gp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", gp, ptr, elemBytes)
				p = "%" + gp
			}
			v, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			sv := v
			if spec.Width == 32 {
				tr := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v)
				sv = "%" + tr
			}
			fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", elemTy, sv, p)
		}
		return true, false, nil

	case "fcvti_round", "fcvti_floor", "fcvti_even", "fcvti_ceil", "fcvti_trunc":
		// FCVT{A,M,N,P,Z}{S,U} [$fbits,] Fsrc/Vsrc, Rd/Vd
		var fbits int64
		var srcOp, dstOp asm.Operand
		if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpImm {
			fbits = ins.Args[0].Imm
			srcOp, dstOp = ins.Args[1], ins.Args[2]
		} else if len(ins.Args) == 2 {
			srcOp, dstOp = ins.Args[0], ins.Args[1]
		} else {
			return true, false, fmt.Errorf("arm64 %s expects [$fbits,] Fsrc, Rd: %q", op, ins.Raw)
		}
		if dstOp.Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s dst must be reg: %q", op, ins.Raw)
		}
		if _, ok := arm64ParseVReg(dstOp.Reg); ok {
			return true, false, c.lowerARM64VecFCVTInt(spec.LLVMOp, spec.Signed, fbits, srcOp, dstOp.Reg)
		}
		v, err := c.evalF64(srcOp)
		if err != nil {
			return true, false, err
		}
		if fbits > 0 {
			scale := math.Ldexp(1.0, int(fbits))
			sc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", sc, v, asm.FormatLLVMFloat64Literal(scale))
			v = "%" + sc
		}
		switch spec.LLVMOp {
		case "fcvti_round":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.round.f64(double %s)\n", t, v)
			v = "%" + t
		case "fcvti_floor":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.floor.f64(double %s)\n", t, v)
			v = "%" + t
		case "fcvti_even":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.roundeven.f64(double %s)\n", t, v)
			v = "%" + t
		case "fcvti_ceil":
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.ceil.f64(double %s)\n", t, v)
			v = "%" + t
		}
		return true, false, c.storeReg(dstOp.Reg, c.floatToInt(spec.Signed, "i64", "i64", "double", "f64", v))

	case "icvtf":
		// SCVTF / UCVTF [$fbits,] Rsrc/Vsrc, Fdst/Vdst
		var fbits int64
		var srcOp, dstOp asm.Operand
		if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpImm {
			fbits = ins.Args[0].Imm
			srcOp, dstOp = ins.Args[1], ins.Args[2]
		} else if len(ins.Args) == 2 {
			srcOp, dstOp = ins.Args[0], ins.Args[1]
		} else {
			return true, false, fmt.Errorf("arm64 %s expects [$fbits,] Rsrc, Fdst: %q", op, ins.Raw)
		}
		if dstOp.Kind == asm.OpReg {
			if _, ok := arm64ParseVReg(dstOp.Reg); ok {
				return true, false, c.lowerARM64VecIntCVTF(spec.Signed, fbits, srcOp, dstOp.Reg)
			}
		}
		iv, err := c.eval64(srcOp, false)
		if err != nil {
			return true, false, err
		}
		conv := "uitofp"
		if spec.Signed {
			conv = "sitofp"
		}
		fv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s to double\n", fv, conv, iv)
		out := "%" + fv
		if fbits > 0 {
			scale := math.Ldexp(1.0, -int(fbits))
			sc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", sc, out, asm.FormatLLVMFloat64Literal(scale))
			out = "%" + sc
		}
		return true, false, c.storeF64(dstOp, out)

	case "fcmp_mask":
		// Scalar FCMEQ/FCMGE/FCMGT Fa, Fb, Fd (or Fa, $0, Fd) -> all-1s/0 mask in Fd
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects src1, src2, dst: %q", op, ins.Raw)
		}
		pred := "oeq"
		if op == "FCMGE" {
			pred = "oge"
		} else if op == "FCMGT" {
			pred = "ogt"
		}
		rhs, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		lhs, err := c.evalF64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		cmp, mask := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s double %s, %s\n", cmp, pred, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = sext i1 %%%s to i64\n", mask, cmp)
		return true, false, c.storeReg(ins.Args[2].Reg, "%"+mask)

	case "fmulx", "fmul_vec":
		// Scalar or vector FMULX / VFMULX / FMUL (incl. indexed Vm.S[idx])
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects src1, src2, dst: %q", op, ins.Raw)
		}
		if _, ok := arm64ParseVReg(ins.Args[2].Reg); ok {
			sh := parseNEONShape(ins.Args[2].Reg, false)
			if sh.elemBits != 32 && sh.elemBits != 64 {
				sh = parseNEONShape("V0.S4", false)
			}
			a, err := c.loadVShapeOperand(ins.Args[0], sh)
			if err != nil {
				return true, false, err
			}
			b, err := c.loadVShapeOperand(ins.Args[1], sh)
			if err != nil {
				return true, false, err
			}
			fpElem := "float"
			if sh.elemBits == 64 {
				fpElem = "double"
			}
			fpVecTy := fmt.Sprintf("<%d x %s>", sh.lanes, fpElem)
			af, bf, m, back := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", af, sh.vecTy(), a, fpVecTy)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", bf, sh.vecTy(), b, fpVecTy)
			fmt.Fprintf(c.b, "  %%%s = fmul %s %%%s, %%%s\n", m, fpVecTy, bf, af)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", back, fpVecTy, m, sh.vecTy())
			return true, false, c.storeVShape(ins.Args[2].Reg, "%"+back, sh)
		}
		a, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		b, err := c.evalF64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		m := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", m, b, a)
		return true, false, c.storeF64(ins.Args[2], "%"+m)

	case "sqdmul":
		// VSQDMLAL/VSQDMLSL/VSQDMULH/VSQRDMULH/VSQDMULL (vector or scalar V-regs)
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects src1, src2, dst: %q", op, ins.Raw)
		}
		sh := parseNEONShape(ins.Args[2].Reg, false)
		a, err := c.loadVShapeOperand(ins.Args[0], sh)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadVShapeOperand(ins.Args[1], sh)
		if err != nil {
			return true, false, err
		}
		wideBits := sh.elemBits * 2
		wideTy := fmt.Sprintf("<%d x i%d>", sh.lanes, wideBits)
		aw, bw, prod, dbl := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", aw, sh.vecTy(), a, wideTy)
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", bw, sh.vecTy(), b, wideTy)
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", prod, wideTy, aw, bw)
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", dbl, wideTy, prod, arm64IntSplat(sh.lanes, wideBits, 1))
		valW := "%" + dbl
		if op == "VSQRDMULH" {
			rd := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rd, wideTy, valW, arm64IntSplat(sh.lanes, wideBits, int64(1)<<uint(sh.elemBits-1)))
			valW = "%" + rd
		}
		var out string
		if op == "VSQDMULH" || op == "VSQRDMULH" {
			hi, tr := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", hi, wideTy, valW, arm64IntSplat(sh.lanes, wideBits, int64(sh.elemBits)))
			fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, wideTy, hi, sh.vecTy())
			out = "%" + tr
		} else {
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", tr, wideTy, valW, sh.vecTy())
			out = "%" + tr
			if op == "VSQDMLAL" || op == "VSQDMLSL" {
				acc, err := c.loadVShape(ins.Args[2].Reg, sh)
				if err != nil {
					return true, false, err
				}
				res := c.newTmp()
				intr := "@llvm.sadd.sat."
				if op == "VSQDMLSL" {
					intr = "@llvm.ssub.sat."
				}
				fmt.Fprintf(c.b, "  %%%s = call %s %sv%di%d(%s %s, %s %s)\n", res, sh.vecTy(), intr, sh.lanes, sh.elemBits, sh.vecTy(), acc, sh.vecTy(), out)
				out = "%" + res
			}
		}
		return true, false, c.storeVShape(ins.Args[2].Reg, out, sh)

	case "ldn_lane", "stn_lane":
		// LD2/LD3/LD4 (Rn), [V...][lane]  and  ST2/ST3/ST4 (Rn), [V...][lane] (or reversed)
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects 2 operands: %q", op, ins.Raw)
		}
		var memOp, listOp asm.Operand
		if ins.Args[0].Kind == asm.OpMem {
			memOp, listOp = ins.Args[0], ins.Args[1]
		} else if ins.Args[1].Kind == asm.OpMem {
			memOp, listOp = ins.Args[1], ins.Args[0]
		} else {
			return true, false, fmt.Errorf("arm64 %s expects memory operand: %q", op, ins.Raw)
		}
		regs, laneIdx := arm64ParseRegListWithLane(listOp)
		if len(regs) == 0 {
			return true, false, fmt.Errorf("arm64 %s expects register list: %q", op, ins.Raw)
		}
		sh := parseNEONShape(regs[0], false)
		elemBytes := sh.elemBits / 8
		laneIdx %= sh.lanes
		addr, err := c.neonStructureAddress(memOp.Mem, postInc)
		if err != nil {
			return true, false, err
		}
		for k, reg := range regs {
			ak := addr
			if k > 0 {
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", t, addr, k*elemBytes)
				ak = "%" + t
			}
			pt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, ak)
			if spec.LLVMOp == "ldn_lane" {
				cur, err := c.loadVShape(reg, sh)
				if err != nil {
					return true, false, err
				}
				ld, insE := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, sh.elemTy(), pt)
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insE, sh.vecTy(), cur, sh.elemTy(), ld, laneIdx)
				if err := c.storeVShape(reg, "%"+insE, sh); err != nil {
					return true, false, err
				}
			} else {
				cur, err := c.loadVShape(reg, sh)
				if err != nil {
					return true, false, err
				}
				el := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", el, sh.vecTy(), cur, laneIdx)
				fmt.Fprintf(c.b, "  store %s %%%s, ptr %%%s, align 1\n", sh.elemTy(), el, pt)
			}
		}
		return true, false, c.neonStructureWriteback(memOp.Mem, postInc, int64(len(regs)*elemBytes))
	}
	return false, false, nil
}

func (c *arm64Ctx) loadVShapeOperand(op asm.Operand, sh neonShape) (string, error) {
	if op.Kind == asm.OpReg {
		s := string(op.Reg)
		if lb := strings.IndexByte(s, '['); lb >= 0 && strings.HasSuffix(s, "]") {
			base := asm.Reg(s[:lb])
			idx, _ := strconv.Atoi(s[lb+1 : len(s)-1])
			v, err := c.loadVShape(base, sh)
			if err != nil {
				return "", err
			}
			el, ins0, splat := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", el, sh.vecTy(), v, idx%sh.lanes)
			fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, sh.vecTy(), sh.elemTy(), el)
			fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, sh.vecTy(), ins0, sh.vecTy(), sh.lanes)
			return "%" + splat, nil
		}
		return c.loadVShape(op.Reg, sh)
	}
	return "zeroinitializer", nil
}

func arm64ParseRegListWithLane(op asm.Operand) ([]asm.Reg, int) {
	if op.Kind == asm.OpRegList {
		return op.RegList, 0
	}
	s := strings.TrimSpace(op.String())
	lane := 0
	if rb := strings.IndexByte(s, ']'); rb >= 0 && strings.HasPrefix(s, "[") {
		inner := s[1:rb]
		rest := strings.TrimSpace(s[rb+1:])
		if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
			if n, err := strconv.Atoi(rest[1 : len(rest)-1]); err == nil {
				lane = n
			}
		}
		parts := strings.Split(inner, ",")
		out := make([]asm.Reg, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, asm.Reg(p))
			}
		}
		return out, lane
	}
	return nil, 0
}
