package arm64

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// M6 complete ARM64 tail closure:
//   - ADRP & MOVP* pair aliases
//   - Unprivileged / unscaled narrow loads & stores (LDTR*, STTR*, LDUR*, VLDNP, VSTNP)
//   - Remaining x/arch NEON widening/narrowing/ABA/ABD/rounding/saturating/shift-accum/estimate ops
//   - Remaining x/arch scalar/vector FP disassembler ops, SMOV/SMOVW, FCVT*W, FRINT* vectors, etc.

var arm64M6Specs = []asm.OpSpec{
	// Address & pair aliases
	{Op: "ADRP", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "adrp"},
	{Op: "MOVP", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "movp"},
	{Op: "MOVPD", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "movp"},
	{Op: "MOVPW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "movp"},
	{Op: "MOVPS", Family: asm.FamilyMove, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "movp"},
	{Op: "MOVPSW", Family: asm.FamilyMove, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "movp"},
	{Op: "MOVPQ", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly, LLVMOp: "vpair"},

	// Vector non-temporal pairs
	{Op: "VLDNP", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly, LLVMOp: "vldnp"},
	{Op: "VSTNP", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectReadOnly, LLVMOp: "vstnp"},

	// Unprivileged EL0 & unscaled narrow/signed loads & stores
	{Op: "LDTR", Family: asm.FamilyMove, Width: 64, SrcWidth: 64, Effect: asm.EffectWriteOnly, LLVMOp: "ld_u"},
	{Op: "LDTRW", Family: asm.FamilyMove, Width: 32, SrcWidth: 32, Effect: asm.EffectWriteOnly, LLVMOp: "ld_u"},
	{Op: "LDTRSW", Family: asm.FamilyMove, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_s"},
	{Op: "LDTRH", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Effect: asm.EffectWriteOnly, LLVMOp: "ld_u"},
	{Op: "LDTRSH", Family: asm.FamilyMove, Width: 64, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_s"},
	{Op: "LDTRSHW", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_sw"},
	{Op: "LDTRBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Effect: asm.EffectWriteOnly, LLVMOp: "ld_u"},
	{Op: "LDTRSB", Family: asm.FamilyMove, Width: 64, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_s"},
	{Op: "LDTRSBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_sw"},
	{Op: "STTR", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectReadOnly, LLVMOp: "st_u"},
	{Op: "STTRW", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectReadOnly, LLVMOp: "st_u"},
	{Op: "STTRHW", Family: asm.FamilyMove, Width: 16, Effect: asm.EffectReadOnly, LLVMOp: "st_u"},
	{Op: "STTRBW", Family: asm.FamilyMove, Width: 8, Effect: asm.EffectReadOnly, LLVMOp: "st_u"},
	{Op: "LDURBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Effect: asm.EffectWriteOnly, LLVMOp: "ld_u"},
	{Op: "LDURHW", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Effect: asm.EffectWriteOnly, LLVMOp: "ld_u"},
	{Op: "LDURSB", Family: asm.FamilyMove, Width: 64, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_s"},
	{Op: "LDURSBW", Family: asm.FamilyMove, Width: 32, SrcWidth: 8, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_sw"},
	{Op: "LDURSH", Family: asm.FamilyMove, Width: 64, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_s"},
	{Op: "LDURSHW", Family: asm.FamilyMove, Width: 32, SrcWidth: 16, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_sw"},
	{Op: "LDURSW", Family: asm.FamilyMove, Width: 64, SrcWidth: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ld_s"},

	// NEON immediate & unary bitwise
	{Op: "VMOVI", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vmovi"},
	{Op: "VMVNI", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vmvni"},
	{Op: "VMVN", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "vmvn"},

	// Signed lane extract to GPR
	{Op: "SMOV", Family: asm.FamilyMove, Width: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "smov"},
	{Op: "SMOVW", Family: asm.FamilyMove, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "smov"},

	// 32-bit GPR FCVT*W (rounding + signed/unsigned)
	{Op: "FCVTASW", Family: asm.FamilyFP, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_round"},
	{Op: "FCVTAUW", Family: asm.FamilyFP, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_round"},
	{Op: "FCVTMSW", Family: asm.FamilyFP, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_floor"},
	{Op: "FCVTMUW", Family: asm.FamilyFP, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_floor"},
	{Op: "FCVTNSW", Family: asm.FamilyFP, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_even"},
	{Op: "FCVTNUW", Family: asm.FamilyFP, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_even"},
	{Op: "FCVTPSW", Family: asm.FamilyFP, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_ceil"},
	{Op: "FCVTPUW", Family: asm.FamilyFP, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtiw_ceil"},

	// Scalar SIMD F-reg <-> F-reg conversions
	{Op: "FCVTZSDD", Family: asm.FamilyFP, Width: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i_freg"},
	{Op: "FCVTZSSS", Family: asm.FamilyFP, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "f2i_freg"},
	{Op: "FCVTZUDD", Family: asm.FamilyFP, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "f2i_freg"},
	{Op: "SCVTFDD", Family: asm.FamilyFP, Width: 64, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f_freg"},
	{Op: "SCVTFSS", Family: asm.FamilyFP, Width: 32, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "i2f_freg"},
	{Op: "UCVTFDD", Family: asm.FamilyFP, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "i2f_freg"},
	{Op: "UCVTFSS", Family: asm.FamilyFP, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "i2f_freg"},
	{Op: "FCVTXN", Family: asm.FamilyFP, Width: 32, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtxn_scalar"},

	// Vector float->int & narrowing conversions
	{Op: "VFCVTAS", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_round"},
	{Op: "VFCVTAU", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_round"},
	{Op: "VFCVTMS", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_floor"},
	{Op: "VFCVTMU", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_floor"},
	{Op: "VFCVTNS", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_even"},
	{Op: "VFCVTNU", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_even"},
	{Op: "VFCVTPS", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_ceil"},
	{Op: "VFCVTPU", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvti_ceil"},
	{Op: "VFCVTXN", Family: asm.FamilyVecUnary, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "vfcvtxn"},
	{Op: "VFCVTXN2", Family: asm.FamilyVecUnary, Float: true, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "vfcvtxn"},

	// Scalar & vector FP math/compare/rounding/reduction/estimate (unprefixed & V-prefixed)
	{Op: "FABD", Family: asm.FamilyFP, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_abd"},
	{Op: "VFABD", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_abd"},
	{Op: "FACGE", Family: asm.FamilyCompare, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_acmp"},
	{Op: "VFACGE", Family: asm.FamilyCompare, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_acmp"},
	{Op: "FACGT", Family: asm.FamilyCompare, Float: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "fp_acmp"},
	{Op: "VFACGT", Family: asm.FamilyCompare, Float: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "fp_acmp"},
	{Op: "FCMLE", Family: asm.FamilyCompare, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_cmpz"},
	{Op: "FCMLT", Family: asm.FamilyCompare, Float: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "fp_cmpz"},
	{Op: "FABS", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_fabs"},
	{Op: "FNEG", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_fneg"},
	{Op: "FSQRT", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_sqrt"},
	{Op: "FRINTA", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_round"},
	{Op: "FRINTI", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_nearbyint"},
	{Op: "FRINTM", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_floor"},
	{Op: "FRINTN", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_roundeven"},
	{Op: "FRINTP", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_ceil"},
	{Op: "FRINTX", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_rint"},
	{Op: "FRINTZ", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_unary_trunc"},
	{Op: "FADD", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_fadd"},
	{Op: "FSUB", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_fsub"},
	{Op: "FDIV", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_fdiv"},
	{Op: "FMAX", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_maximum"},
	{Op: "FMIN", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_minimum"},
	{Op: "FMAXNM", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_maxnum"},
	{Op: "FMINNM", Family: asm.FamilyVecBinOp, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_bin_minnum"},
	{Op: "FMLA", Family: asm.FamilyVecFMA, Float: true, SubOp: 0, Effect: asm.EffectReadWrite, LLVMOp: "fp_fma"},
	{Op: "FMLS", Family: asm.FamilyVecFMA, Float: true, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "fp_fma"},
	{Op: "FADDP", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_fadd"},
	{Op: "FMAXP", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_maximum"},
	{Op: "FMINP", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_minimum"},
	{Op: "FMAXNMP", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_maxnum"},
	{Op: "FMINNMP", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_minnum"},
	{Op: "FMAXV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_maximum"},
	{Op: "FMINV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_minimum"},
	{Op: "FMAXNMV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_maxnum"},
	{Op: "FMINNMV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fp_red_minnum"},
	{Op: "FRECPE", Family: asm.FamilyFP, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_est"},
	{Op: "VFRECPE", Family: asm.FamilyVecUnary, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_est"},
	{Op: "FRECPX", Family: asm.FamilyFP, Float: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "fp_est"},
	{Op: "FRSQRTE", Family: asm.FamilyFP, Float: true, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "fp_est"},
	{Op: "VFRSQRTE", Family: asm.FamilyVecUnary, Float: true, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "fp_est"},
	{Op: "FRECPS", Family: asm.FamilyFP, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_step"},
	{Op: "VFRECPS", Family: asm.FamilyVecBinOp, Float: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "fp_step"},
	{Op: "FRSQRTS", Family: asm.FamilyFP, Float: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "fp_step"},
	{Op: "VFRSQRTS", Family: asm.FamilyVecBinOp, Float: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "fp_step"},

	// NEON narrowing add/sub high-half (SubOp: bit0=sub, bit1=round, bit2=high2)
	{Op: "VADDHN", Family: asm.FamilyVecBinOp, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "addhn"},
	{Op: "VADDHN2", Family: asm.FamilyVecBinOp, SubOp: 4, Effect: asm.EffectReadWrite, LLVMOp: "addhn"},
	{Op: "VSUBHN", Family: asm.FamilyVecBinOp, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "addhn"},
	{Op: "VSUBHN2", Family: asm.FamilyVecBinOp, SubOp: 5, Effect: asm.EffectReadWrite, LLVMOp: "addhn"},
	{Op: "VRADDHN", Family: asm.FamilyVecBinOp, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "addhn"},
	{Op: "VRADDHN2", Family: asm.FamilyVecBinOp, SubOp: 6, Effect: asm.EffectReadWrite, LLVMOp: "addhn"},
	{Op: "VRSUBHN", Family: asm.FamilyVecBinOp, SubOp: 3, Effect: asm.EffectWriteOnly, LLVMOp: "addhn"},
	{Op: "VRSUBHN2", Family: asm.FamilyVecBinOp, SubOp: 7, Effect: asm.EffectReadWrite, LLVMOp: "addhn"},

	// NEON ABD / ABA / ABDL / ABAL (SubOp: bit0=accum, bit1=long, bit2=high2)
	{Op: "VSABD", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "abd"},
	{Op: "VUABD", Family: asm.FamilyVecBinOp, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "abd"},
	{Op: "VSABA", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "abd"},
	{Op: "VUABA", Family: asm.FamilyVecBinOp, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "abd"},
	{Op: "VSABDL", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "abd"},
	{Op: "VUABDL", Family: asm.FamilyVecBinOp, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "abd"},
	{Op: "VSABDL2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 6, Effect: asm.EffectWriteOnly, LLVMOp: "abd"},
	{Op: "VUABDL2", Family: asm.FamilyVecBinOp, SubOp: 6, Effect: asm.EffectWriteOnly, LLVMOp: "abd"},
	{Op: "VSABAL", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 3, Effect: asm.EffectReadWrite, LLVMOp: "abd"},
	{Op: "VUABAL", Family: asm.FamilyVecBinOp, SubOp: 3, Effect: asm.EffectReadWrite, LLVMOp: "abd"},
	{Op: "VSABAL2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 7, Effect: asm.EffectReadWrite, LLVMOp: "abd"},
	{Op: "VUABAL2", Family: asm.FamilyVecBinOp, SubOp: 7, Effect: asm.EffectReadWrite, LLVMOp: "abd"},

	// NEON widening add/sub/shift, halving sub, pairwise long, sum-across-long
	// SubOp for widen_as: bit0=sub, bit1=wide(W vs L), bit2=high2
	{Op: "VSADDL", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUADDL", Family: asm.FamilyVecBinOp, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSADDL2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 4, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUADDL2", Family: asm.FamilyVecBinOp, SubOp: 4, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSSUBL", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUSUBL", Family: asm.FamilyVecBinOp, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSSUBL2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 5, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUSUBL2", Family: asm.FamilyVecBinOp, SubOp: 5, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSADDW", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUADDW", Family: asm.FamilyVecBinOp, SubOp: 2, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSADDW2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 6, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUADDW2", Family: asm.FamilyVecBinOp, SubOp: 6, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSSUBW", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 3, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUSUBW", Family: asm.FamilyVecBinOp, SubOp: 3, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSSUBW2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 7, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VUSUBW2", Family: asm.FamilyVecBinOp, SubOp: 7, Effect: asm.EffectWriteOnly, LLVMOp: "widen_as"},
	{Op: "VSHLL", Family: asm.FamilyVecShift, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "vshll"},
	{Op: "VSHLL2", Family: asm.FamilyVecShift, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "vshll"},
	{Op: "VSHSUB", Family: asm.FamilyVecBinOp, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "hsub"},
	{Op: "VUHSUB", Family: asm.FamilyVecBinOp, Effect: asm.EffectWriteOnly, LLVMOp: "hsub"},
	{Op: "VSADDLP", Family: asm.FamilyVecShuffle, Signed: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "addlp"},
	{Op: "VUADDLP", Family: asm.FamilyVecShuffle, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "addlp"},
	{Op: "VSADALP", Family: asm.FamilyVecShuffle, Signed: true, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "addlp"},
	{Op: "VUADALP", Family: asm.FamilyVecShuffle, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "addlp"},
	{Op: "VSADDLV", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "addlv"},

	// Saturating doubling multiply-long upper-half
	{Op: "VSQDMLAL2", Family: asm.FamilyVecFMA, Signed: true, SubOp: 1, Effect: asm.EffectReadWrite, LLVMOp: "sqdmul2"},
	{Op: "VSQDMLSL2", Family: asm.FamilyVecFMA, Signed: true, SubOp: 2, Effect: asm.EffectReadWrite, LLVMOp: "sqdmul2"},
	{Op: "VSQDMULL2", Family: asm.FamilyVecBinOp, Signed: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "sqdmul2"},

	// Rounding / saturating / narrowing shifts & shift-accumulate
	{Op: "VSRSHL", Family: asm.FamilyVecShift, Signed: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "var_rshl"},
	{Op: "VURSHL", Family: asm.FamilyVecShift, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "var_rshl"},
	{Op: "VSQRSHL", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "var_rshl"},
	{Op: "VUQRSHL", Family: asm.FamilyVecShift, Saturating: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "var_rshl"},
	{Op: "VURSHR", Family: asm.FamilyVecShift, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "imm_rshr"},
	{Op: "VSSRA", Family: asm.FamilyVecShift, Signed: true, SubOp: 2, Effect: asm.EffectReadWrite, LLVMOp: "imm_rshr"},
	{Op: "VSRSRA", Family: asm.FamilyVecShift, Signed: true, SubOp: 3, Effect: asm.EffectReadWrite, LLVMOp: "imm_rshr"},
	{Op: "VURSRA", Family: asm.FamilyVecShift, SubOp: 3, Effect: asm.EffectReadWrite, LLVMOp: "imm_rshr"},
	{Op: "VSQSHLU", Family: asm.FamilyVecShift, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqshlu"},
	// Narrowing right shifts (SubOp: bit0=round, bit1=high2, bit2=unsigned_dst)
	{Op: "VRSHRN", Family: asm.FamilyVecShift, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VRSHRN2", Family: asm.FamilyVecShift, SubOp: 3, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},
	{Op: "VSQSHRN", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VSQSHRN2", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 2, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},
	{Op: "VUQSHRN", Family: asm.FamilyVecShift, Saturating: true, SubOp: 4, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VUQSHRN2", Family: asm.FamilyVecShift, Saturating: true, SubOp: 6, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},
	{Op: "VSQRSHRN", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VSQRSHRN2", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 3, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},
	{Op: "VUQRSHRN", Family: asm.FamilyVecShift, Saturating: true, SubOp: 5, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VUQRSHRN2", Family: asm.FamilyVecShift, Saturating: true, SubOp: 7, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},
	{Op: "VSQSHRUN", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 4, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VSQSHRUN2", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 6, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},
	{Op: "VSQRSHRUN", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 5, Effect: asm.EffectWriteOnly, LLVMOp: "shrn_ext"},
	{Op: "VSQRSHRUN2", Family: asm.FamilyVecShift, Signed: true, Saturating: true, SubOp: 7, Effect: asm.EffectReadWrite, LLVMOp: "shrn_ext"},

	// Mixed-sign saturating add & integer reciprocal/rsqrt estimates
	{Op: "VSUQADD", Family: asm.FamilyVecBinOp, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "mixed_qadd"},
	{Op: "VUSQADD", Family: asm.FamilyVecBinOp, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "mixed_qadd"},
	{Op: "VURECPE", Family: asm.FamilyVecUnary, SubOp: 0, Effect: asm.EffectWriteOnly, LLVMOp: "u_est"},
	{Op: "VURSQRTE", Family: asm.FamilyVecUnary, SubOp: 1, Effect: asm.EffectWriteOnly, LLVMOp: "u_est"},
}

var arm64M6Table = asm.NewOpTable(arm64M6Specs)

func (c *arm64Ctx) arm64ExtractVecLaneI64(reg asm.Reg, wantBits int) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(string(reg)))
	lb := strings.IndexByte(s, '[')
	if lb < 0 || !strings.HasSuffix(s, "]") {
		return c.loadReg(reg)
	}
	base := s[:lb]
	idx, _ := strconv.Atoi(s[lb+1 : len(s)-1])
	bits := wantBits
	if dot := strings.IndexByte(base, '.'); dot >= 0 && dot+1 < len(base) {
		switch base[dot+1] {
		case 'B':
			bits = 8
		case 'H':
			bits = 16
		case 'S':
			bits = 32
		case 'D':
			bits = 64
		}
	}
	if bits == 0 {
		bits = 64
	}
	lanes := 128 / bits
	vecTy := fmt.Sprintf("<%d x i%d>", lanes, bits)
	raw, err := c.loadVReg(asm.Reg(base))
	if err != nil {
		return "", err
	}
	bc, el := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, raw, vecTy)
	fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", el, vecTy, bc, idx%lanes)
	if bits == 64 {
		return "%" + el, nil
	}
	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, bits, el)
	return "%" + z, nil
}

func (c *arm64Ctx) lowerARM64NEONImmBitwise(kind string, imm int64, dst asm.Reg) error {
	sh := parseNEONShape(dst, false)
	cur, err := c.loadVShape(dst, sh)
	if err != nil {
		return err
	}
	val := imm
	opName := "or"
	if kind == "bic" {
		val = ^imm
		opName = "and"
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", out, opName, sh.vecTy(), cur, arm64IntSplat(sh.lanes, sh.elemBits, val))
	return c.storeVShape(dst, "%"+out, sh)
}

func (c *arm64Ctx) lowerARM64VecFCVTInt(kind string, signed bool, fbits int64, srcOp asm.Operand, dst asm.Reg) error {
	sh := parseNEONShape(dst, true)
	if sh.elemBits != 32 && sh.elemBits != 64 {
		sh = parseNEONShape("V0.S4", true)
	}
	sv, err := c.loadVShapeOperand(srcOp, sh)
	if err != nil {
		return err
	}
	fpTy, suf := sh.vecTy(), sh.intrSuffix()
	cur := sv
	if fbits > 0 {
		sc := math.Ldexp(1.0, int(fbits))
		lit := asm.FormatLLVMFloat64Literal(sc)
		if sh.elemBits == 32 {
			lit = asm.FormatLLVMFloat64Literal(float64(float32(sc)))
		}
		elems := make([]string, sh.lanes)
		for i := range elems {
			elems[i] = fmt.Sprintf("%s %s", sh.elemTy(), lit)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fmul %s %s, <%s>\n", t, fpTy, cur, strings.Join(elems, ", "))
		cur = "%" + t
	}
	var roundIntr string
	switch kind {
	case "fcvti_round", "vfcvti_round":
		roundIntr = "@llvm.round."
	case "fcvti_floor", "vfcvti_floor":
		roundIntr = "@llvm.floor."
	case "fcvti_even", "vfcvti_even":
		roundIntr = "@llvm.roundeven."
	case "fcvti_ceil", "vfcvti_ceil":
		roundIntr = "@llvm.ceil."
	}
	if roundIntr != "" {
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s %s%s(%s %s)\n", t, fpTy, roundIntr, suf, fpTy, cur)
		cur = "%" + t
	}
	intSh := neonShape{lanes: sh.lanes, elemBits: sh.elemBits, half64: sh.half64}
	conv := "fptoui"
	if signed {
		conv = "fptosi"
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", out, conv, fpTy, cur, intSh.vecTy())
	return c.storeVShape(dst, "%"+out, intSh)
}

func (c *arm64Ctx) lowerARM64VecIntCVTF(signed bool, fbits int64, srcOp asm.Operand, dst asm.Reg) error {
	sh := parseNEONShape(dst, false)
	if sh.elemBits != 32 && sh.elemBits != 64 {
		sh = parseNEONShape("V0.S4", false)
	}
	sv, err := c.loadVShapeOperand(srcOp, sh)
	if err != nil {
		return err
	}
	fpSh := neonShape{lanes: sh.lanes, elemBits: sh.elemBits, half64: sh.half64, float: true}
	conv := "uitofp"
	if signed {
		conv = "sitofp"
	}
	fv := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", fv, conv, sh.vecTy(), sv, fpSh.vecTy())
	cur := "%" + fv
	if fbits > 0 {
		sc := math.Ldexp(1.0, -int(fbits))
		lit := asm.FormatLLVMFloat64Literal(sc)
		if sh.elemBits == 32 {
			lit = asm.FormatLLVMFloat64Literal(float64(float32(sc)))
		}
		elems := make([]string, sh.lanes)
		for i := range elems {
			elems[i] = fmt.Sprintf("%s %s", fpSh.elemTy(), lit)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fmul %s %s, <%s>\n", t, fpSh.vecTy(), cur, strings.Join(elems, ", "))
		cur = "%" + t
	}
	return c.storeVShape(dst, cur, fpSh)
}

func (c *arm64Ctx) loadVHalf(r asm.Reg, elemBits int, high bool) (string, int, error) {
	fullLanes := 128 / elemBits
	halfLanes := fullLanes / 2
	fullTy := fmt.Sprintf("<%d x i%d>", fullLanes, elemBits)
	raw, err := c.loadVReg(r)
	if err != nil {
		return "", 0, err
	}
	cur := raw
	if fullTy != "<16 x i8>" {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, raw, fullTy)
		cur = "%" + bc
	}
	off := 0
	if high {
		off = halfLanes
	}
	mask := make([]string, halfLanes)
	for i := 0; i < halfLanes; i++ {
		mask[i] = fmt.Sprintf("i32 %d", off+i)
	}
	sub := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", sub, fullTy, cur, fullTy, halfLanes, strings.Join(mask, ", "))
	return "%" + sub, halfLanes, nil
}

func (c *arm64Ctx) storeVNarrowHalf(dst asm.Reg, halfVal string, elemBits int, high bool) error {
	fullLanes := 128 / elemBits
	halfLanes := fullLanes / 2
	halfTy := fmt.Sprintf("<%d x i%d>", halfLanes, elemBits)
	fullTy := fmt.Sprintf("<%d x i%d>", fullLanes, elemBits)
	var merged string
	if !high {
		mask := make([]string, fullLanes)
		for i := 0; i < halfLanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", i)
		}
		for i := halfLanes; i < fullLanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", halfLanes)
		}
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s zeroinitializer, <%d x i32> <%s>\n", ext, halfTy, halfVal, halfTy, fullLanes, strings.Join(mask, ", "))
		merged = "%" + ext
	} else {
		oldLo, _, err := c.loadVHalf(dst, elemBits, false)
		if err != nil {
			return err
		}
		mask := make([]string, fullLanes)
		for i := 0; i < fullLanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", i)
		}
		comb := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n", comb, halfTy, oldLo, halfTy, halfVal, fullLanes, strings.Join(mask, ", "))
		merged = "%" + comb
	}
	out := merged
	if fullTy != "<16 x i8>" {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", bc, fullTy, merged)
		out = "%" + bc
	}
	return c.storeVReg(dst, out)
}

func arm64ScalarOrVecShape(r asm.Reg, isFloat bool) neonShape {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if strings.Contains(s, ".") {
		return parseNEONShape(r, isFloat)
	}
	// Bare V-register in x/arch scalar-SIMD syntax (e.g. VSQRSHL V26, V30, V23): treat as D1 (1 x i64).
	return neonShape{lanes: 1, elemBits: 64, half64: true, float: isFloat}
}

func (c *arm64Ctx) lowerM6XArch(op asm.Op, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := arm64M6Table.Lookup(op)
	if !found {
		return false, false, nil
	}
	switch spec.LLVMOp {
	case "adrp":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 ADRP expects sym, Rd: %q", ins.Raw)
		}
		if ins.Args[0].Kind == asm.OpSym {
			p, err := c.ptrFromSB(ins.Args[0].Sym)
			if err != nil {
				return true, false, c.storeReg(ins.Args[1].Reg, "0")
			}
			pi, pg := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", pi, p)
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, -4096\n", pg, pi)
			return true, false, c.storeReg(ins.Args[1].Reg, "%"+pg)
		}
		return true, false, c.storeReg(ins.Args[1].Reg, "0")

	case "movp":
		// Pair load/store aliases MOVP/MOVPD/MOVPW/MOVPS/MOVPSW
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects pair load/store operands: %q", op, ins.Raw)
		}
		elemBytes := int64(spec.Width / 8)
		elemTy := fmt.Sprintf("i%d", spec.Width)
		if ins.Args[0].Kind == asm.OpMem || ins.Args[0].Kind == asm.OpSym {
			var regs []asm.Reg
			if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpRegList && len(ins.Args[1].RegList) == 2 {
				regs = ins.Args[1].RegList
			} else if len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
				regs = []asm.Reg{ins.Args[1].Reg, ins.Args[2].Reg}
			} else {
				return true, false, fmt.Errorf("arm64 %s expects mem, (r1, r2): %q", op, ins.Raw)
			}
			ptr, base, inc, update, err := c.arm64PairPtr(ins.Args[0], strings.Contains(strings.ToUpper(string(ins.Op)), ".W"), postInc)
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
					ext := "zext"
					if spec.Signed {
						ext = "sext"
					}
					e := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = %s i32 %%%s to i64\n", e, ext, ld)
					val = "%" + e
				}
				if err := c.storeReg(r, val); err != nil {
					return true, false, err
				}
			}
			if update {
				return true, false, c.updatePostInc(base, inc)
			}
			return true, false, nil
		}
		var regs []asm.Reg
		var memOp asm.Operand
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpRegList && len(ins.Args[0].RegList) == 2 {
			regs, memOp = ins.Args[0].RegList, ins.Args[1]
		} else if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg {
			regs, memOp = []asm.Reg{ins.Args[0].Reg, ins.Args[1].Reg}, ins.Args[2]
		} else {
			return true, false, fmt.Errorf("arm64 %s expects (r1, r2), mem: %q", op, ins.Raw)
		}
		ptr, base, inc, update, err := c.arm64PairPtr(memOp, strings.Contains(strings.ToUpper(string(ins.Op)), ".W"), postInc)
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
		if update {
			return true, false, c.updatePostInc(base, inc)
		}
		return true, false, nil

	case "vldnp", "vstnp", "vpair":
		isStore := spec.LLVMOp == "vstnp" || (spec.LLVMOp == "vpair" && ins.Args[0].Kind != asm.OpMem && ins.Args[0].Kind != asm.OpSym)
		var memOp asm.Operand
		var regs []asm.Reg
		if len(ins.Args) == 3 && (ins.Args[0].Kind == asm.OpMem || ins.Args[0].Kind == asm.OpSym) && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
			memOp, regs = ins.Args[0], []asm.Reg{ins.Args[1].Reg, ins.Args[2].Reg}
		} else if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpRegList && len(ins.Args[1].RegList) == 2 {
			memOp, regs = ins.Args[0], ins.Args[1].RegList
		} else if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpRegList && len(ins.Args[0].RegList) == 2 {
			regs, memOp = ins.Args[0].RegList, ins.Args[1]
		} else if len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg {
			regs, memOp = []asm.Reg{ins.Args[0].Reg, ins.Args[1].Reg}, ins.Args[2]
		} else {
			return true, false, fmt.Errorf("arm64 %s expects mem and 2 vector regs: %q", op, ins.Raw)
		}
		ptr, _, _, _, err := c.arm64PairPtr(memOp, false, false)
		if err != nil {
			return true, false, err
		}
		for i, r := range regs {
			p := ptr
			if i != 0 {
				gp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 16\n", gp, ptr)
				p = "%" + gp
			}
			if !isStore {
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
				if err := c.storeVReg(r, "%"+ld); err != nil {
					return true, false, err
				}
			} else {
				v, err := c.loadVReg(r)
				if err != nil {
					return true, false, err
				}
				fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", v, p)
			}
		}
		return true, false, nil

	case "ld_u", "ld_s", "ld_sw":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects mem, Rd: %q", op, ins.Raw)
		}
		bits := int(spec.SrcWidth)
		raw64, err := c.loadMem(ins.Args[0].Mem, bits, postInc)
		if err != nil {
			return true, false, err
		}
		if spec.LLVMOp == "ld_u" {
			return true, false, c.storeReg(ins.Args[1].Reg, raw64)
		}
		tr, se := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, raw64, bits)
		if spec.LLVMOp == "ld_sw" {
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", se, bits, tr)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, se)
			return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)
		}
		fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i64\n", se, bits, tr)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+se)

	case "st_u":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpReg {
			// Also accept reversed reg, mem
			if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpMem {
				v, err := c.loadReg(ins.Args[0].Reg)
				if err != nil {
					return true, false, err
				}
				return true, false, c.storeMem(ins.Args[1].Mem, int(spec.Width), postInc, v)
			}
			return true, false, fmt.Errorf("arm64 %s expects mem, Rs: %q", op, ins.Raw)
		}
		v, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		return true, false, c.storeMem(ins.Args[0].Mem, int(spec.Width), postInc, v)

	case "vmovi", "vmvni":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects $imm, Vdst: %q", op, ins.Raw)
		}
		sh := parseNEONShape(ins.Args[1].Reg, false)
		val := ins.Args[0].Imm
		if spec.LLVMOp == "vmvni" {
			val = ^val
		}
		return true, false, c.storeVShape(ins.Args[1].Reg, arm64IntSplat(sh.lanes, sh.elemBits, val), sh)

	case "vmvn":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 VMVN expects Vsrc, Vdst: %q", ins.Raw)
		}
		sh := parseNEONShape(ins.Args[1].Reg, false)
		v, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", t, sh.vecTy(), v, arm64IntSplat(sh.lanes, sh.elemBits, -1))
		return true, false, c.storeVShape(ins.Args[1].Reg, "%"+t, sh)

	case "smov":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Vn.T[idx], Rd: %q", op, ins.Raw)
		}
		s := strings.ToUpper(string(ins.Args[0].Reg))
		srcBits := 32
		if strings.Contains(s, ".B[") {
			srcBits = 8
		} else if strings.Contains(s, ".H[") {
			srcBits = 16
		}
		raw, err := c.arm64ExtractVecLaneI64(ins.Args[0].Reg, srcBits)
		if err != nil {
			return true, false, err
		}
		tr, se := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, raw, srcBits)
		if spec.Width == 32 {
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i32\n", se, srcBits, tr)
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, se)
			return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)
		}
		fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i64\n", se, srcBits, tr)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+se)

	case "fcvtiw_round", "fcvtiw_floor", "fcvtiw_even", "fcvtiw_ceil":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Fsrc, Rd: %q", op, ins.Raw)
		}
		v, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		intr := map[string]string{
			"fcvtiw_round": "@llvm.round.f64",
			"fcvtiw_floor": "@llvm.floor.f64",
			"fcvtiw_even":  "@llvm.roundeven.f64",
			"fcvtiw_ceil":  "@llvm.ceil.f64",
		}[spec.LLVMOp]
		rd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double %s(double %s)\n", rd, intr, v)
		conv := "fptoui"
		if spec.Signed {
			conv = "fptosi"
		}
		i32, z := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s double %%%s to i32\n", i32, conv, rd)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, i32)
		return true, false, c.storeReg(ins.Args[1].Reg, "%"+z)

	case "f2i_freg", "i2f_freg":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Fsrc, Fdst: %q", op, ins.Raw)
		}
		if spec.LLVMOp == "f2i_freg" {
			fv, err := c.evalFP(ins.Args[0], spec.Width)
			if err != nil {
				return true, false, err
			}
			fpTy, iTy := "double", "i64"
			if spec.Width == 32 {
				fpTy, iTy = "float", "i32"
			}
			conv := "fptoui"
			if spec.Signed {
				conv = "fptosi"
			}
			iv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", iv, conv, fpTy, fv, iTy)
			out := "%" + iv
			if spec.Width == 32 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, iv)
				out = "%" + z
			}
			return true, false, c.storeReg(ins.Args[1].Reg, out)
		}
		raw, err := c.eval64(ins.Args[0], false)
		if err != nil {
			return true, false, err
		}
		conv := "uitofp"
		if spec.Signed {
			conv = "sitofp"
		}
		if spec.Width == 32 {
			tr, fv := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, raw)
			fmt.Fprintf(c.b, "  %%%s = %s i32 %%%s to float\n", fv, conv, tr)
			return true, false, c.storeF32(ins.Args[1], "%"+fv)
		}
		fv := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s to double\n", fv, conv, raw)
		return true, false, c.storeF64(ins.Args[1], "%"+fv)

	case "fcvtxn_scalar":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 FCVTXN expects Fsrc, Fdst: %q", ins.Raw)
		}
		v, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", t, v)
		return true, false, c.storeF32(ins.Args[1], "%"+t)

	case "vfcvti_round", "vfcvti_floor", "vfcvti_even", "vfcvti_ceil":
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Vsrc, Vdst: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64VecFCVTInt(spec.LLVMOp, spec.Signed, 0, ins.Args[0], ins.Args[1].Reg)

	case "vfcvtxn":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return true, false, fmt.Errorf("arm64 %s expects Vsrc.D2, Vdst.S2/S4: %q", op, ins.Raw)
		}
		srcSh := neonShape{lanes: 2, elemBits: 64, float: true}
		v, err := c.loadVShape(ins.Args[0].Reg, srcSh)
		if err != nil {
			return true, false, err
		}
		tr, bc := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc <2 x double> %s to <2 x float>\n", tr, v)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x float> %%%s to <2 x i32>\n", bc, tr)
		return true, false, c.storeVNarrowHalf(ins.Args[1].Reg, "%"+bc, 32, spec.SubOp != 0)

	case "fp_abd", "fp_acmp", "fp_cmpz", "fp_fma", "fp_est", "fp_step",
		"fp_unary_fabs", "fp_unary_fneg", "fp_unary_sqrt",
		"fp_unary_round", "fp_unary_nearbyint", "fp_unary_floor", "fp_unary_roundeven", "fp_unary_ceil", "fp_unary_rint", "fp_unary_trunc",
		"fp_bin_fadd", "fp_bin_fsub", "fp_bin_fdiv", "fp_bin_maximum", "fp_bin_minimum", "fp_bin_maxnum", "fp_bin_minnum",
		"fp_red_fadd", "fp_red_maximum", "fp_red_minimum", "fp_red_maxnum", "fp_red_minnum":
		return true, false, c.lowerARM64M6FP(spec, ins)

	case "addhn":
		return true, false, c.lowerARM64M6AddHN(spec, ins)
	case "abd":
		return true, false, c.lowerARM64M6ABD(spec, ins)
	case "widen_as":
		return true, false, c.lowerARM64M6WidenAS(spec, ins)
	case "vshll":
		return true, false, c.lowerARM64M6VSHLL(spec, ins)
	case "hsub":
		return true, false, c.lowerARM64M6HSub(spec, ins)
	case "addlp":
		return true, false, c.lowerARM64M6AddLP(spec, ins)
	case "addlv":
		return true, false, c.lowerARM64M6AddLV(ins)
	case "sqdmul2":
		return true, false, c.lowerARM64M6SQDMul2(spec, ins)
	case "var_rshl":
		return true, false, c.lowerARM64M6VarRShl(spec, ins)
	case "imm_rshr":
		return true, false, c.lowerARM64M6ImmRShr(spec, ins)
	case "sqshlu":
		return true, false, c.lowerARM64M6SQShlu(ins)
	case "shrn_ext":
		return true, false, c.lowerARM64M6ShrnExt(spec, ins)
	case "mixed_qadd":
		return true, false, c.lowerARM64M6MixedQAdd(spec, ins)
	case "u_est":
		return true, false, c.lowerARM64M6UEst(spec, ins)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerARM64M6FP(spec asm.OpSpec, ins asm.Instr) error {
	op := spec.LLVMOp
	if strings.HasPrefix(op, "fp_red_") {
		// FADDP/FMAXP/FMINP/FMAXNMP/FMINNMP/FMAXV/FMINV/FMAXNMV/FMINNMV Vsrc.T, Fdst
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vsrc, Fdst: %q", spec.Op, ins.Raw)
		}
		sh := parseNEONShape(ins.Args[0].Reg, true)
		v, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		el0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 0\n", el0, sh.vecTy(), v)
		acc := "%" + el0
		kind := strings.TrimPrefix(op, "fp_red_")
		suf := "f32"
		if sh.elemBits == 64 {
			suf = "f64"
		}
		for i := 1; i < sh.lanes; i++ {
			eli, nxt := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", eli, sh.vecTy(), v, i)
			if kind == "fadd" {
				fmt.Fprintf(c.b, "  %%%s = fadd %s %s, %%%s\n", nxt, sh.elemTy(), acc, eli)
			} else {
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %%%s)\n", nxt, sh.elemTy(), kind, suf, sh.elemTy(), acc, sh.elemTy(), eli)
			}
			acc = "%" + nxt
		}
		return c.storeFP(ins.Args[1], acc, uint16(sh.elemBits))
	}

	if op == "fp_cmpz" {
		// FCMLE / FCMLT $0, Fsrc, Fdst
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects $0, Fsrc, Fdst: %q", spec.Op, ins.Raw)
		}
		v, err := c.evalF64(ins.Args[1])
		if err != nil {
			return err
		}
		pred := "ole"
		if spec.SubOp != 0 {
			pred = "olt"
		}
		cmp, mask := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp %s double %s, 0.0\n", cmp, pred, v)
		fmt.Fprintf(c.b, "  %%%s = sext i1 %%%s to i64\n", mask, cmp)
		return c.storeReg(ins.Args[2].Reg, "%"+mask)
	}

	if op == "fp_fma" {
		// FMLA / FMLS Vm.S[i]/Fm, Fn, Fd  (or vector Vm.T, Vn.T, Vd.T)
		if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src1, src2, dst: %q", spec.Op, ins.Raw)
		}
		if _, isV := arm64ParseVReg(ins.Args[2].Reg); isV {
			sh := parseNEONShape(ins.Args[2].Reg, true)
			a, err := c.loadVShapeOperand(ins.Args[0], sh)
			if err != nil {
				return err
			}
			b, err := c.loadVShapeOperand(ins.Args[1], sh)
			if err != nil {
				return err
			}
			acc, err := c.loadVShape(ins.Args[2].Reg, sh)
			if err != nil {
				return err
			}
			if spec.SubOp != 0 {
				neg := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", neg, sh.vecTy(), a)
				a = "%" + neg
			}
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", res, sh.vecTy(), sh.intrSuffix(), sh.vecTy(), a, sh.vecTy(), b, sh.vecTy(), acc)
			return c.storeVShape(ins.Args[2].Reg, "%"+res, sh)
		}
		w := uint16(64)
		ty, suf := "double", "f64"
		if ins.Args[0].Kind == asm.OpReg && strings.Contains(strings.ToUpper(string(ins.Args[0].Reg)), ".S[") {
			w, ty, suf = 32, "float", "f32"
		}
		a, err := c.evalFP(ins.Args[0], w)
		if err != nil {
			return err
		}
		b, err := c.evalFP(ins.Args[1], w)
		if err != nil {
			return err
		}
		acc, err := c.evalFP(ins.Args[2], w)
		if err != nil {
			return err
		}
		if spec.SubOp != 0 {
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", neg, ty, a)
			a = "%" + neg
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", res, ty, suf, ty, a, ty, b, ty, acc)
		return c.storeFP(ins.Args[2], "%"+res, w)
	}

	if strings.HasPrefix(op, "fp_unary_") {
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		kind := strings.TrimPrefix(op, "fp_unary_")
		sh := parseNEONShape(ins.Args[1].Reg, true)
		v, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		out := c.newTmp()
		if kind == "fneg" {
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", out, sh.vecTy(), v)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", out, sh.vecTy(), kind, sh.intrSuffix(), sh.vecTy(), v)
		}
		return c.storeVShape(ins.Args[1].Reg, "%"+out, sh)
	}

	if op == "fp_est" {
		if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects src, dst: %q", spec.Op, ins.Raw)
		}
		if _, isV := arm64ParseVReg(ins.Args[1].Reg); isV {
			sh := parseNEONShape(ins.Args[1].Reg, true)
			v, err := c.loadVShape(ins.Args[0].Reg, sh)
			if err != nil {
				return err
			}
			cur := v
			if spec.SubOp == 2 {
				sq := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %s)\n", sq, sh.vecTy(), sh.intrSuffix(), sh.vecTy(), v)
				cur = "%" + sq
			}
			ones := make([]string, sh.lanes)
			for i := range ones {
				ones[i] = fmt.Sprintf("%s 1.0", sh.elemTy())
			}
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fdiv %s <%s>, %s\n", out, sh.vecTy(), strings.Join(ones, ", "), cur)
			return c.storeVShape(ins.Args[1].Reg, "%"+out, sh)
		}
		v, err := c.evalF64(ins.Args[0])
		if err != nil {
			return err
		}
		var res string
		if spec.SubOp == 1 { // FRECPX: exponent extraction / power of 2
			res = v
		} else {
			cur := v
			if spec.SubOp == 2 {
				sq := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = call double @llvm.sqrt.f64(double %s)\n", sq, v)
				cur = "%" + sq
			}
			d := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fdiv double 1.0, %s\n", d, cur)
			res = "%" + d
		}
		return c.storeF64(ins.Args[1], res)
	}

	// Binary FP ops: fp_abd, fp_acmp, fp_step, fp_bin_*
	if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects src1, src2, dst: %q", spec.Op, ins.Raw)
	}
	if _, isV := arm64ParseVReg(ins.Args[2].Reg); isV {
		sh := parseNEONShape(ins.Args[2].Reg, true)
		rhs, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		lhs, err := c.loadVShape(ins.Args[1].Reg, sh)
		if err != nil {
			return err
		}
		switch op {
		case "fp_abd":
			d, ab := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fsub %s %s, %s\n", d, sh.vecTy(), lhs, rhs)
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %%%s)\n", ab, sh.vecTy(), sh.intrSuffix(), sh.vecTy(), d)
			return c.storeVShape(ins.Args[2].Reg, "%"+ab, sh)
		case "fp_acmp":
			al, ar, cmp, sx := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			pred := "oge"
			if spec.SubOp != 0 {
				pred = "ogt"
			}
			intSh := neonShape{lanes: sh.lanes, elemBits: sh.elemBits, half64: sh.half64}
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", al, sh.vecTy(), sh.intrSuffix(), sh.vecTy(), lhs)
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fabs.%s(%s %s)\n", ar, sh.vecTy(), sh.intrSuffix(), sh.vecTy(), rhs)
			fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %%%s, %%%s\n", cmp, pred, sh.vecTy(), al, ar)
			fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sx, sh.lanes, cmp, intSh.vecTy())
			return c.storeVShape(ins.Args[2].Reg, "%"+sx, intSh)
		case "fp_step":
			// FRECPS: 2 - a*b; FRSQRTS: (3 - a*b) / 2
			cLit := "2.0"
			if spec.SubOp != 0 {
				cLit = "3.0"
			}
			cv := make([]string, sh.lanes)
			hv := make([]string, sh.lanes)
			for i := range cv {
				cv[i] = fmt.Sprintf("%s %s", sh.elemTy(), cLit)
				hv[i] = fmt.Sprintf("%s 0.5", sh.elemTy())
			}
			m, sub := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul %s %s, %s\n", m, sh.vecTy(), lhs, rhs)
			fmt.Fprintf(c.b, "  %%%s = fsub %s <%s>, %%%s\n", sub, sh.vecTy(), strings.Join(cv, ", "), m)
			res := "%" + sub
			if spec.SubOp != 0 {
				h := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = fmul %s %%%s, <%s>\n", h, sh.vecTy(), sub, strings.Join(hv, ", "))
				res = "%" + h
			}
			return c.storeVShape(ins.Args[2].Reg, res, sh)
		default:
			kind := strings.TrimPrefix(op, "fp_bin_")
			out := c.newTmp()
			if kind == "fadd" || kind == "fsub" || kind == "fdiv" {
				fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", out, kind, sh.vecTy(), lhs, rhs)
			} else {
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %s)\n", out, sh.vecTy(), kind, sh.intrSuffix(), sh.vecTy(), lhs, sh.vecTy(), rhs)
			}
			return c.storeVShape(ins.Args[2].Reg, "%"+out, sh)
		}
	}

	// Scalar F-register binary FP ops (FABD, FACGE, FACGT, FRECPS, FRSQRTS)
	rhs, err := c.evalF64(ins.Args[0])
	if err != nil {
		return err
	}
	lhs, err := c.evalF64(ins.Args[1])
	if err != nil {
		return err
	}
	switch op {
	case "fp_abd":
		d, ab := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fsub double %s, %s\n", d, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.fabs.f64(double %%%s)\n", ab, d)
		return c.storeF64(ins.Args[2], "%"+ab)
	case "fp_acmp":
		al, ar, cmp, sx := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		pred := "oge"
		if spec.SubOp != 0 {
			pred = "ogt"
		}
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.fabs.f64(double %s)\n", al, lhs)
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.fabs.f64(double %s)\n", ar, rhs)
		fmt.Fprintf(c.b, "  %%%s = fcmp %s double %%%s, %%%s\n", cmp, pred, al, ar)
		fmt.Fprintf(c.b, "  %%%s = sext i1 %%%s to i64\n", sx, cmp)
		return c.storeReg(ins.Args[2].Reg, "%"+sx)
	default: // fp_step scalar
		m, sub := c.newTmp(), c.newTmp()
		cLit := "2.0"
		if spec.SubOp != 0 {
			cLit = "3.0"
		}
		fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", m, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = fsub double %s, %%%s\n", sub, cLit, m)
		res := "%" + sub
		if spec.SubOp != 0 {
			h := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fmul double %%%s, 0.5\n", h, sub)
			res = "%" + h
		}
		return c.storeF64(ins.Args[2], res)
	}
}

func (c *arm64Ctx) lowerARM64M6AddHN(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vm, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	isSub := (spec.SubOp & 1) != 0
	isRound := (spec.SubOp & 2) != 0
	isHigh := (spec.SubOp & 4) != 0
	srcSh := parseNEONShape(ins.Args[0].Reg, false)
	if srcSh.elemBits < 16 {
		srcSh = parseNEONShape("V0.H8", false)
	}
	rhs, err := c.loadVShape(ins.Args[0].Reg, srcSh)
	if err != nil {
		return err
	}
	lhs, err := c.loadVShape(ins.Args[1].Reg, srcSh)
	if err != nil {
		return err
	}
	opName := "add"
	if isSub {
		opName = "sub"
	}
	sum := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", sum, opName, srcSh.vecTy(), lhs, rhs)
	cur := "%" + sum
	narrowBits := srcSh.elemBits / 2
	if isRound {
		r := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", r, srcSh.vecTy(), cur, arm64IntSplat(srcSh.lanes, srcSh.elemBits, int64(1)<<uint(narrowBits-1)))
		cur = "%" + r
	}
	sh, tr := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", sh, srcSh.vecTy(), cur, arm64IntSplat(srcSh.lanes, srcSh.elemBits, int64(narrowBits)))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to <%d x i%d>\n", tr, srcSh.vecTy(), sh, srcSh.lanes, narrowBits)
	return c.storeVNarrowHalf(ins.Args[2].Reg, "%"+tr, narrowBits, isHigh)
}

func (c *arm64Ctx) lowerARM64M6ABD(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vm, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	isAcc := (spec.SubOp & 1) != 0
	isLong := (spec.SubOp & 2) != 0
	isHigh := (spec.SubOp & 4) != 0
	dstSh := parseNEONShape(ins.Args[2].Reg, false)
	var a, b string
	var err error
	var workSh neonShape
	if isLong {
		srcElem := dstSh.elemBits / 2
		if srcElem < 8 {
			srcElem = 8
		}
		aHalf, nLanes, lerr := c.loadVHalf(ins.Args[0].Reg, srcElem, isHigh)
		if lerr != nil {
			return lerr
		}
		bHalf, _, lerr := c.loadVHalf(ins.Args[1].Reg, srcElem, isHigh)
		if lerr != nil {
			return lerr
		}
		ext := "zext"
		if spec.Signed {
			ext = "sext"
		}
		halfTy := fmt.Sprintf("<%d x i%d>", nLanes, srcElem)
		workSh = neonShape{lanes: nLanes, elemBits: dstSh.elemBits}
		ae, be := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ae, ext, halfTy, aHalf, workSh.vecTy())
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", be, ext, halfTy, bHalf, workSh.vecTy())
		a, b = "%"+ae, "%"+be
	} else {
		workSh = dstSh
		a, err = c.loadVShape(ins.Args[0].Reg, workSh)
		if err != nil {
			return err
		}
		b, err = c.loadVShape(ins.Args[1].Reg, workSh)
		if err != nil {
			return err
		}
	}
	pred := "ugt"
	if spec.Signed {
		pred = "sgt"
	}
	cmp, hi, lo, diff := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, workSh.vecTy(), b, a)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", hi, workSh.lanes, cmp, workSh.vecTy(), b, workSh.vecTy(), a)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", lo, workSh.lanes, cmp, workSh.vecTy(), a, workSh.vecTy(), b)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", diff, workSh.vecTy(), hi, lo)
	out := "%" + diff
	if isAcc {
		cur, err := c.loadVShape(ins.Args[2].Reg, workSh)
		if err != nil {
			return err
		}
		acc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", acc, workSh.vecTy(), cur, diff)
		out = "%" + acc
	}
	return c.storeVShape(ins.Args[2].Reg, out, workSh)
}

func (c *arm64Ctx) lowerARM64M6WidenAS(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vm, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	isSub := (spec.SubOp & 1) != 0
	isWide := (spec.SubOp & 2) != 0
	isHigh := (spec.SubOp & 4) != 0
	dstSh := parseNEONShape(ins.Args[2].Reg, false)
	srcElem := dstSh.elemBits / 2
	if srcElem < 8 {
		srcElem = 8
	}
	ext := "zext"
	if spec.Signed {
		ext = "sext"
	}
	mHalf, nLanes, err := c.loadVHalf(ins.Args[0].Reg, srcElem, isHigh)
	if err != nil {
		return err
	}
	halfTy := fmt.Sprintf("<%d x i%d>", nLanes, srcElem)
	workSh := neonShape{lanes: nLanes, elemBits: dstSh.elemBits}
	me := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", me, ext, halfTy, mHalf, workSh.vecTy())
	var lhs string
	if isWide {
		lhs, err = c.loadVShape(ins.Args[1].Reg, workSh)
		if err != nil {
			return err
		}
	} else {
		nHalf, _, err := c.loadVHalf(ins.Args[1].Reg, srcElem, isHigh)
		if err != nil {
			return err
		}
		ne := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ne, ext, halfTy, nHalf, workSh.vecTy())
		lhs = "%" + ne
	}
	opName := "add"
	if isSub {
		opName = "sub"
	}
	res := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", res, opName, workSh.vecTy(), lhs, me)
	return c.storeVShape(ins.Args[2].Reg, "%"+res, workSh)
}

func (c *arm64Ctx) lowerARM64M6VSHLL(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects $shift, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	dstSh := parseNEONShape(ins.Args[2].Reg, false)
	srcElem := dstSh.elemBits / 2
	if srcElem < 8 {
		srcElem = 8
	}
	sHalf, nLanes, err := c.loadVHalf(ins.Args[1].Reg, srcElem, spec.SubOp != 0)
	if err != nil {
		return err
	}
	workSh := neonShape{lanes: nLanes, elemBits: dstSh.elemBits}
	ext, sh := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i%d> %s to %s\n", ext, nLanes, srcElem, sHalf, workSh.vecTy())
	amt := ins.Args[0].Imm & int64(dstSh.elemBits-1)
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", sh, workSh.vecTy(), ext, arm64IntSplat(nLanes, dstSh.elemBits, amt))
	return c.storeVShape(ins.Args[2].Reg, "%"+sh, workSh)
}

func (c *arm64Ctx) lowerARM64M6HSub(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vm, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	sh := parseNEONShape(ins.Args[2].Reg, false)
	rhs, err := c.loadVShape(ins.Args[0].Reg, sh)
	if err != nil {
		return err
	}
	lhs, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	wideBits := sh.elemBits * 2
	wideTy := fmt.Sprintf("<%d x i%d>", sh.lanes, wideBits)
	ext := "zext"
	if spec.Signed {
		ext = "sext"
	}
	le, re, sub, shr, tr := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", le, ext, sh.vecTy(), lhs, wideTy)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", re, ext, sh.vecTy(), rhs, wideTy)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", sub, wideTy, le, re)
	fmt.Fprintf(c.b, "  %%%s = ashr %s %%%s, %s\n", shr, wideTy, sub, arm64IntSplat(sh.lanes, wideBits, 1))
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, wideTy, shr, sh.vecTy())
	return c.storeVShape(ins.Args[2].Reg, "%"+tr, sh)
}

func (c *arm64Ctx) lowerARM64M6AddLP(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vn, Vd: %q", spec.Op, ins.Raw)
	}
	srcSh := parseNEONShape(ins.Args[0].Reg, false)
	dstSh := parseNEONShape(ins.Args[1].Reg, false)
	v, err := c.loadVShape(ins.Args[0].Reg, srcSh)
	if err != nil {
		return err
	}
	ext := "zext"
	if spec.Signed {
		ext = "sext"
	}
	evMask := make([]string, dstSh.lanes)
	odMask := make([]string, dstSh.lanes)
	for i := 0; i < dstSh.lanes; i++ {
		evMask[i] = fmt.Sprintf("i32 %d", 2*i)
		odMask[i] = fmt.Sprintf("i32 %d", 2*i+1)
	}
	halfTy := fmt.Sprintf("<%d x i%d>", dstSh.lanes, srcSh.elemBits)
	ev, od, eve, ode, sum := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", ev, srcSh.vecTy(), v, srcSh.vecTy(), dstSh.lanes, strings.Join(evMask, ", "))
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", od, srcSh.vecTy(), v, srcSh.vecTy(), dstSh.lanes, strings.Join(odMask, ", "))
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", eve, ext, halfTy, ev, dstSh.vecTy())
	fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", ode, ext, halfTy, od, dstSh.vecTy())
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, dstSh.vecTy(), eve, ode)
	out := "%" + sum
	if spec.SubOp != 0 {
		cur, err := c.loadVShape(ins.Args[1].Reg, dstSh)
		if err != nil {
			return err
		}
		acc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", acc, dstSh.vecTy(), cur, sum)
		out = "%" + acc
	}
	return c.storeVShape(ins.Args[1].Reg, out, dstSh)
}

func (c *arm64Ctx) lowerARM64M6AddLV(ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("arm64 VSADDLV expects Vn, Vd: %q", ins.Raw)
	}
	srcSh := parseNEONShape(ins.Args[0].Reg, false)
	v, err := c.loadVShape(ins.Args[0].Reg, srcSh)
	if err != nil {
		return err
	}
	acc := "0"
	for i := 0; i < srcSh.lanes; i++ {
		el, ex, nxt := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", el, srcSh.vecTy(), v, i)
		fmt.Fprintf(c.b, "  %%%s = sext %s %%%s to i64\n", ex, srcSh.elemTy(), el)
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", nxt, acc, ex)
		acc = "%" + nxt
	}
	d1 := neonShape{lanes: 1, elemBits: 64, half64: true}
	ins0 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i64> zeroinitializer, i64 %s, i32 0\n", ins0, acc)
	return c.storeVShape(ins.Args[1].Reg, "%"+ins0, d1)
}

func (c *arm64Ctx) lowerARM64M6SQDMul2(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects src1, src2, Vd: %q", spec.Op, ins.Raw)
	}
	dstSh := parseNEONShape(ins.Args[2].Reg, false)
	srcElem := dstSh.elemBits / 2
	if srcElem < 16 {
		srcElem = 16
	}
	nLanes := dstSh.lanes
	halfTy := fmt.Sprintf("<%d x i%d>", nLanes, srcElem)
	var aHalf string
	var err error
	if ins.Args[0].Kind == asm.OpReg && strings.Contains(string(ins.Args[0].Reg), "[") {
		bits, lerr := c.arm64ExtractVecLaneI64(ins.Args[0].Reg, srcElem)
		if lerr != nil {
			return lerr
		}
		tr, ins0, sp := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", tr, bits, srcElem)
		fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, i%d %%%s, i32 0\n", ins0, halfTy, srcElem, tr)
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", sp, halfTy, ins0, halfTy, nLanes)
		aHalf = "%" + sp
	} else {
		aHalf, _, err = c.loadVHalf(ins.Args[0].Reg, srcElem, true)
		if err != nil {
			return err
		}
	}
	bHalf, _, err := c.loadVHalf(ins.Args[1].Reg, srcElem, true)
	if err != nil {
		return err
	}
	ae, be, mul, dbl := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", ae, halfTy, aHalf, dstSh.vecTy())
	fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", be, halfTy, bHalf, dstSh.vecTy())
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", mul, dstSh.vecTy(), ae, be)
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", dbl, dstSh.vecTy(), mul, arm64IntSplat(nLanes, dstSh.elemBits, 1))
	out := "%" + dbl
	if spec.SubOp != 0 {
		acc, err := c.loadVShape(ins.Args[2].Reg, dstSh)
		if err != nil {
			return err
		}
		intr := "@llvm.sadd.sat."
		if spec.SubOp == 2 {
			intr = "@llvm.ssub.sat."
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s %s%s(%s %s, %s %s)\n", res, dstSh.vecTy(), intr, dstSh.intrSuffix(), dstSh.vecTy(), acc, dstSh.vecTy(), out)
		out = "%" + res
	}
	return c.storeVShape(ins.Args[2].Reg, out, dstSh)
}

func (c *arm64Ctx) lowerARM64M6VarRShl(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vshift, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	sh := arm64ScalarOrVecShape(ins.Args[2].Reg, false)
	shAmt, err := c.loadVShape(ins.Args[0].Reg, sh)
	if err != nil {
		return err
	}
	val, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	// Signed shift amount in low byte of each lane: >=0 left shift, <0 right shift.
	mask := arm64IntSplat(sh.lanes, sh.elemBits, int64(sh.elemBits-1))
	zero := "zeroinitializer"
	neg := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", neg, sh.vecTy(), shAmt, zero)
	lAmt, rNeg, rAmt := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", lAmt, sh.vecTy(), shAmt, mask)
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", rNeg, sh.vecTy(), zero, shAmt)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", rAmt, sh.vecTy(), rNeg, mask)
	shrOp := "lshr"
	if spec.Signed {
		shrOp = "ashr"
	}
	lRes, rRes, sel := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", lRes, sh.vecTy(), val, lAmt)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", rRes, shrOp, sh.vecTy(), val, rAmt)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %%%s\n", sel, sh.lanes, neg, sh.vecTy(), rRes, sh.vecTy(), lRes)
	return c.storeVShape(ins.Args[2].Reg, "%"+sel, sh)
}

func (c *arm64Ctx) lowerARM64M6ImmRShr(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects $shift, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	isRound := (spec.SubOp & 1) != 0
	isAcc := (spec.SubOp & 2) != 0
	sh := arm64ScalarOrVecShape(ins.Args[2].Reg, false)
	v, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	amt := ins.Args[0].Imm
	if amt < 0 {
		amt = 0
	}
	if amt >= int64(sh.elemBits) {
		amt = int64(sh.elemBits - 1)
	}
	shrOp := "lshr"
	if spec.Signed {
		shrOp = "ashr"
	}
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, shrOp, sh.vecTy(), v, arm64IntSplat(sh.lanes, sh.elemBits, amt))
	out := "%" + shifted
	if isRound && amt > 0 {
		rb, rbit, rd := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", rb, sh.vecTy(), v, arm64IntSplat(sh.lanes, sh.elemBits, amt-1))
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", rbit, sh.vecTy(), rb, arm64IntSplat(sh.lanes, sh.elemBits, 1))
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", rd, sh.vecTy(), shifted, rbit)
		out = "%" + rd
	}
	if isAcc {
		cur, err := c.loadVShape(ins.Args[2].Reg, sh)
		if err != nil {
			return err
		}
		acc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", acc, sh.vecTy(), cur, out)
		out = "%" + acc
	}
	return c.storeVShape(ins.Args[2].Reg, out, sh)
}

func (c *arm64Ctx) lowerARM64M6SQShlu(ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 VSQSHLU expects $shift, Vn, Vd: %q", ins.Raw)
	}
	sh := arm64ScalarOrVecShape(ins.Args[2].Reg, false)
	v, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	amt := ins.Args[0].Imm & int64(sh.elemBits-1)
	neg, clamp, shifted := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", neg, sh.vecTy(), v)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s zeroinitializer, %s %s\n", clamp, sh.lanes, neg, sh.vecTy(), sh.vecTy(), v)
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", shifted, sh.vecTy(), clamp, arm64IntSplat(sh.lanes, sh.elemBits, amt))
	return c.storeVShape(ins.Args[2].Reg, "%"+shifted, sh)
}

func (c *arm64Ctx) lowerARM64M6ShrnExt(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects $shift, Vn, Vd: %q", spec.Op, ins.Raw)
	}
	isRound := (spec.SubOp & 1) != 0
	isHigh := (spec.SubOp & 2) != 0
	unsignedDst := (spec.SubOp & 4) != 0
	srcSh := arm64ScalarOrVecShape(ins.Args[1].Reg, false)
	if srcSh.elemBits < 16 {
		srcSh = parseNEONShape("V0.H8", false)
	}
	v, err := c.loadVShape(ins.Args[1].Reg, srcSh)
	if err != nil {
		return err
	}
	amt := ins.Args[0].Imm
	if amt < 0 {
		amt = 0
	}
	if amt >= int64(srcSh.elemBits) {
		amt = int64(srcSh.elemBits - 1)
	}
	shrOp := "lshr"
	if spec.Signed {
		shrOp = "ashr"
	}
	sh := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", sh, shrOp, srcSh.vecTy(), v, arm64IntSplat(srcSh.lanes, srcSh.elemBits, amt))
	cur := "%" + sh
	if isRound && amt > 0 {
		rb, rbit, rd := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", rb, srcSh.vecTy(), v, arm64IntSplat(srcSh.lanes, srcSh.elemBits, amt-1))
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", rbit, srcSh.vecTy(), rb, arm64IntSplat(srcSh.lanes, srcSh.elemBits, 1))
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", rd, srcSh.vecTy(), sh, rbit)
		cur = "%" + rd
	}
	dstBits := srcSh.elemBits / 2
	if spec.Saturating {
		if unsignedDst {
			maxU := (int64(1) << uint(dstBits)) - 1
			if spec.Signed {
				lt0, cl0 := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", lt0, srcSh.vecTy(), cur)
				fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s zeroinitializer, %s %s\n", cl0, srcSh.lanes, lt0, srcSh.vecTy(), srcSh.vecTy(), cur)
				cur = "%" + cl0
			}
			gtM, clM := c.newTmp(), c.newTmp()
			maxVec := arm64IntSplat(srcSh.lanes, srcSh.elemBits, maxU)
			fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %s, %s\n", gtM, srcSh.vecTy(), cur, maxVec)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", clM, srcSh.lanes, gtM, srcSh.vecTy(), maxVec, srcSh.vecTy(), cur)
			cur = "%" + clM
		} else {
			maxS := (int64(1) << uint(dstBits-1)) - 1
			minS := -(int64(1) << uint(dstBits-1))
			maxVec := arm64IntSplat(srcSh.lanes, srcSh.elemBits, maxS)
			minVec := arm64IntSplat(srcSh.lanes, srcSh.elemBits, minS)
			gtM, clM, ltM, clL := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %s, %s\n", gtM, srcSh.vecTy(), cur, maxVec)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", clM, srcSh.lanes, gtM, srcSh.vecTy(), maxVec, srcSh.vecTy(), cur)
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, %s\n", ltM, srcSh.vecTy(), clM, minVec)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", clL, srcSh.lanes, ltM, srcSh.vecTy(), minVec, srcSh.vecTy(), clM)
			cur = "%" + clL
		}
	}
	tr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to <%d x i%d>\n", tr, srcSh.vecTy(), cur, srcSh.lanes, dstBits)
	if srcSh.lanes == 1 {
		// Scalar-SIMD narrowing (e.g. VUQSHRN $5, V18, V17 -> low 32-bit lane zero-extended into V17)
		el, z, ins0 := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %%%s, i32 0\n", el, dstBits, tr)
		fmt.Fprintf(c.b, "  %%%s = zext i%d %%%s to i64\n", z, dstBits, el)
		fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i64> zeroinitializer, i64 %%%s, i32 0\n", ins0, z)
		return c.storeVShape(ins.Args[2].Reg, "%"+ins0, neonShape{lanes: 1, elemBits: 64, half64: true})
	}
	return c.storeVNarrowHalf(ins.Args[2].Reg, "%"+tr, dstBits, isHigh)
}

func (c *arm64Ctx) lowerARM64M6MixedQAdd(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vn, Vd: %q", spec.Op, ins.Raw)
	}
	sh := arm64ScalarOrVecShape(ins.Args[1].Reg, false)
	src, err := c.loadVShape(ins.Args[0].Reg, sh)
	if err != nil {
		return err
	}
	dst, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	intr := "@llvm.uadd.sat."
	if spec.Signed {
		intr = "@llvm.sadd.sat."
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s%s(%s %s, %s %s)\n", out, sh.vecTy(), intr, sh.intrSuffix(), sh.vecTy(), dst, sh.vecTy(), src)
	return c.storeVShape(ins.Args[1].Reg, "%"+out, sh)
}

func (c *arm64Ctx) lowerARM64M6UEst(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vn, Vd: %q", spec.Op, ins.Raw)
	}
	sh := parseNEONShape(ins.Args[1].Reg, false)
	v, err := c.loadVShape(ins.Args[0].Reg, sh)
	if err != nil {
		return err
	}
	// Fixed-point unsigned reciprocal / rsqrt estimate via double conversion + round-trip.
	fpTy := fmt.Sprintf("<%d x double>", sh.lanes)
	c232 := make([]string, sh.lanes)
	for i := range c232 {
		c232[i] = "double 4294967296.0"
	}
	f0, nz, safe, resF, out := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = uitofp %s %s to %s\n", f0, sh.vecTy(), v, fpTy)
	fmt.Fprintf(c.b, "  %%%s = fcmp oeq %s %%%s, zeroinitializer\n", nz, fpTy, f0)
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s <%s>, %s %%%s\n", safe, sh.lanes, nz, fpTy, strings.Join(c232, ", "), fpTy, f0)
	denom := "%" + safe
	if spec.SubOp != 0 {
		sq := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.v%df64(%s %%%s)\n", sq, fpTy, sh.lanes, fpTy, safe)
		denom = "%" + sq
	}
	fmt.Fprintf(c.b, "  %%%s = fdiv %s <%s>, %s\n", resF, fpTy, strings.Join(c232, ", "), denom)
	fmt.Fprintf(c.b, "  %%%s = fptoui %s %%%s to %s\n", out, fpTy, resF, sh.vecTy())
	return c.storeVShape(ins.Args[1].Reg, "%"+out, sh)
}
