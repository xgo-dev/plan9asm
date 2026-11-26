package x86

import (
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// emitX87SoftwareArithHelpers emits pure-integer, target-independent IEEE-754
// binary80 ({ i64, i16 }) arithmetic helpers when X87Software mode is selected
// and the file uses x87 arithmetic (FADDD*/FSUB*/FMUL*/FDIV*) or FSQRT.
//
// All helpers avoid variable i128 shifts and i128 division so LLVM lowers them
// inline with zero external runtime libcalls across 386, amd64, arm64, arm,
// wasm, Linux, macOS, and Windows MSVC.
func emitX87SoftwareArithHelpers(b *strings.Builder, file *asm.File) {
	needAdd, needMul, needDiv, needSqrt := false, false, false, false
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			op := asm.NormalizeInstructionOpcode(ins.Op)
			if op == "FSQRT" {
				needSqrt = true
				continue
			}
			if spec, ok := x87ArithSpecs[asm.Op(op)]; ok {
				switch spec.llvmOp {
				case "fadd", "fsub":
					needAdd = true
				case "fmul":
					needMul = true
				case "fdiv":
					needDiv = true
				}
			}
		}
	}
	if !needAdd && !needMul && !needDiv && !needSqrt {
		return
	}
	b.WriteString(x87SoftFPRoundPackIR)
	if needAdd {
		b.WriteString(x87SoftFPAddIR)
	}
	if needMul {
		b.WriteString(x87SoftFPMulIR)
	}
	if needDiv {
		b.WriteString(x87SoftFPDivIR)
	}
	if needSqrt {
		b.WriteString(x87SoftFPSqrtIR)
	}
}

func (c *amd64Ctx) x87PortableArith(llvmOp string, lhs, rhs x87Value, cw string) x87Value {
	switch llvmOp {
	case "fadd":
		return x87Value(c.x87IR("call %s @__plan9asm_x87_add(%s %s, %s %s, i16 %s, i1 false)",
			x87ValueType, x87ValueType, lhs, x87ValueType, rhs, cw))
	case "fsub":
		return x87Value(c.x87IR("call %s @__plan9asm_x87_add(%s %s, %s %s, i16 %s, i1 true)",
			x87ValueType, x87ValueType, lhs, x87ValueType, rhs, cw))
	case "fmul":
		return x87Value(c.x87IR("call %s @__plan9asm_x87_mul(%s %s, %s %s, i16 %s)",
			x87ValueType, x87ValueType, lhs, x87ValueType, rhs, cw))
	default: // fdiv
		return x87Value(c.x87IR("call %s @__plan9asm_x87_div(%s %s, %s %s, i16 %s)",
			x87ValueType, x87ValueType, lhs, x87ValueType, rhs, cw))
	}
}

func (c *amd64Ctx) x87PortableSqrt(val x87Value, cw string) x87Value {
	return x87Value(c.x87IR("call %s @__plan9asm_x87_sqrt(%s %s, i16 %s)",
		x87ValueType, x87ValueType, val, cw))
}

// x87SoftFPRoundPackIR defines:
//
//	@__plan9asm_x87_round_pack(i1 %sign, i32 %exp, i64 %sig, i64 %rem, i16 %cw) -> { i64, i16 }
//
// %sig must have bit 63 == 1 (normalized finite magnitude). %rem holds bit 63
// as the round (halfway) bit and bits 62:0 as sticky bits. Respects both RC
// (bits 11:10) and PC (bits 9:8) of the x87 control word %cw.
const x87SoftFPRoundPackIR = `define internal { i64, i16 } @__plan9asm_x87_round_pack(i1 %sign, i32 %exp, i64 %sig, i64 %rem, i16 %cw) {
entry:
  %is_sub = icmp sle i32 %exp, 0
  br i1 %is_sub, label %subnormal, label %normal

subnormal:
  %s32 = sub i32 1, %exp
  %rem_nz = icmp ne i64 %rem, 0
  %rem_st = zext i1 %rem_nz to i64
  %s_ge65 = icmp sge i32 %s32, 65
  %s_eq64 = icmp eq i32 %s32, 64
  %s_lt64 = icmp slt i32 %s32, 64
  %safe_s32 = select i1 %s_lt64, i32 %s32, i32 1
  %safe_s = zext i32 %safe_s32 to i64
  %inv_s = sub i64 64, %safe_s
  %sh_sig = lshr i64 %sig, %safe_s
  %sh_out = shl i64 %sig, %inv_s
  %sh_rem = or i64 %sh_out, %rem_st
  %rem64 = or i64 %sig, %rem_st
  %sub_sig = select i1 %s_lt64, i64 %sh_sig, i64 0
  %sub_rem_0 = select i1 %s_eq64, i64 %rem64, i64 1
  %sub_rem = select i1 %s_lt64, i64 %sh_rem, i64 %sub_rem_0
  %sub_rem_final = select i1 %s_ge65, i64 1, i64 %sub_rem
  br label %apply_pc

normal:
  br label %apply_pc

apply_pc:
  %eff_exp = phi i32 [ 0, %subnormal ], [ %exp, %normal ]
  %eff_sig = phi i64 [ %sub_sig, %subnormal ], [ %sig, %normal ]
  %eff_rem = phi i64 [ %sub_rem_final, %subnormal ], [ %rem, %normal ]
  %pc_raw = lshr i16 %cw, 8
  %pc = and i16 %pc_raw, 3
  %pc24 = icmp eq i16 %pc, 0
  %pc53 = icmp eq i16 %pc, 2
  %drop_0 = select i1 %pc53, i64 11, i64 0
  %drop = select i1 %pc24, i64 40, i64 %drop_0
  %drop_zero = icmp eq i64 %drop, 0
  %inv_drop = select i1 %drop_zero, i64 0, i64 64
  %inv_drop_sub = sub i64 %inv_drop, %drop
  %sig_low_raw = shl i64 %eff_sig, %inv_drop_sub
  %rem_nz2 = icmp ne i64 %eff_rem, 0
  %rem_st2 = zext i1 %rem_nz2 to i64
  %rem_pc = or i64 %sig_low_raw, %rem_st2
  %sig2 = lshr i64 %eff_sig, %drop
  %rem2 = select i1 %drop_zero, i64 %eff_rem, i64 %rem_pc

  %rc_raw = lshr i16 %cw, 10
  %rc = and i16 %rc_raw, 3
  %inexact = icmp ne i64 %rem2, 0
  %gt_half = icmp ugt i64 %rem2, -9223372036854775808
  %eq_half = icmp eq i64 %rem2, -9223372036854775808
  %lsb = and i64 %sig2, 1
  %odd = icmp ne i64 %lsb, 0
  %tie_up = and i1 %eq_half, %odd
  %rn_up = or i1 %gt_half, %tie_up
  %is_rn = icmp eq i16 %rc, 0
  %is_rd = icmp eq i16 %rc, 1
  %is_ru = icmp eq i16 %rc, 2
  %rd_up = and i1 %is_rd, %sign
  %not_sign = xor i1 %sign, true
  %ru_up = and i1 %is_ru, %not_sign
  %dir_up = or i1 %rd_up, %ru_up
  %dir_inc = and i1 %dir_up, %inexact
  %round_up = select i1 %is_rn, i1 %rn_up, i1 %dir_inc

  %inc = zext i1 %round_up to i64
  %sig3 = add i64 %sig2, %inc
  %sig_back = shl i64 %sig3, %drop
  %sig_back_zero = icmp eq i64 %sig_back, 0
  %carry_out = and i1 %round_up, %sig_back_zero

  %sig_carry = select i1 %carry_out, i64 -9223372036854775808, i64 %sig_back
  %carry_exp = add i32 %eff_exp, 1
  %exp_carry = select i1 %carry_out, i32 %carry_exp, i32 %eff_exp

  %msb_set = icmp slt i64 %sig_carry, 0
  %promote = and i1 %is_sub, %msb_set
  %final_exp = select i1 %promote, i32 1, i32 %exp_carry

  %overflow = icmp sge i32 %final_exp, 32767
  %ovf_inf = or i1 %is_rn, %dir_up
  %max_sig = shl i64 -1, %drop
  %ovf_sig = select i1 %ovf_inf, i64 -9223372036854775808, i64 %max_sig
  %ovf_exp = select i1 %ovf_inf, i32 32767, i32 32766

  %out_sig = select i1 %overflow, i64 %ovf_sig, i64 %sig_carry
  %out_exp32 = select i1 %overflow, i32 %ovf_exp, i32 %final_exp
  %out_exp16 = trunc i32 %out_exp32 to i16
  %sign16 = select i1 %sign, i16 -32768, i16 0
  %out_se = or i16 %out_exp16, %sign16
  %r0 = insertvalue { i64, i16 } zeroinitializer, i64 %out_sig, 0
  %r1 = insertvalue { i64, i16 } %r0, i16 %out_se, 1
  ret { i64, i16 } %r1
}

`

const x87SoftFPAddIR = `define internal { i64, i16 } @__plan9asm_x87_add({ i64, i16 } %a, { i64, i16 } %b, i16 %cw, i1 %sub) {
entry:
  %a_sig = extractvalue { i64, i16 } %a, 0
  %a_se = extractvalue { i64, i16 } %a, 1
  %b_sig = extractvalue { i64, i16 } %b, 0
  %b_se = extractvalue { i64, i16 } %b, 1

  %a_exp16 = and i16 %a_se, 32767
  %b_exp16 = and i16 %b_se, 32767
  %a_sign = icmp slt i16 %a_se, 0
  %b_raw_sign = icmp slt i16 %b_se, 0
  %b_sign = xor i1 %b_raw_sign, %sub

  %a_zexp = icmp eq i16 %a_exp16, 0
  %b_zexp = icmp eq i16 %b_exp16, 0
  %a_msbz = icmp sge i64 %a_sig, 0
  %b_msbz = icmp sge i64 %b_sig, 0
  %a_nzexp = xor i1 %a_zexp, true
  %b_nzexp = xor i1 %b_zexp, true
  %a_unsup = and i1 %a_nzexp, %a_msbz
  %b_unsup = and i1 %b_nzexp, %b_msbz
  %any_unsup = or i1 %a_unsup, %b_unsup
  br i1 %any_unsup, label %ret_indef, label %chk_nan

chk_nan:
  %a_maxe = icmp eq i16 %a_exp16, 32767
  %b_maxe = icmp eq i16 %b_exp16, 32767
  %a_frac = and i64 %a_sig, 9223372036854775807
  %b_frac = and i64 %b_sig, 9223372036854775807
  %a_fnz = icmp ne i64 %a_frac, 0
  %b_fnz = icmp ne i64 %b_frac, 0
  %a_nan = and i1 %a_maxe, %a_fnz
  %b_nan = and i1 %b_maxe, %b_fnz
  %any_nan = or i1 %a_nan, %b_nan
  br i1 %any_nan, label %ret_nan, label %chk_inf

ret_nan:
  %both_nan = and i1 %a_nan, %b_nan
  %b_bigger = icmp ugt i64 %b_sig, %a_sig
  %pick_b_both = and i1 %both_nan, %b_bigger
  %not_a_nan = xor i1 %a_nan, true
  %pick_b = or i1 %pick_b_both, %not_a_nan
  %nan_sig0 = select i1 %pick_b, i64 %b_sig, i64 %a_sig
  %nan_se = select i1 %pick_b, i16 %b_se, i16 %a_se
  %nan_sig = or i64 %nan_sig0, 4611686018427387904
  %rn0 = insertvalue { i64, i16 } zeroinitializer, i64 %nan_sig, 0
  %rn1 = insertvalue { i64, i16 } %rn0, i16 %nan_se, 1
  ret { i64, i16 } %rn1

chk_inf:
  %any_inf = or i1 %a_maxe, %b_maxe
  br i1 %any_inf, label %handle_inf, label %chk_zero

handle_inf:
  %both_inf = and i1 %a_maxe, %b_maxe
  %diff_inf = xor i1 %a_sign, %b_sign
  %inf_indef = and i1 %both_inf, %diff_inf
  br i1 %inf_indef, label %ret_indef, label %ret_inf

ret_inf:
  %inf_sign = select i1 %a_maxe, i1 %a_sign, i1 %b_sign
  %inf_s16 = select i1 %inf_sign, i16 -32768, i16 0
  %inf_se = or i16 %inf_s16, 32767
  %ri0 = insertvalue { i64, i16 } zeroinitializer, i64 -9223372036854775808, 0
  %ri1 = insertvalue { i64, i16 } %ri0, i16 %inf_se, 1
  ret { i64, i16 } %ri1

chk_zero:
  %a_zsig = icmp eq i64 %a_sig, 0
  %b_zsig = icmp eq i64 %b_sig, 0
  %a_zero = and i1 %a_zexp, %a_zsig
  %b_zero = and i1 %b_zexp, %b_zsig
  %both_zero = and i1 %a_zero, %b_zero
  br i1 %both_zero, label %ret_both_zero, label %chk_one_zero

ret_both_zero:
  %rc_z = and i16 %cw, 3072
  %is_rd_z = icmp eq i16 %rc_z, 1024
  %z_and = and i1 %a_sign, %b_sign
  %z_or = or i1 %a_sign, %b_sign
  %z_sign = select i1 %is_rd_z, i1 %z_or, i1 %z_and
  %z_se = select i1 %z_sign, i16 -32768, i16 0
  %rz0 = insertvalue { i64, i16 } zeroinitializer, i64 0, 0
  %rz1 = insertvalue { i64, i16 } %rz0, i16 %z_se, 1
  ret { i64, i16 } %rz1

chk_one_zero:
  %one_zero = or i1 %a_zero, %b_zero
  br i1 %one_zero, label %ret_one_zero, label %finite

ret_one_zero:
  %nz_sig = select i1 %a_zero, i64 %b_sig, i64 %a_sig
  %nz_exp16 = select i1 %a_zero, i16 %b_exp16, i16 %a_exp16
  %nz_sign = select i1 %a_zero, i1 %b_sign, i1 %a_sign
  %nz_zexp = icmp eq i16 %nz_exp16, 0
  %nz_eff16 = select i1 %nz_zexp, i16 1, i16 %nz_exp16
  %nz_eff32 = zext i16 %nz_eff16 to i32
  %nz_lz = call i64 @llvm.ctlz.i64(i64 %nz_sig, i1 false)
  %nz_norm = shl i64 %nz_sig, %nz_lz
  %nz_lz32 = trunc i64 %nz_lz to i32
  %nz_exp = sub i32 %nz_eff32, %nz_lz32
  %nz_res = call { i64, i16 } @__plan9asm_x87_round_pack(i1 %nz_sign, i32 %nz_exp, i64 %nz_norm, i64 0, i16 %cw)
  ret { i64, i16 } %nz_res

finite:
  %a_eff16 = select i1 %a_zexp, i16 1, i16 %a_exp16
  %b_eff16 = select i1 %b_zexp, i16 1, i16 %b_exp16
  %a_eff32 = zext i16 %a_eff16 to i32
  %b_eff32 = zext i16 %b_eff16 to i32
  %a_lz = call i64 @llvm.ctlz.i64(i64 %a_sig, i1 false)
  %b_lz = call i64 @llvm.ctlz.i64(i64 %b_sig, i1 false)
  %a_nsig = shl i64 %a_sig, %a_lz
  %b_nsig = shl i64 %b_sig, %b_lz
  %a_lz32 = trunc i64 %a_lz to i32
  %b_lz32 = trunc i64 %b_lz to i32
  %a_nexp = sub i32 %a_eff32, %a_lz32
  %b_nexp = sub i32 %b_eff32, %b_lz32

  %exp_lt = icmp slt i32 %a_nexp, %b_nexp
  %exp_eq = icmp eq i32 %a_nexp, %b_nexp
  %sig_lt = icmp ult i64 %a_nsig, %b_nsig
  %eq_and_lt = and i1 %exp_eq, %sig_lt
  %swap = or i1 %exp_lt, %eq_and_lt

  %big_sign = select i1 %swap, i1 %b_sign, i1 %a_sign
  %big_exp = select i1 %swap, i32 %b_nexp, i32 %a_nexp
  %big_sig = select i1 %swap, i64 %b_nsig, i64 %a_nsig
  %sml_sign = select i1 %swap, i1 %a_sign, i1 %b_sign
  %sml_exp = select i1 %swap, i32 %a_nexp, i32 %b_nexp
  %sml_sig = select i1 %swap, i64 %a_nsig, i64 %b_nsig

  %diff = sub i32 %big_exp, %sml_exp
  %diff_z = icmp eq i32 %diff, 0
  %diff_lt64 = icmp slt i32 %diff, 64
  %diff_eq64 = icmp eq i32 %diff, 64
  %not_diff_z = xor i1 %diff_z, true
  %in_1_63 = and i1 %diff_lt64, %not_diff_z
  %safe_d32 = select i1 %in_1_63, i32 %diff, i32 1
  %safe_d = zext i32 %safe_d32 to i64
  %inv_d = sub i64 64, %safe_d
  %mid_hi = lshr i64 %sml_sig, %safe_d
  %mid_lo = shl i64 %sml_sig, %inv_d

  %hi_0 = select i1 %in_1_63, i64 %mid_hi, i64 0
  %sml_hi = select i1 %diff_z, i64 %sml_sig, i64 %hi_0
  %lo_ge64 = select i1 %diff_eq64, i64 %sml_sig, i64 1
  %lo_0 = select i1 %in_1_63, i64 %mid_lo, i64 %lo_ge64
  %sml_lo = select i1 %diff_z, i64 0, i64 %lo_0

  %same_sign = icmp eq i1 %big_sign, %sml_sign
  br i1 %same_sign, label %do_add, label %do_sub

do_add:
  %big128 = zext i64 %big_sig to i128
  %sml128 = zext i64 %sml_hi to i128
  %sum128 = add i128 %big128, %sml128
  %carry_bit = lshr i128 %sum128, 64
  %has_carry = icmp ne i128 %carry_bit, 0
  %sum_lo64 = trunc i128 %sum128 to i64
  %sum_shr1 = lshr i128 %sum128, 1
  %sum_shr64 = trunc i128 %sum_shr1 to i64
  %sum_bit0 = shl i64 %sum_lo64, 63
  %sml_lo_nz = icmp ne i64 %sml_lo, 0
  %sml_lo_st = zext i1 %sml_lo_nz to i64
  %carry_rem = or i64 %sum_bit0, %sml_lo_st
  %add_exp1 = add i32 %big_exp, 1
  %add_exp = select i1 %has_carry, i32 %add_exp1, i32 %big_exp
  %add_sig = select i1 %has_carry, i64 %sum_shr64, i64 %sum_lo64
  %add_rem = select i1 %has_carry, i64 %carry_rem, i64 %sml_lo
  %add_res = call { i64, i16 } @__plan9asm_x87_round_pack(i1 %big_sign, i32 %add_exp, i64 %add_sig, i64 %add_rem, i16 %cw)
  ret { i64, i16 } %add_res

do_sub:
  %sig_eq = icmp eq i64 %big_sig, %sml_sig
  %cancel = and i1 %diff_z, %sig_eq
  br i1 %cancel, label %ret_cancel_zero, label %do_sub_calc

ret_cancel_zero:
  %rc_c = and i16 %cw, 3072
  %is_rd_c = icmp eq i16 %rc_c, 1024
  %cz_se = select i1 %is_rd_c, i16 -32768, i16 0
  %rcz0 = insertvalue { i64, i16 } zeroinitializer, i64 0, 0
  %rcz1 = insertvalue { i64, i16 } %rcz0, i16 %cz_se, 1
  ret { i64, i16 } %rcz1

do_sub_calc:
  %sb_hi128 = zext i64 %big_sig to i128
  %sb_full = shl i128 %sb_hi128, 64
  %ss_hi128 = zext i64 %sml_hi to i128
  %ss_hi_sh = shl i128 %ss_hi128, 64
  %ss_lo128 = zext i64 %sml_lo to i128
  %ss_full = or i128 %ss_hi_sh, %ss_lo128
  %d128 = sub i128 %sb_full, %ss_full
  %d_hi128 = lshr i128 %d128, 64
  %d_hi = trunc i128 %d_hi128 to i64
  %d_lo = trunc i128 %d128 to i64
  %d_hi_z = icmp eq i64 %d_hi, 0
  br i1 %d_hi_z, label %sub_lo_only, label %sub_hi_nz

sub_hi_nz:
  %h_lz = call i64 @llvm.ctlz.i64(i64 %d_hi, i1 false)
  %h_lz_z = icmp eq i64 %h_lz, 0
  %h_inv_base = select i1 %h_lz_z, i64 0, i64 64
  %h_inv = sub i64 %h_inv_base, %h_lz
  %h_sh = shl i64 %d_hi, %h_lz
  %l_shr = lshr i64 %d_lo, %h_inv
  %h_comb = or i64 %h_sh, %l_shr
  %sub_sig_h = select i1 %h_lz_z, i64 %d_hi, i64 %h_comb
  %sub_rem_h = shl i64 %d_lo, %h_lz
  %h_lz32 = trunc i64 %h_lz to i32
  %sub_exp_h = sub i32 %big_exp, %h_lz32
  %sub_res_h = call { i64, i16 } @__plan9asm_x87_round_pack(i1 %big_sign, i32 %sub_exp_h, i64 %sub_sig_h, i64 %sub_rem_h, i16 %cw)
  ret { i64, i16 } %sub_res_h

sub_lo_only:
  %l_lz = call i64 @llvm.ctlz.i64(i64 %d_lo, i1 false)
  %sub_sig_l = shl i64 %d_lo, %l_lz
  %l_lz32 = trunc i64 %l_lz to i32
  %sub_exp_l0 = sub i32 %big_exp, 64
  %sub_exp_l = sub i32 %sub_exp_l0, %l_lz32
  %sub_res_l = call { i64, i16 } @__plan9asm_x87_round_pack(i1 %big_sign, i32 %sub_exp_l, i64 %sub_sig_l, i64 0, i16 %cw)
  ret { i64, i16 } %sub_res_l

ret_indef:
  %ind0 = insertvalue { i64, i16 } zeroinitializer, i64 -4611686018427387904, 0
  %ind1 = insertvalue { i64, i16 } %ind0, i16 -1, 1
  ret { i64, i16 } %ind1
}

`

const x87SoftFPMulIR = `define internal { i64, i16 } @__plan9asm_x87_mul({ i64, i16 } %a, { i64, i16 } %b, i16 %cw) {
entry:
  %a_sig = extractvalue { i64, i16 } %a, 0
  %a_se = extractvalue { i64, i16 } %a, 1
  %b_sig = extractvalue { i64, i16 } %b, 0
  %b_se = extractvalue { i64, i16 } %b, 1

  %a_exp16 = and i16 %a_se, 32767
  %b_exp16 = and i16 %b_se, 32767
  %a_sign = icmp slt i16 %a_se, 0
  %b_sign = icmp slt i16 %b_se, 0
  %res_sign = xor i1 %a_sign, %b_sign

  %a_zexp = icmp eq i16 %a_exp16, 0
  %b_zexp = icmp eq i16 %b_exp16, 0
  %a_msbz = icmp sge i64 %a_sig, 0
  %b_msbz = icmp sge i64 %b_sig, 0
  %a_nzexp = xor i1 %a_zexp, true
  %b_nzexp = xor i1 %b_zexp, true
  %a_unsup = and i1 %a_nzexp, %a_msbz
  %b_unsup = and i1 %b_nzexp, %b_msbz
  %any_unsup = or i1 %a_unsup, %b_unsup
  br i1 %any_unsup, label %ret_indef, label %chk_nan

chk_nan:
  %a_maxe = icmp eq i16 %a_exp16, 32767
  %b_maxe = icmp eq i16 %b_exp16, 32767
  %a_frac = and i64 %a_sig, 9223372036854775807
  %b_frac = and i64 %b_sig, 9223372036854775807
  %a_fnz = icmp ne i64 %a_frac, 0
  %b_fnz = icmp ne i64 %b_frac, 0
  %a_nan = and i1 %a_maxe, %a_fnz
  %b_nan = and i1 %b_maxe, %b_fnz
  %any_nan = or i1 %a_nan, %b_nan
  br i1 %any_nan, label %ret_nan, label %chk_inf_zero

ret_nan:
  %both_nan = and i1 %a_nan, %b_nan
  %b_bigger = icmp ugt i64 %b_sig, %a_sig
  %pick_b_both = and i1 %both_nan, %b_bigger
  %not_a_nan = xor i1 %a_nan, true
  %pick_b = or i1 %pick_b_both, %not_a_nan
  %nan_sig0 = select i1 %pick_b, i64 %b_sig, i64 %a_sig
  %nan_se = select i1 %pick_b, i16 %b_se, i16 %a_se
  %nan_sig = or i64 %nan_sig0, 4611686018427387904
  %rn0 = insertvalue { i64, i16 } zeroinitializer, i64 %nan_sig, 0
  %rn1 = insertvalue { i64, i16 } %rn0, i16 %nan_se, 1
  ret { i64, i16 } %rn1

chk_inf_zero:
  %a_zsig = icmp eq i64 %a_sig, 0
  %b_zsig = icmp eq i64 %b_sig, 0
  %a_zero = and i1 %a_zexp, %a_zsig
  %b_zero = and i1 %b_zexp, %b_zsig
  %inf_x_zero1 = and i1 %a_maxe, %b_zero
  %inf_x_zero2 = and i1 %b_maxe, %a_zero
  %inf_x_zero = or i1 %inf_x_zero1, %inf_x_zero2
  br i1 %inf_x_zero, label %ret_indef, label %chk_inf

chk_inf:
  %any_inf = or i1 %a_maxe, %b_maxe
  br i1 %any_inf, label %ret_inf, label %chk_zero

ret_inf:
  %inf_s16 = select i1 %res_sign, i16 -32768, i16 0
  %inf_se = or i16 %inf_s16, 32767
  %ri0 = insertvalue { i64, i16 } zeroinitializer, i64 -9223372036854775808, 0
  %ri1 = insertvalue { i64, i16 } %ri0, i16 %inf_se, 1
  ret { i64, i16 } %ri1

chk_zero:
  %any_zero = or i1 %a_zero, %b_zero
  br i1 %any_zero, label %ret_zero, label %finite

ret_zero:
  %z_se = select i1 %res_sign, i16 -32768, i16 0
  %rz0 = insertvalue { i64, i16 } zeroinitializer, i64 0, 0
  %rz1 = insertvalue { i64, i16 } %rz0, i16 %z_se, 1
  ret { i64, i16 } %rz1

finite:
  %a_eff16 = select i1 %a_zexp, i16 1, i16 %a_exp16
  %b_eff16 = select i1 %b_zexp, i16 1, i16 %b_exp16
  %a_eff32 = zext i16 %a_eff16 to i32
  %b_eff32 = zext i16 %b_eff16 to i32
  %a_lz = call i64 @llvm.ctlz.i64(i64 %a_sig, i1 false)
  %b_lz = call i64 @llvm.ctlz.i64(i64 %b_sig, i1 false)
  %a_nsig = shl i64 %a_sig, %a_lz
  %b_nsig = shl i64 %b_sig, %b_lz
  %a_lz32 = trunc i64 %a_lz to i32
  %b_lz32 = trunc i64 %b_lz to i32
  %a_nexp = sub i32 %a_eff32, %a_lz32
  %b_nexp = sub i32 %b_eff32, %b_lz32

  %a128 = zext i64 %a_nsig to i128
  %b128 = zext i64 %b_nsig to i128
  %prod = mul i128 %a128, %b128
  %phi128 = lshr i128 %prod, 64
  %p_hi = trunc i128 %phi128 to i64
  %p_lo = trunc i128 %prod to i64

  %exp_sum = add i32 %a_nexp, %b_nexp
  %base_exp = sub i32 %exp_sum, 16383
  %msb = icmp slt i64 %p_hi, 0
  %exp_p1 = add i32 %base_exp, 1
  %sh_hi = shl i64 %p_hi, 1
  %lo_top = lshr i64 %p_lo, 63
  %norm_sig = or i64 %sh_hi, %lo_top
  %norm_rem = shl i64 %p_lo, 1

  %out_exp = select i1 %msb, i32 %exp_p1, i32 %base_exp
  %out_sig = select i1 %msb, i64 %p_hi, i64 %norm_sig
  %out_rem = select i1 %msb, i64 %p_lo, i64 %norm_rem
  %res = call { i64, i16 } @__plan9asm_x87_round_pack(i1 %res_sign, i32 %out_exp, i64 %out_sig, i64 %out_rem, i16 %cw)
  ret { i64, i16 } %res

ret_indef:
  %ind0 = insertvalue { i64, i16 } zeroinitializer, i64 -4611686018427387904, 0
  %ind1 = insertvalue { i64, i16 } %ind0, i16 -1, 1
  ret { i64, i16 } %ind1
}

`

const x87SoftFPDivIR = `define internal { i64, i16 } @__plan9asm_x87_div({ i64, i16 } %a, { i64, i16 } %b, i16 %cw) {
entry:
  %a_sig = extractvalue { i64, i16 } %a, 0
  %a_se = extractvalue { i64, i16 } %a, 1
  %b_sig = extractvalue { i64, i16 } %b, 0
  %b_se = extractvalue { i64, i16 } %b, 1

  %a_exp16 = and i16 %a_se, 32767
  %b_exp16 = and i16 %b_se, 32767
  %a_sign = icmp slt i16 %a_se, 0
  %b_sign = icmp slt i16 %b_se, 0
  %res_sign = xor i1 %a_sign, %b_sign

  %a_zexp = icmp eq i16 %a_exp16, 0
  %b_zexp = icmp eq i16 %b_exp16, 0
  %a_msbz = icmp sge i64 %a_sig, 0
  %b_msbz = icmp sge i64 %b_sig, 0
  %a_nzexp = xor i1 %a_zexp, true
  %b_nzexp = xor i1 %b_zexp, true
  %a_unsup = and i1 %a_nzexp, %a_msbz
  %b_unsup = and i1 %b_nzexp, %b_msbz
  %any_unsup = or i1 %a_unsup, %b_unsup
  br i1 %any_unsup, label %ret_indef, label %chk_nan

chk_nan:
  %a_maxe = icmp eq i16 %a_exp16, 32767
  %b_maxe = icmp eq i16 %b_exp16, 32767
  %a_frac = and i64 %a_sig, 9223372036854775807
  %b_frac = and i64 %b_sig, 9223372036854775807
  %a_fnz = icmp ne i64 %a_frac, 0
  %b_fnz = icmp ne i64 %b_frac, 0
  %a_nan = and i1 %a_maxe, %a_fnz
  %b_nan = and i1 %b_maxe, %b_fnz
  %any_nan = or i1 %a_nan, %b_nan
  br i1 %any_nan, label %ret_nan, label %chk_special

ret_nan:
  %both_nan = and i1 %a_nan, %b_nan
  %b_bigger = icmp ugt i64 %b_sig, %a_sig
  %pick_b_both = and i1 %both_nan, %b_bigger
  %not_a_nan = xor i1 %a_nan, true
  %pick_b = or i1 %pick_b_both, %not_a_nan
  %nan_sig0 = select i1 %pick_b, i64 %b_sig, i64 %a_sig
  %nan_se = select i1 %pick_b, i16 %b_se, i16 %a_se
  %nan_sig = or i64 %nan_sig0, 4611686018427387904
  %rn0 = insertvalue { i64, i16 } zeroinitializer, i64 %nan_sig, 0
  %rn1 = insertvalue { i64, i16 } %rn0, i16 %nan_se, 1
  ret { i64, i16 } %rn1

chk_special:
  %a_zsig = icmp eq i64 %a_sig, 0
  %b_zsig = icmp eq i64 %b_sig, 0
  %a_zero = and i1 %a_zexp, %a_zsig
  %b_zero = and i1 %b_zexp, %b_zsig
  %inf_div_inf = and i1 %a_maxe, %b_maxe
  %zero_div_zero = and i1 %a_zero, %b_zero
  %is_indef = or i1 %inf_div_inf, %zero_div_zero
  br i1 %is_indef, label %ret_indef, label %chk_inf

chk_inf:
  %make_inf = or i1 %a_maxe, %b_zero
  br i1 %make_inf, label %ret_inf, label %chk_zero

ret_inf:
  %inf_s16 = select i1 %res_sign, i16 -32768, i16 0
  %inf_se = or i16 %inf_s16, 32767
  %ri0 = insertvalue { i64, i16 } zeroinitializer, i64 -9223372036854775808, 0
  %ri1 = insertvalue { i64, i16 } %ri0, i16 %inf_se, 1
  ret { i64, i16 } %ri1

chk_zero:
  %make_zero = or i1 %a_zero, %b_maxe
  br i1 %make_zero, label %ret_zero, label %finite

ret_zero:
  %z_se = select i1 %res_sign, i16 -32768, i16 0
  %rz0 = insertvalue { i64, i16 } zeroinitializer, i64 0, 0
  %rz1 = insertvalue { i64, i16 } %rz0, i16 %z_se, 1
  ret { i64, i16 } %rz1

finite:
  %a_eff16 = select i1 %a_zexp, i16 1, i16 %a_exp16
  %b_eff16 = select i1 %b_zexp, i16 1, i16 %b_exp16
  %a_eff32 = zext i16 %a_eff16 to i32
  %b_eff32 = zext i16 %b_eff16 to i32
  %a_lz = call i64 @llvm.ctlz.i64(i64 %a_sig, i1 false)
  %b_lz = call i64 @llvm.ctlz.i64(i64 %b_sig, i1 false)
  %a_nsig = shl i64 %a_sig, %a_lz
  %b_nsig = shl i64 %b_sig, %b_lz
  %a_lz32 = trunc i64 %a_lz to i32
  %b_lz32 = trunc i64 %b_lz to i32
  %a_nexp = sub i32 %a_eff32, %a_lz32
  %b_nexp = sub i32 %b_eff32, %b_lz32

  %exp_diff = sub i32 %a_nexp, %b_nexp
  %exp_base = add i32 %exp_diff, 16383
  %a_lt_b = icmp ult i64 %a_nsig, %b_nsig
  %exp_m1 = sub i32 %exp_base, 1
  %res_exp = select i1 %a_lt_b, i32 %exp_m1, i32 %exp_base

  %rem0_raw = zext i64 %a_nsig to i128
  %rem0_sh = shl i128 %rem0_raw, 1
  %rem0 = select i1 %a_lt_b, i128 %rem0_sh, i128 %rem0_raw
  %den = zext i64 %b_nsig to i128
  br label %loop

loop:
  %i = phi i32 [ 0, %finite ], [ %i_next, %loop ]
  %rem = phi i128 [ %rem0, %finite ], [ %rem_next, %loop ]
  %q = phi i64 [ 0, %finite ], [ %q_next, %loop ]
  %ge = icmp uge i128 %rem, %den
  %rem_sub = sub i128 %rem, %den
  %rem_sel = select i1 %ge, i128 %rem_sub, i128 %rem
  %rem_next = shl i128 %rem_sel, 1
  %q_sh = shl i64 %q, 1
  %q_bit = zext i1 %ge to i64
  %q_next = or i64 %q_sh, %q_bit
  %i_next = add i32 %i, 1
  %done = icmp eq i32 %i_next, 64
  br i1 %done, label %after_loop, label %loop

after_loop:
  %r_ge = icmp uge i128 %rem_next, %den
  %r_sub = sub i128 %rem_next, %den
  %r_final = select i1 %r_ge, i128 %r_sub, i128 %rem_next
  %sticky = icmp ne i128 %r_final, 0
  %r_top = select i1 %r_ge, i64 -9223372036854775808, i64 0
  %r_st = zext i1 %sticky to i64
  %out_rem = or i64 %r_top, %r_st
  %res = call { i64, i16 } @__plan9asm_x87_round_pack(i1 %res_sign, i32 %res_exp, i64 %q_next, i64 %out_rem, i16 %cw)
  ret { i64, i16 } %res

ret_indef:
  %ind0 = insertvalue { i64, i16 } zeroinitializer, i64 -4611686018427387904, 0
  %ind1 = insertvalue { i64, i16 } %ind0, i16 -1, 1
  ret { i64, i16 } %ind1
}

`

const x87SoftFPSqrtIR = `define internal { i64, i16 } @__plan9asm_x87_sqrt({ i64, i16 } %a, i16 %cw) {
entry:
  %a_sig = extractvalue { i64, i16 } %a, 0
  %a_se = extractvalue { i64, i16 } %a, 1
  %a_exp16 = and i16 %a_se, 32767
  %a_sign = icmp slt i16 %a_se, 0
  %a_zexp = icmp eq i16 %a_exp16, 0
  %a_msbz = icmp sge i64 %a_sig, 0
  %a_nzexp = xor i1 %a_zexp, true
  %a_unsup = and i1 %a_nzexp, %a_msbz
  br i1 %a_unsup, label %ret_indef, label %chk_nan

chk_nan:
  %a_maxe = icmp eq i16 %a_exp16, 32767
  %a_frac = and i64 %a_sig, 9223372036854775807
  %a_fnz = icmp ne i64 %a_frac, 0
  %a_nan = and i1 %a_maxe, %a_fnz
  br i1 %a_nan, label %ret_nan, label %chk_zero

ret_nan:
  %qnan_sig = or i64 %a_sig, 4611686018427387904
  %rn0 = insertvalue { i64, i16 } zeroinitializer, i64 %qnan_sig, 0
  %rn1 = insertvalue { i64, i16 } %rn0, i16 %a_se, 1
  ret { i64, i16 } %rn1

chk_zero:
  %a_zsig = icmp eq i64 %a_sig, 0
  %a_zero = and i1 %a_zexp, %a_zsig
  br i1 %a_zero, label %ret_self, label %chk_neg

ret_self:
  ret { i64, i16 } %a

chk_neg:
  br i1 %a_sign, label %ret_indef, label %chk_inf

chk_inf:
  br i1 %a_maxe, label %ret_self, label %finite

finite:
  %a_eff16 = select i1 %a_zexp, i16 1, i16 %a_exp16
  %a_eff32 = zext i16 %a_eff16 to i32
  %a_lz = call i64 @llvm.ctlz.i64(i64 %a_sig, i1 false)
  %a_nsig = shl i64 %a_sig, %a_lz
  %a_lz32 = trunc i64 %a_lz to i32
  %a_nexp = sub i32 %a_eff32, %a_lz32

  %unbiased = sub i32 %a_nexp, 16383
  %odd_bit = and i32 %unbiased, 1
  %is_odd = icmp ne i32 %odd_bit, 0
  %unb_m1 = sub i32 %unbiased, 1
  %even_unb = select i1 %is_odd, i32 %unb_m1, i32 %unbiased
  %half_unb = ashr i32 %even_unb, 1
  %res_exp = add i32 %half_unb, 16383

  %hi_even = lshr i64 %a_nsig, 63
  %hi_odd = lshr i64 %a_nsig, 62
  %hi2_64 = select i1 %is_odd, i64 %hi_odd, i64 %hi_even
  %rem0 = zext i64 %hi2_64 to i128
  %mid_even = shl i64 %a_nsig, 1
  %mid_odd = shl i64 %a_nsig, 2
  %feed0 = select i1 %is_odd, i64 %mid_odd, i64 %mid_even
  br label %loop

loop:
  %i = phi i32 [ 0, %finite ], [ %i_next, %loop_cont ]
  %rem = phi i128 [ %rem0, %finite ], [ %rem_next, %loop_cont ]
  %feed = phi i64 [ %feed0, %finite ], [ %feed_next, %loop_cont ]
  %root = phi i128 [ 0, %finite ], [ %root_next, %loop_cont ]
  %trial0 = shl i128 %root, 2
  %trial = or i128 %trial0, 1
  %ge = icmp uge i128 %rem, %trial
  %rem_sub = sub i128 %rem, %trial
  %rem_sel = select i1 %ge, i128 %rem_sub, i128 %rem
  %root_sh = shl i128 %root, 1
  %root_bit = zext i1 %ge to i128
  %root_next = or i128 %root_sh, %root_bit
  %i_next = add i32 %i, 1
  %done = icmp eq i32 %i_next, 65
  br i1 %done, label %after_loop, label %loop_cont

loop_cont:
  %next2_64 = lshr i64 %feed, 62
  %next2 = zext i64 %next2_64 to i128
  %feed_next = shl i64 %feed, 2
  %rem_sh = shl i128 %rem_sel, 2
  %rem_next = or i128 %rem_sh, %next2
  br label %loop

after_loop:
  %q128 = lshr i128 %root_next, 1
  %q = trunc i128 %q128 to i64
  %r_bit128 = and i128 %root_next, 1
  %r_bit = icmp ne i128 %r_bit128, 0
  %sticky = icmp ne i128 %rem_sel, 0
  %r_top = select i1 %r_bit, i64 -9223372036854775808, i64 0
  %r_st = zext i1 %sticky to i64
  %out_rem = or i64 %r_top, %r_st
  %res = call { i64, i16 } @__plan9asm_x87_round_pack(i1 false, i32 %res_exp, i64 %q, i64 %out_rem, i16 %cw)
  ret { i64, i16 } %res

ret_indef:
  %ind0 = insertvalue { i64, i16 } zeroinitializer, i64 -4611686018427387904, 0
  %ind1 = insertvalue { i64, i16 } %ind0, i16 -1, 1
  ret { i64, i16 } %ind1
}

`
