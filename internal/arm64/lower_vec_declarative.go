package arm64

import (
	"fmt"
	"math"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// arm64NEONSpecs declaratively models AArch64 NEON/ASIMD instructions so one
// lane-geometry engine lowers all `.B8/.B16/.H4/.H8/.S2/.S4/.D2` shapes cleanly.
var arm64NEONSpecs = []asm.OpSpec{
	// Integer unary
	{Op: "VABS", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "abs"},
	{Op: "VSQABS", Family: asm.FamilyVecUnary, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqabs"},
	{Op: "VNEG", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "neg"},
	{Op: "VSQNEG", Family: asm.FamilyVecUnary, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqneg"},
	{Op: "VNOT", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "not"},
	{Op: "VCLZ", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "clz"},
	{Op: "VCLS", Family: asm.FamilyVecUnary, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "cls"},
	{Op: "VCNT", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "ctpop"},
	{Op: "VRBIT", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "bitreverse"},
	{Op: "VREV16", Family: asm.FamilyVecUnary, Effect: asm.EffectWriteOnly, LLVMOp: "rev16"},

	// Integer binary
	{Op: "VSUB", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sub"},
	{Op: "VMUL", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mul"},
	{Op: "VBIC", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "bic"},
	{Op: "VORN", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "orn"},
	{Op: "VSMAX", Family: asm.FamilyVecBinOp, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "smax"},
	{Op: "VSMIN", Family: asm.FamilyVecBinOp, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "smin"},
	{Op: "VUMAX", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "umax"},
	{Op: "VUMIN", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "umin"},
	{Op: "VSQADD", Family: asm.FamilyVecBinOp, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sadd.sat"},
	{Op: "VUQADD", Family: asm.FamilyVecBinOp, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uadd.sat"},
	{Op: "VSQSUB", Family: asm.FamilyVecBinOp, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "ssub.sat"},
	{Op: "VUQSUB", Family: asm.FamilyVecBinOp, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "usub.sat"},
	{Op: "VSHADD", Family: asm.FamilyVecBinOp, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "shadd"},
	{Op: "VUHADD", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uhadd"},
	{Op: "VSRHADD", Family: asm.FamilyVecBinOp, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "srhadd"},
	{Op: "VURHADD", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "urhadd"},
	{Op: "VCMTST", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "cmtst"},
	{Op: "VBSL", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "bsl"},
	{Op: "VBIT", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "bit"},
	{Op: "VBIF", Family: asm.FamilyVecBinOp, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "bif"},
	{Op: "VMLA", Family: asm.FamilyVecFMA, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mla"},
	{Op: "VMLS", Family: asm.FamilyVecFMA, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mls"},

	// Integer compare (reg-reg or $0)
	{Op: "VCMGE", Family: asm.FamilyCompare, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sge"},
	{Op: "VCMGT", Family: asm.FamilyCompare, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sgt"},
	{Op: "VCMLE", Family: asm.FamilyCompare, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sle"},
	{Op: "VCMLT", Family: asm.FamilyCompare, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "slt"},
	{Op: "VCMHI", Family: asm.FamilyCompare, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "ugt"},
	{Op: "VCMHS", Family: asm.FamilyCompare, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uge"},

	// Integer shifts
	{Op: "VSSHL", Family: asm.FamilyVecShift, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sshl"},
	{Op: "VUSHL", Family: asm.FamilyVecShift, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "ushl"},
	{Op: "VSQSHL", Family: asm.FamilyVecShift, Signed: true, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqshl"},
	{Op: "VUQSHL", Family: asm.FamilyVecShift, Saturating: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uqshl"},
	{Op: "VSSHR", Family: asm.FamilyVecShift, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "ashr"},
	{Op: "VSRSHR", Family: asm.FamilyVecShift, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "srshr"},
	{Op: "VSLI", Family: asm.FamilyVecShift, Effect: asm.EffectReadWrite, LLVMOp: "sli"},
	{Op: "VUSRA", Family: asm.FamilyVecShift, Effect: asm.EffectReadWrite, LLVMOp: "usra"},

	// Float binary / unary / FMA / cmp / cvt
	{Op: "VFADD", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "fadd"},
	{Op: "VFSUB", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "fsub"},
	{Op: "VFMUL", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "fmul"},
	{Op: "VFDIV", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "fdiv"},
	{Op: "VFMAX", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "maximum"},
	{Op: "VFMIN", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "minimum"},
	{Op: "VFMAXNM", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "maxnum"},
	{Op: "VFMINNM", Family: asm.FamilyVecBinOp, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "minnum"},
	{Op: "VFABS", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fabs"},
	{Op: "VFNEG", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fneg"},
	{Op: "VFSQRT", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "sqrt"},
	{Op: "VFRINTM", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "floor"},
	{Op: "VFRINTN", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "roundeven"},
	{Op: "VFRINTP", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "ceil"},
	{Op: "VFRINTZ", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "trunc"},
	{Op: "VFCVTZS", Family: asm.FamilyVecUnary, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "fptosi"},
	{Op: "VFCVTZU", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fptoui"},
	{Op: "VSCVTF", Family: asm.FamilyVecUnary, Float: true, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "sitofp"},
	{Op: "VUCVTF", Family: asm.FamilyVecUnary, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "uitofp"},
	{Op: "VFMLA", Family: asm.FamilyVecFMA, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "fmla"},
	{Op: "VFMLS", Family: asm.FamilyVecFMA, Float: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "fmls"},
	{Op: "VFCMEQ", Family: asm.FamilyCompare, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "oeq"},
	{Op: "VFCMGE", Family: asm.FamilyCompare, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "oge"},
	{Op: "VFCMGT", Family: asm.FamilyCompare, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "ogt"},
	{Op: "VFCMLE", Family: asm.FamilyCompare, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "ole"},
	{Op: "VFCMLT", Family: asm.FamilyCompare, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "olt"},

	// Pairwise, reductions, permutes, widens, narrows
	{Op: "VADDV", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_add"},
	{Op: "VSMAXV", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_smax"},
	{Op: "VSMINV", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_smin"},
	{Op: "VUMAXV", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_umax"},
	{Op: "VUMINV", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_umin"},
	{Op: "VFMAXV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_fmax"},
	{Op: "VFMINV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_fmin"},
	{Op: "VFMAXNMV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_fmaxnm"},
	{Op: "VFMINNMV", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "reduce_fminnm"},
	{Op: "VSMAXP", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_smax"},
	{Op: "VSMINP", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_smin"},
	{Op: "VUMAXP", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_umax"},
	{Op: "VUMINP", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_umin"},
	{Op: "VFADDP", Family: asm.FamilyVecShuffle, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_fadd"},
	{Op: "VFMAXP", Family: asm.FamilyVecShuffle, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_fmax"},
	{Op: "VFMINP", Family: asm.FamilyVecShuffle, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_fmin"},
	{Op: "VFMAXNMP", Family: asm.FamilyVecShuffle, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_fmaxnm"},
	{Op: "VFMINNMP", Family: asm.FamilyVecShuffle, Float: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "pair_fminnm"},
	{Op: "VTRN1", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "trn1"},
	{Op: "VTRN2", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "trn2"},
	{Op: "VUZP1", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uzp1"},
	{Op: "VUZP2", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uzp2"},
	{Op: "VTBX", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "tbx"},

	// Widening / narrowing / long ops
	{Op: "VSXTL", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "widen"},
	{Op: "VSXTL2", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "widen2"},
	{Op: "VUXTL", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "widen"},
	{Op: "VUXTL2", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "widen2"},
	{Op: "VSSHLL", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "shll"},
	{Op: "VSSHLL2", Family: asm.FamilyVecShuffle, Signed: true, Effect: asm.EffectWriteOnly, LLVMOp: "shll2"},
	{Op: "VUSHLL", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "shll"},
	{Op: "VUSHLL2", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "shll2"},
	{Op: "VSMULL", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull"},
	{Op: "VSMULL2", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull2"},
	{Op: "VUMULL", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull"},
	{Op: "VUMULL2", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "mull2"},
	{Op: "VSMLAL", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlal"},
	{Op: "VSMLAL2", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlal2"},
	{Op: "VUMLAL", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlal"},
	{Op: "VUMLAL2", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlal2"},
	{Op: "VSMLSL", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlsl"},
	{Op: "VSMLSL2", Family: asm.FamilyVecShuffle, Signed: true, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlsl2"},
	{Op: "VUMLSL", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlsl"},
	{Op: "VUMLSL2", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectReadWrite, LLVMOp: "mlsl2"},
	{Op: "VUADDW", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uaddw"},
	{Op: "VUADDW2", Family: asm.FamilyVecShuffle, ThreeOp: true, Effect: asm.EffectWriteOnly, LLVMOp: "uaddw2"},
	{Op: "VXTN", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "xtn"},
	{Op: "VXTN2", Family: asm.FamilyVecShuffle, Effect: asm.EffectReadWrite, LLVMOp: "xtn2"},
	{Op: "VSQXTN", Family: asm.FamilyVecShuffle, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "xtn"},
	{Op: "VSQXTN2", Family: asm.FamilyVecShuffle, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "xtn2"},
	{Op: "VUQXTN", Family: asm.FamilyVecShuffle, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "xtn"},
	{Op: "VUQXTN2", Family: asm.FamilyVecShuffle, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "xtn2"},
	{Op: "VSQXTUN", Family: asm.FamilyVecShuffle, Signed: true, Saturating: true, Effect: asm.EffectWriteOnly, LLVMOp: "xtn"},
	{Op: "VSQXTUN2", Family: asm.FamilyVecShuffle, Signed: true, Saturating: true, Effect: asm.EffectReadWrite, LLVMOp: "xtn2"},
	{Op: "VSHRN", Family: asm.FamilyVecShuffle, Effect: asm.EffectWriteOnly, LLVMOp: "shrn"},
	{Op: "VSHRN2", Family: asm.FamilyVecShuffle, Effect: asm.EffectReadWrite, LLVMOp: "shrn2"},
	{Op: "VFCVTL", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtl"},
	{Op: "VFCVTL2", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtl2"},
	{Op: "VFCVTN", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectWriteOnly, LLVMOp: "fcvtn"},
	{Op: "VFCVTN2", Family: asm.FamilyVecShuffle, Float: true, Effect: asm.EffectReadWrite, LLVMOp: "fcvtn2"},

	// Immediate vector moves & multi-register struct load/store
	{Op: "VMOVS", Family: asm.FamilyMove, Width: 32, Effect: asm.EffectWriteOnly, LLVMOp: "vmovimm"},
	{Op: "VMOVD", Family: asm.FamilyMove, Width: 64, Effect: asm.EffectWriteOnly, LLVMOp: "vmovimm"},
	{Op: "VMOVQ", Family: asm.FamilyMove, Width: 128, Effect: asm.EffectWriteOnly, LLVMOp: "vmovimm"},
	{Op: "VLD2", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vldn"},
	{Op: "VLD2R", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vldnr"},
	{Op: "VLD3", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vldn"},
	{Op: "VLD3R", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vldnr"},
	{Op: "VLD4", Family: asm.FamilyMove, Effect: asm.EffectWriteOnly, LLVMOp: "vldn"},
	{Op: "VST2", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vstn"},
	{Op: "VST3", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vstn"},
	{Op: "VST4", Family: asm.FamilyMove, Effect: asm.EffectReadOnly, LLVMOp: "vstn"},
}

var arm64NEONTable = asm.NewOpTable(arm64NEONSpecs)

type neonShape struct {
	lanes    int
	elemBits int
	half64   bool
	float    bool
}

func (s neonShape) elemTy() string {
	if s.float {
		if s.elemBits == 32 {
			return "float"
		}
		return "double"
	}
	return fmt.Sprintf("i%d", s.elemBits)
}

func (s neonShape) vecTy() string {
	return fmt.Sprintf("<%d x %s>", s.lanes, s.elemTy())
}

func (s neonShape) fullLanes() int {
	return 128 / s.elemBits
}

func (s neonShape) fullVecTy() string {
	return fmt.Sprintf("<%d x %s>", s.fullLanes(), s.elemTy())
}

func (s neonShape) intrSuffix() string {
	if s.float {
		return fmt.Sprintf("v%df%d", s.lanes, s.elemBits)
	}
	return fmt.Sprintf("v%di%d", s.lanes, s.elemBits)
}

func parseNEONShape(r asm.Reg, isFloat bool) neonShape {
	s := strings.ToUpper(strings.TrimSpace(string(r)))
	if dot := strings.IndexByte(s, '.'); dot >= 0 && dot+1 < len(s) {
		arr := s[dot+1:]
		switch arr {
		case "B8":
			return neonShape{lanes: 8, elemBits: 8, half64: true}
		case "B16":
			return neonShape{lanes: 16, elemBits: 8}
		case "H4":
			return neonShape{lanes: 4, elemBits: 16, half64: true}
		case "H8":
			return neonShape{lanes: 8, elemBits: 16}
		case "S2":
			return neonShape{lanes: 2, elemBits: 32, half64: true, float: isFloat}
		case "S4":
			return neonShape{lanes: 4, elemBits: 32, float: isFloat}
		case "D2":
			return neonShape{lanes: 2, elemBits: 64, float: isFloat}
		case "D1":
			return neonShape{lanes: 1, elemBits: 64, half64: true, float: isFloat}
		}
	}
	if isFloat {
		return neonShape{lanes: 4, elemBits: 32, float: true}
	}
	return neonShape{lanes: 2, elemBits: 64}
}

func (c *arm64Ctx) loadVShape(r asm.Reg, sh neonShape) (string, error) {
	raw, err := c.loadVReg(r)
	if err != nil {
		return "", err
	}
	fullTy := sh.fullVecTy()
	cur := raw
	if fullTy != "<16 x i8>" {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", bc, raw, fullTy)
		cur = "%" + bc
	}
	if !sh.half64 {
		return cur, nil
	}
	mask := make([]string, sh.lanes)
	for i := 0; i < sh.lanes; i++ {
		mask[i] = fmt.Sprintf("i32 %d", i)
	}
	sub := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", sub, fullTy, cur, fullTy, sh.lanes, strings.Join(mask, ", "))
	return "%" + sub, nil
}

func (c *arm64Ctx) storeVShape(dst asm.Reg, val string, sh neonShape) error {
	cur := val
	fullTy := sh.fullVecTy()
	if sh.half64 {
		// Zero-extend low 64 bits into 128-bit V register.
		fullN := sh.fullLanes()
		mask := make([]string, fullN)
		for i := 0; i < sh.lanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", i)
		}
		for i := sh.lanes; i < fullN; i++ {
			mask[i] = fmt.Sprintf("i32 %d", sh.lanes)
		}
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s zeroinitializer, <%d x i32> <%s>\n", ext, sh.vecTy(), val, sh.vecTy(), fullN, strings.Join(mask, ", "))
		cur = "%" + ext
	}
	if fullTy != "<16 x i8>" {
		bc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <16 x i8>\n", bc, fullTy, cur)
		cur = "%" + bc
	}
	return c.storeVReg(dst, cur)
}

func (c *arm64Ctx) lowerVecDeclarative(op asm.Op, postInc bool, ins asm.Instr) (ok bool, terminated bool, err error) {
	spec, found := arm64NEONTable.Lookup(op)
	if !found {
		return false, false, nil
	}
	switch spec.Family {
	case asm.FamilyMove:
		return true, false, c.lowerNEONMoveStruct(spec, postInc, ins)
	case asm.FamilyVecUnary:
		return true, false, c.lowerNEONUnary(spec, ins)
	case asm.FamilyVecBinOp:
		return true, false, c.lowerNEONBinOp(spec, ins)
	case asm.FamilyVecFMA:
		return true, false, c.lowerNEONFMA(spec, ins)
	case asm.FamilyCompare:
		return true, false, c.lowerNEONCompare(spec, ins)
	case asm.FamilyVecShift:
		return true, false, c.lowerNEONShift(spec, ins)
	case asm.FamilyVecShuffle:
		return true, false, c.lowerNEONShuffleWidenReduce(spec, ins)
	}
	return false, false, nil
}

func (c *arm64Ctx) lowerNEONMoveStruct(spec asm.OpSpec, postInc bool, ins asm.Instr) error {
	switch spec.LLVMOp {
	case "vmovimm":
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpSym && ins.Args[1].Kind == asm.OpReg {
			s := strings.TrimSpace(ins.Args[0].Sym)
			if strings.HasPrefix(s, "$") {
				// Symbolic constant or float immediate (e.g. VMOVS $const_q, V2).
				imm := int64(0)
				if iv, ok := arm64ParseDollarInt64(s); ok {
					imm = iv
				} else if fv, ok := arm64ParseDollarFloatFlex(s); ok {
					if spec.Width == 32 {
						imm = int64(uint32(math.Float32bits(float32(fv))))
					} else {
						imm = int64(math.Float64bits(fv))
					}
				}
				v0, v1, bc := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %d, i32 0\n", v0, imm)
				fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 0, i32 1\n", v1, v0)
				fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, v1)
				return c.storeVReg(ins.Args[1].Reg, "%"+bc)
			}
			p, err := c.ptrFromSB(s)
			if err != nil {
				return err
			}
			if spec.Width == 128 {
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load <16 x i8>, ptr %s, align 1\n", ld, p)
				return c.storeVReg(ins.Args[1].Reg, "%"+ld)
			}
			ldTy := "i64"
			if spec.Width == 32 {
				ldTy = "i32"
			}
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", ld, ldTy, p)
			v64 := "%" + ld
			if spec.Width == 32 {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, ld)
				v64 = "%" + z
			}
			v0, v1, bc := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %s, i32 0\n", v0, v64)
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 0, i32 1\n", v1, v0)
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, v1)
			return c.storeVReg(ins.Args[1].Reg, "%"+bc)
		}
		if spec.Width == 128 {
			if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpImm || ins.Args[2].Kind != asm.OpReg {
				return fmt.Errorf("arm64 VMOVQ expects $lo, $hi, Vdst: %q", ins.Raw)
			}
			v0, v1, bc := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %d, i32 0\n", v0, ins.Args[0].Imm)
			fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 %d, i32 1\n", v1, v0, ins.Args[1].Imm)
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, v1)
			return c.storeVReg(ins.Args[2].Reg, "%"+bc)
		}
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects $imm, Vdst: %q", spec.Op, ins.Raw)
		}
		v0, v1, bc := c.newTmp(), c.newTmp(), c.newTmp()
		imm := ins.Args[0].Imm
		if spec.Width == 32 {
			imm = int64(uint32(imm))
		}
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> undef, i64 %d, i32 0\n", v0, imm)
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> %%%s, i64 0, i32 1\n", v1, v0)
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bc, v1)
		return c.storeVReg(ins.Args[1].Reg, "%"+bc)

	case "vldn", "vldnr":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpMem || ins.Args[1].Kind != asm.OpRegList || len(ins.Args[1].RegList) == 0 {
			return fmt.Errorf("arm64 %s expects mem, [V...]: %q", spec.Op, ins.Raw)
		}
		n := len(ins.Args[1].RegList)
		sh := parseNEONShape(ins.Args[1].RegList[0], false)
		elemBytes := sh.elemBits / 8
		addr, base, inc, err := c.addrI64(ins.Args[0].Mem, false)
		if err != nil {
			return err
		}
		if spec.LLVMOp == "vldnr" {
			// Load one element per reg and splat across vector lanes.
			for k, reg := range ins.Args[1].RegList {
				ak := addr
				if k > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", t, addr, k*elemBytes)
					ak = "%" + t
				}
				pt, ld, ins0, splat := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, ak)
				fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, sh.elemTy(), pt)
				fmt.Fprintf(c.b, "  %%%s = insertelement %s undef, %s %%%s, i32 0\n", ins0, sh.vecTy(), sh.elemTy(), ld)
				fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, sh.vecTy(), ins0, sh.vecTy(), sh.lanes)
				if err := c.storeVShape(reg, "%"+splat, sh); err != nil {
					return err
				}
			}
			if postInc {
				if inc == 0 {
					inc = int64(n * elemBytes)
				}
				return c.updatePostInc(base, inc)
			}
			return nil
		}
		// De-interleaved load of N vectors across sh.lanes elements.
		vecs := make([]string, n)
		for k := range vecs {
			vecs[k] = "undef"
		}
		for lane := 0; lane < sh.lanes; lane++ {
			for k := 0; k < n; k++ {
				off := (lane*n + k) * elemBytes
				ak := addr
				if off > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", t, addr, off)
					ak = "%" + t
				}
				pt, ld, insE := c.newTmp(), c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, ak)
				fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", ld, sh.elemTy(), pt)
				fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insE, sh.vecTy(), vecs[k], sh.elemTy(), ld, lane)
				vecs[k] = "%" + insE
			}
		}
		for k, reg := range ins.Args[1].RegList {
			if err := c.storeVShape(reg, vecs[k], sh); err != nil {
				return err
			}
		}
		if postInc {
			if inc == 0 {
				inc = int64(n * sh.lanes * elemBytes)
			}
			return c.updatePostInc(base, inc)
		}
		return nil

	case "vstn":
		if len(ins.Args) != 2 {
			return fmt.Errorf("arm64 %s expects [V...], mem: %q", spec.Op, ins.Raw)
		}
		listArg, memArg := ins.Args[0], ins.Args[1]
		if listArg.Kind == asm.OpMem && memArg.Kind == asm.OpRegList {
			listArg, memArg = memArg, listArg
		}
		if listArg.Kind != asm.OpRegList || len(listArg.RegList) == 0 || memArg.Kind != asm.OpMem {
			return fmt.Errorf("arm64 %s expects [V...], mem: %q", spec.Op, ins.Raw)
		}
		n := len(listArg.RegList)
		sh := parseNEONShape(listArg.RegList[0], false)
		elemBytes := sh.elemBits / 8
		addr, base, inc, err := c.addrI64(memArg.Mem, false)
		if err != nil {
			return err
		}
		vecs := make([]string, n)
		for k, reg := range listArg.RegList {
			vecs[k], err = c.loadVShape(reg, sh)
			if err != nil {
				return err
			}
		}
		for lane := 0; lane < sh.lanes; lane++ {
			for k := 0; k < n; k++ {
				off := (lane*n + k) * elemBytes
				ak := addr
				if off > 0 {
					t := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", t, addr, off)
					ak = "%" + t
				}
				ex, pt := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", ex, sh.vecTy(), vecs[k], lane)
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pt, ak)
				fmt.Fprintf(c.b, "  store %s %%%s, ptr %%%s, align 1\n", sh.elemTy(), ex, pt)
			}
		}
		if postInc {
			if inc == 0 {
				inc = int64(n * sh.lanes * elemBytes)
			}
			return c.updatePostInc(base, inc)
		}
		return nil
	}
	return fmt.Errorf("arm64: unhandled NEON move %s", spec.Op)
}

func (c *arm64Ctx) lowerNEONUnary(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vsrc, Vdst: %q", spec.Op, ins.Raw)
	}
	srcFloat := spec.Float && spec.LLVMOp != "sitofp" && spec.LLVMOp != "uitofp"
	dstFloat := spec.Float && spec.LLVMOp != "fptosi" && spec.LLVMOp != "fptoui"
	srcSh := parseNEONShape(ins.Args[0].Reg, srcFloat)
	dstSh := parseNEONShape(ins.Args[1].Reg, dstFloat)
	src, err := c.loadVShape(ins.Args[0].Reg, srcSh)
	if err != nil {
		return err
	}
	vty := srcSh.vecTy()
	out := ""
	switch spec.LLVMOp {
	case "abs":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.abs.%s(%s %s, i1 false)\n", t, vty, srcSh.intrSuffix(), vty, src)
		out = "%" + t
	case "sqabs":
		neg, isNeg, res := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ssub.sat.%s(%s zeroinitializer, %s %s)\n", neg, vty, srcSh.intrSuffix(), vty, vty, src)
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", isNeg, vty, src)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s %s\n", res, srcSh.lanes, isNeg, vty, neg, vty, src)
		out = "%" + res
	case "neg":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s zeroinitializer, %s\n", t, vty, src)
		out = "%" + t
	case "sqneg":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ssub.sat.%s(%s zeroinitializer, %s %s)\n", t, vty, srcSh.intrSuffix(), vty, vty, src)
		out = "%" + t
	case "not":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", t, vty, src, neonSplatInt(srcSh, -1))
		out = "%" + t
	case "clz":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.%s(%s %s, i1 false)\n", t, vty, srcSh.intrSuffix(), vty, src)
		out = "%" + t
	case "cls":
		sign, diff, lz, isZero, sub1, sel := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", sign, vty, src, neonSplatInt(srcSh, int64(srcSh.elemBits-1)))
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", diff, vty, src, sign)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.%s(%s %%%s, i1 false)\n", lz, vty, srcSh.intrSuffix(), vty, diff)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", isZero, vty, diff)
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %s\n", sub1, vty, lz, neonSplatInt(srcSh, 1))
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %%%s\n", sel, srcSh.lanes, isZero, vty, neonSplatInt(srcSh, int64(srcSh.elemBits-1)), vty, sub1)
		out = "%" + sel
	case "ctpop", "bitreverse":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", t, vty, spec.LLVMOp, srcSh.intrSuffix(), vty, src)
		out = "%" + t
	case "rev16":
		mask := make([]string, srcSh.lanes)
		for i := 0; i < srcSh.lanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", i^1)
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", t, vty, src, vty, srcSh.lanes, strings.Join(mask, ", "))
		out = "%" + t
	case "fneg":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", t, vty, src)
		out = "%" + t
	case "fabs", "sqrt", "floor", "roundeven", "ceil", "trunc":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", t, vty, spec.LLVMOp, srcSh.intrSuffix(), vty, src)
		out = "%" + t
	case "fptosi", "fptoui", "sitofp", "uitofp":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", t, spec.LLVMOp, vty, src, dstSh.vecTy())
		out = "%" + t
	default:
		return fmt.Errorf("arm64: unhandled NEON unary %s", spec.Op)
	}
	return c.storeVShape(ins.Args[1].Reg, out, dstSh)
}

func (c *arm64Ctx) lowerNEONBinOp(spec asm.OpSpec, ins asm.Instr) error {
	if (len(ins.Args) != 2 && len(ins.Args) != 3) || ins.Args[0].Kind != asm.OpReg || ins.Args[len(ins.Args)-1].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Vsrc1, [Vsrc2,] Vdst: %q", spec.Op, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	lhsArg := dstArg
	if len(ins.Args) == 3 {
		if ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vsrc1, Vsrc2, Vdst: %q", spec.Op, ins.Raw)
		}
		lhsArg = ins.Args[1]
	}
	sh := parseNEONShape(dstArg.Reg, spec.Float)
	vty := sh.vecTy()
	// Plan 9 order: OP Vm, Vn, Vd => Vd = Vn op Vm
	rhs, err := c.loadVShape(ins.Args[0].Reg, sh)
	if err != nil {
		return err
	}
	lhs, err := c.loadVShape(lhsArg.Reg, sh)
	if err != nil {
		return err
	}
	var out string
	switch spec.LLVMOp {
	case "sub", "mul", "fadd", "fsub", "fmul", "fdiv":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", t, spec.LLVMOp, vty, lhs, rhs)
		out = "%" + t
	case "bic", "orn":
		inv, t := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", inv, vty, rhs, neonSplatInt(sh, -1))
		opName := "and"
		if spec.LLVMOp == "orn" {
			opName = "or"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", t, opName, vty, lhs, inv)
		out = "%" + t
	case "smax", "smin", "umax", "umin":
		pred := map[string]string{"smax": "sgt", "smin": "slt", "umax": "ugt", "umin": "ult"}[spec.LLVMOp]
		cmp, sel := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, vty, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", sel, sh.lanes, cmp, vty, lhs, vty, rhs)
		out = "%" + sel
	case "sadd.sat", "uadd.sat", "ssub.sat", "usub.sat", "maximum", "minimum", "maxnum", "minnum":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %s)\n", t, vty, spec.LLVMOp, sh.intrSuffix(), vty, lhs, vty, rhs)
		out = "%" + t
	case "shadd", "uhadd", "srhadd", "urhadd":
		wBits := sh.elemBits * 2
		wTy := fmt.Sprintf("<%d x i%d>", sh.lanes, wBits)
		extOp := "zext"
		if spec.Signed {
			extOp = "sext"
		}
		lw, rw, sum := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", lw, extOp, vty, lhs, wTy)
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", rw, extOp, vty, rhs, wTy)
		fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", sum, wTy, lw, rw)
		cur := "%" + sum
		if strings.Contains(spec.LLVMOp, "rh") {
			wSh := neonShape{lanes: sh.lanes, elemBits: wBits}
			r := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", r, wTy, cur, neonSplatInt(wSh, 1))
			cur = "%" + r
		}
		wSh := neonShape{lanes: sh.lanes, elemBits: wBits}
		shiftOp := "lshr"
		if spec.Signed {
			shiftOp = "ashr"
		}
		shv, tr := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shv, shiftOp, wTy, cur, neonSplatInt(wSh, 1))
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", tr, wTy, shv, vty)
		out = "%" + tr
	case "cmtst":
		andv, nz, sx := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", andv, vty, lhs, rhs)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", nz, vty, andv)
		fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sx, sh.lanes, nz, vty)
		out = "%" + sx
	case "bsl", "bit", "bif":
		dstV, err := c.loadVShape(ins.Args[2].Reg, sh)
		if err != nil {
			return err
		}
		var mask, onOne, onZero string
		switch spec.LLVMOp {
		case "bsl":
			mask, onOne, onZero = dstV, rhs, lhs
		case "bit":
			mask, onOne, onZero = lhs, rhs, dstV
		case "bif":
			mask, onOne, onZero = lhs, dstV, rhs
		}
		nmask, p1, p2, res := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", nmask, vty, mask, neonSplatInt(sh, -1))
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", p1, vty, onOne, mask)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", p2, vty, onZero, nmask)
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", res, vty, p1, p2)
		out = "%" + res
	default:
		return fmt.Errorf("arm64: unhandled NEON binop %s", spec.Op)
	}
	return c.storeVShape(dstArg.Reg, out, sh)
}

func (c *arm64Ctx) lowerNEONFMA(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects Va, Vb, Vdst: %q", spec.Op, ins.Raw)
	}
	sh := parseNEONShape(ins.Args[2].Reg, spec.Float)
	vty := sh.vecTy()
	a, err := c.loadVShape(ins.Args[0].Reg, sh)
	if err != nil {
		return err
	}
	b, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	dst, err := c.loadVShape(ins.Args[2].Reg, sh)
	if err != nil {
		return err
	}
	if spec.Float {
		if spec.LLVMOp == "fmls" {
			na := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", na, vty, a)
			a = "%" + na
		}
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.%s(%s %s, %s %s, %s %s)\n", res, vty, sh.intrSuffix(), vty, a, vty, b, vty, dst)
		return c.storeVShape(ins.Args[2].Reg, "%"+res, sh)
	}
	prod, res := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", prod, vty, a, b)
	if spec.LLVMOp == "mla" {
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", res, vty, dst, prod)
	} else {
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %%%s\n", res, vty, dst, prod)
	}
	return c.storeVShape(ins.Args[2].Reg, "%"+res, sh)
}

func (c *arm64Ctx) lowerNEONCompare(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects src1/$0, Vsrc2, Vdst: %q", spec.Op, ins.Raw)
	}
	sh := parseNEONShape(ins.Args[1].Reg, spec.Float)
	dstSh := parseNEONShape(ins.Args[2].Reg, false)
	lhs, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	var rhs string
	if ins.Args[0].Kind == asm.OpReg {
		rhs, err = c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
	} else {
		// Compare against zero ($0 or $(0.0)).
		rhs = "zeroinitializer"
	}
	cmp, sx := c.newTmp(), c.newTmp()
	if spec.Float {
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", cmp, spec.LLVMOp, sh.vecTy(), lhs, rhs)
	} else {
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", cmp, spec.LLVMOp, sh.vecTy(), lhs, rhs)
	}
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to %s\n", sx, sh.lanes, cmp, dstSh.vecTy())
	return c.storeVShape(ins.Args[2].Reg, "%"+sx, dstSh)
}

func (c *arm64Ctx) lowerNEONShift(spec asm.OpSpec, ins asm.Instr) error {
	if len(ins.Args) != 3 || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
		return fmt.Errorf("arm64 %s expects shift, Vsrc, Vdst: %q", spec.Op, ins.Raw)
	}
	sh := parseNEONShape(ins.Args[2].Reg, false)
	vty := sh.vecTy()
	src, err := c.loadVShape(ins.Args[1].Reg, sh)
	if err != nil {
		return err
	}
	var shiftVec string
	if ins.Args[0].Kind == asm.OpImm {
		amt := ins.Args[0].Imm
		if amt < 0 {
			amt = 0
		}
		if amt >= int64(sh.elemBits) {
			amt = int64(sh.elemBits - 1)
		}
		shiftVec = neonSplatInt(sh, amt)
	} else if ins.Args[0].Kind == asm.OpReg {
		rv, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		m := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", m, vty, rv, neonSplatInt(sh, int64(sh.elemBits-1)))
		shiftVec = "%" + m
	} else {
		return fmt.Errorf("arm64 %s expects imm or Vreg shift: %q", spec.Op, ins.Raw)
	}
	var out string
	switch spec.LLVMOp {
	case "sshl", "ushl", "sqshl", "uqshl":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", t, vty, src, shiftVec)
		out = "%" + t
	case "ashr", "srshr":
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %s\n", t, vty, src, shiftVec)
		out = "%" + t
	case "sli":
		dstV, err := c.loadVShape(ins.Args[2].Reg, sh)
		if err != nil {
			return err
		}
		amt := ins.Args[0].Imm
		lowMask := (uint64(1) << uint(amt)) - 1
		shv, kept, res := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", shv, vty, src, shiftVec)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", kept, vty, dstV, neonSplatInt(sh, int64(lowMask)))
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", res, vty, shv, kept)
		out = "%" + res
	case "usra":
		dstV, err := c.loadVShape(ins.Args[2].Reg, sh)
		if err != nil {
			return err
		}
		shv, sum := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shv, vty, src, shiftVec)
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", sum, vty, dstV, shv)
		out = "%" + sum
	default:
		return fmt.Errorf("arm64: unhandled NEON shift %s", spec.Op)
	}
	return c.storeVShape(ins.Args[2].Reg, out, sh)
}

func (c *arm64Ctx) lowerNEONShuffleWidenReduce(spec asm.OpSpec, ins asm.Instr) error {
	switch {
	case strings.HasPrefix(spec.LLVMOp, "reduce_"):
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vsrc, Vdst: %q", spec.Op, ins.Raw)
		}
		sh := parseNEONShape(ins.Args[0].Reg, spec.Float)
		src, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		acc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 0\n", acc, sh.vecTy(), src)
		cur := "%" + acc
		for i := 1; i < sh.lanes; i++ {
			e := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", e, sh.vecTy(), src, i)
			nxt := c.newTmp()
			switch spec.LLVMOp {
			case "reduce_add":
				fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", nxt, sh.elemTy(), cur, e)
			case "reduce_smax", "reduce_smin", "reduce_umax", "reduce_umin":
				pred := map[string]string{"reduce_smax": "sgt", "reduce_smin": "slt", "reduce_umax": "ugt", "reduce_umin": "ult"}[spec.LLVMOp]
				cmp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %%%s\n", cmp, pred, sh.elemTy(), cur, e)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %%%s\n", nxt, cmp, sh.elemTy(), cur, sh.elemTy(), e)
			default:
				intr := map[string]string{
					"reduce_fmax": "maximum", "reduce_fmin": "minimum",
					"reduce_fmaxnm": "maxnum", "reduce_fminnm": "minnum",
				}[spec.LLVMOp]
				suf := fmt.Sprintf("f%d", sh.elemBits)
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s, %s %%%s)\n", nxt, sh.elemTy(), intr, suf, sh.elemTy(), cur, sh.elemTy(), e)
			}
			cur = "%" + nxt
		}
		// Place scalar result into lane 0 of destination V register (zeroing upper lanes).
		dstSh := neonShape{lanes: sh.fullLanes(), elemBits: sh.elemBits, float: sh.float}
		ins0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, %s %s, i32 0\n", ins0, dstSh.vecTy(), sh.elemTy(), cur)
		return c.storeVShape(ins.Args[1].Reg, "%"+ins0, dstSh)

	case strings.HasPrefix(spec.LLVMOp, "pair_"):
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vm, Vn, Vd: %q", spec.Op, ins.Raw)
		}
		sh := parseNEONShape(ins.Args[2].Reg, spec.Float)
		b, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		a, err := c.loadVShape(ins.Args[1].Reg, sh)
		if err != nil {
			return err
		}
		cur := "undef"
		half := sh.lanes / 2
		for i := 0; i < sh.lanes; i++ {
			src, idx := a, i*2
			if i >= half {
				src, idx = b, (i-half)*2
			}
			e0, e1 := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", e0, sh.vecTy(), src, idx)
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", e1, sh.vecTy(), src, idx+1)
			r := c.newTmp()
			switch spec.LLVMOp {
			case "pair_fadd":
				fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %%%s\n", r, sh.elemTy(), e0, e1)
			case "pair_smax", "pair_smin", "pair_umax", "pair_umin":
				pred := map[string]string{"pair_smax": "sgt", "pair_smin": "slt", "pair_umax": "ugt", "pair_umin": "ult"}[spec.LLVMOp]
				cmp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = icmp %s %s %%%s, %%%s\n", cmp, pred, sh.elemTy(), e0, e1)
				fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", r, cmp, sh.elemTy(), e0, sh.elemTy(), e1)
			default:
				intr := map[string]string{
					"pair_fmax": "maximum", "pair_fmin": "minimum",
					"pair_fmaxnm": "maxnum", "pair_fminnm": "minnum",
				}[spec.LLVMOp]
				suf := fmt.Sprintf("f%d", sh.elemBits)
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s, %s %%%s)\n", r, sh.elemTy(), intr, suf, sh.elemTy(), e0, sh.elemTy(), e1)
			}
			insv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", insv, sh.vecTy(), cur, sh.elemTy(), r, i)
			cur = "%" + insv
		}
		return c.storeVShape(ins.Args[2].Reg, cur, sh)

	case spec.LLVMOp == "trn1" || spec.LLVMOp == "trn2" || spec.LLVMOp == "uzp1" || spec.LLVMOp == "uzp2":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vm, Vn, Vd: %q", spec.Op, ins.Raw)
		}
		sh := parseNEONShape(ins.Args[2].Reg, false)
		b, err := c.loadVShape(ins.Args[0].Reg, sh)
		if err != nil {
			return err
		}
		a, err := c.loadVShape(ins.Args[1].Reg, sh)
		if err != nil {
			return err
		}
		mask := make([]string, sh.lanes)
		for i := 0; i < sh.lanes; i++ {
			var idx int
			switch spec.LLVMOp {
			case "trn1":
				if i%2 == 0 {
					idx = i
				} else {
					idx = sh.lanes + i - 1
				}
			case "trn2":
				if i%2 == 0 {
					idx = i + 1
				} else {
					idx = sh.lanes + i
				}
			case "uzp1":
				idx = i * 2
			case "uzp2":
				idx = i*2 + 1
			}
			mask[i] = fmt.Sprintf("i32 %d", idx)
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n", out, sh.vecTy(), a, sh.vecTy(), b, sh.lanes, strings.Join(mask, ", "))
		return c.storeVShape(ins.Args[2].Reg, "%"+out, sh)

	case spec.LLVMOp == "tbx":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpRegList || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 VTBX expects Vidx, [Vtbl...], Vdst: %q", ins.Raw)
		}
		// Keep dst intact for out-of-range indices; perform table lookup per byte lane.
		idxV, err := c.loadVReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		dstV, err := c.loadVReg(ins.Args[2].Reg)
		if err != nil {
			return err
		}
		tblRegs := make([]string, len(ins.Args[1].RegList))
		for i, tr := range ins.Args[1].RegList {
			tblRegs[i], err = c.loadVReg(tr)
			if err != nil {
				return err
			}
		}
		// Store table bytes into a small stack array for indexed byte lookup.
		nBytes := len(tblRegs) * 16
		buf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = alloca [%d x i8], align 16\n", buf, nBytes)
		for i, tv := range tblRegs {
			p := "%" + buf
			if i > 0 {
				gp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %%%s, i64 %d\n", gp, buf, i*16)
				p = "%" + gp
			}
			fmt.Fprintf(c.b, "  store <16 x i8> %s, ptr %s, align 1\n", tv, p)
		}
		sh := parseNEONShape(ins.Args[2].Reg, false)
		cur := dstV
		for i := 0; i < sh.lanes; i++ {
			idb, inR, clamped, id64, gp, ld, oldB, sel, insv := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", idb, idxV, i)
			fmt.Fprintf(c.b, "  %%%s = icmp ult i8 %%%s, %d\n", inR, idb, nBytes)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 0\n", clamped, inR, idb)
			fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", id64, clamped)
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %%%s, i64 %%%s\n", gp, buf, id64)
			fmt.Fprintf(c.b, "  %%%s = load i8, ptr %%%s\n", ld, gp)
			fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i8> %s, i32 %d\n", oldB, cur, i)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 %%%s\n", sel, inR, ld, oldB)
			fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i8> %s, i8 %%%s, i32 %d\n", insv, cur, sel, i)
			cur = "%" + insv
		}
		return c.storeVReg(ins.Args[2].Reg, cur)

	default:
		return c.lowerNEONWidenNarrow(spec, ins)
	}
}

func (c *arm64Ctx) lowerNEONWidenNarrow(spec asm.OpSpec, ins asm.Instr) error {
	base := strings.TrimSuffix(spec.LLVMOp, "2")
	isHigh := strings.HasSuffix(spec.LLVMOp, "2")
	extractHalf := func(reg asm.Reg, sh neonShape, high bool) (string, neonShape, error) {
		v, err := c.loadVShape(reg, sh)
		if err != nil {
			return "", neonShape{}, err
		}
		if sh.half64 {
			return v, sh, nil
		}
		halfLanes := sh.lanes / 2
		start := 0
		if high {
			start = halfLanes
		}
		mask := make([]string, halfLanes)
		for i := 0; i < halfLanes; i++ {
			mask[i] = fmt.Sprintf("i32 %d", start+i)
		}
		sub := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n", sub, sh.vecTy(), v, sh.vecTy(), halfLanes, strings.Join(mask, ", "))
		return "%" + sub, neonShape{lanes: halfLanes, elemBits: sh.elemBits, half64: true, float: sh.float}, nil
	}
	extOp := "zext"
	if spec.Signed {
		extOp = "sext"
	}

	switch base {
	case "widen", "fcvtl":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vsrc, Vdst: %q", spec.Op, ins.Raw)
		}
		srcSh := parseNEONShape(ins.Args[0].Reg, spec.Float)
		dstSh := parseNEONShape(ins.Args[1].Reg, spec.Float)
		hv, hSh, err := extractHalf(ins.Args[0].Reg, srcSh, isHigh)
		if err != nil {
			return err
		}
		out := c.newTmp()
		if spec.Float {
			fmt.Fprintf(c.b, "  %%%s = fpext %s %s to %s\n", out, hSh.vecTy(), hv, dstSh.vecTy())
		} else {
			fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", out, extOp, hSh.vecTy(), hv, dstSh.vecTy())
		}
		return c.storeVShape(ins.Args[1].Reg, "%"+out, dstSh)

	case "shll":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects $imm, Vsrc, Vdst: %q", spec.Op, ins.Raw)
		}
		srcSh := parseNEONShape(ins.Args[1].Reg, false)
		dstSh := parseNEONShape(ins.Args[2].Reg, false)
		hv, hSh, err := extractHalf(ins.Args[1].Reg, srcSh, isHigh)
		if err != nil {
			return err
		}
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ext, extOp, hSh.vecTy(), hv, dstSh.vecTy())
		out := "%" + ext
		if ins.Args[0].Imm > 0 {
			shv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", shv, dstSh.vecTy(), ext, neonSplatInt(dstSh, ins.Args[0].Imm))
			out = "%" + shv
		}
		return c.storeVShape(ins.Args[2].Reg, out, dstSh)

	case "mull", "mlal", "mlsl":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Va, Vb, Vdst: %q", spec.Op, ins.Raw)
		}
		srcSh := parseNEONShape(ins.Args[0].Reg, false)
		dstSh := parseNEONShape(ins.Args[2].Reg, false)
		ha, hSh, err := extractHalf(ins.Args[0].Reg, srcSh, isHigh)
		if err != nil {
			return err
		}
		hb, _, err := extractHalf(ins.Args[1].Reg, srcSh, isHigh)
		if err != nil {
			return err
		}
		ea, eb, prod := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", ea, extOp, hSh.vecTy(), ha, dstSh.vecTy())
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", eb, extOp, hSh.vecTy(), hb, dstSh.vecTy())
		fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", prod, dstSh.vecTy(), ea, eb)
		out := "%" + prod
		if base == "mlal" || base == "mlsl" {
			acc, err := c.loadVShape(ins.Args[2].Reg, dstSh)
			if err != nil {
				return err
			}
			r := c.newTmp()
			if base == "mlal" {
				fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", r, dstSh.vecTy(), acc, out)
			} else {
				fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", r, dstSh.vecTy(), acc, out)
			}
			out = "%" + r
		}
		return c.storeVShape(ins.Args[2].Reg, out, dstSh)

	case "uaddw":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
			return fmt.Errorf("arm64 %s expects Vnarrow, Vwide, Vdst: %q", spec.Op, ins.Raw)
		}
		nSh := parseNEONShape(ins.Args[0].Reg, false)
		wSh := parseNEONShape(ins.Args[2].Reg, false)
		hn, hSh, err := extractHalf(ins.Args[0].Reg, nSh, isHigh)
		if err != nil {
			return err
		}
		wv, err := c.loadVShape(ins.Args[1].Reg, wSh)
		if err != nil {
			return err
		}
		ext, sum := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to %s\n", ext, hSh.vecTy(), hn, wSh.vecTy())
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", sum, wSh.vecTy(), wv, ext)
		return c.storeVShape(ins.Args[2].Reg, "%"+sum, wSh)

	case "xtn", "shrn", "fcvtn":
		var srcOp, dstOp asm.Operand
		var shiftAmt int64
		if base == "shrn" {
			if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg || ins.Args[2].Kind != asm.OpReg {
				return fmt.Errorf("arm64 %s expects $imm, Vsrc, Vdst: %q", spec.Op, ins.Raw)
			}
			shiftAmt, srcOp, dstOp = ins.Args[0].Imm, ins.Args[1], ins.Args[2]
		} else {
			if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg || ins.Args[1].Kind != asm.OpReg {
				return fmt.Errorf("arm64 %s expects Vsrc, Vdst: %q", spec.Op, ins.Raw)
			}
			srcOp, dstOp = ins.Args[0], ins.Args[1]
		}
		srcSh := parseNEONShape(srcOp.Reg, spec.Float)
		dstSh := parseNEONShape(dstOp.Reg, spec.Float)
		sv, err := c.loadVShape(srcOp.Reg, srcSh)
		if err != nil {
			return err
		}
		if base == "shrn" && shiftAmt > 0 {
			shv := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shv, srcSh.vecTy(), sv, neonSplatInt(srcSh, shiftAmt))
			sv = "%" + shv
		}
		halfSh := neonShape{lanes: srcSh.lanes, elemBits: dstSh.elemBits, half64: true, float: spec.Float}
		narrow := c.newTmp()
		if spec.Float {
			fmt.Fprintf(c.b, "  %%%s = fptrunc %s %s to %s\n", narrow, srcSh.vecTy(), sv, halfSh.vecTy())
		} else {
			fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", narrow, srcSh.vecTy(), sv, halfSh.vecTy())
		}
		if !isHigh {
			return c.storeVShape(dstOp.Reg, "%"+narrow, halfSh)
		}
		// High half: preserve low 64 bits of dst, insert narrowed half into upper 64 bits.
		oldLow, _, err := extractHalf(dstOp.Reg, dstSh, false)
		if err != nil {
			return err
		}
		fullN := halfSh.lanes * 2
		mask := make([]string, fullN)
		for i := 0; i < fullN; i++ {
			mask[i] = fmt.Sprintf("i32 %d", i)
		}
		joined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %%%s, <%d x i32> <%s>\n", joined, halfSh.vecTy(), oldLow, halfSh.vecTy(), narrow, fullN, strings.Join(mask, ", "))
		return c.storeVShape(dstOp.Reg, "%"+joined, neonShape{lanes: fullN, elemBits: dstSh.elemBits, float: spec.Float})
	}
	return fmt.Errorf("arm64: unhandled NEON widen/narrow %s", spec.Op)
}

func neonSplatInt(sh neonShape, val int64) string {
	elems := make([]string, sh.lanes)
	for i := range elems {
		elems[i] = fmt.Sprintf("i%d %d", sh.elemBits, val)
	}
	return "<" + strings.Join(elems, ", ") + ">"
}
