package plan9asm

import "strings"

type x86PackedSubtractForm struct {
	x86PackedBinaryForm
	laneBits int
	mode     amd64PackedSubtractMode
}

// Go's legacy subtract rows are yxm, never the add family's MMX rows.
// The V rows share _yvandnpd, but only D/Q enable broadcast in avx_optabs.
func x86PackedSubtractProperties(ins Instr, goarch string) (x86PackedSubtractForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	bits, mode, vector, known := amd64PackedSubtractProperties(base)
	if !known {
		return x86PackedSubtractForm{}, false, nil
	}
	if !vector {
		form, _, err := x86LegacyIntegerArithmeticProperties(ins.Op, ins, goarch)
		return x86PackedSubtractForm{form.x86PackedBinaryForm, bits, mode}, true, err
	}
	spec := x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}
	if vector {
		spec.encoding, spec.zeroing = x86PackedLogicalVEXOrEVEX, true
		if base == "VPSUBD" || base == "VPSUBQ" {
			spec.broadcastBytes = bits / 8
		}
	}
	form, err := x86PackedBinaryProperties(ins, goarch, spec)
	if err == nil {
		err = x86Mode32VectorRegisterContext(ins, goarch)
	}
	return x86PackedSubtractForm{form, bits, mode}, true, err
}
