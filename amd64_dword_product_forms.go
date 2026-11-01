package plan9asm

type x86DwordProductSpec struct {
	x86PackedBinarySpec
	signed       bool
	nativeOpcode string
}

// Go names the legacy unsigned instruction PMULULQ, not Intel's PMULUDQ.
// Only the unsigned legacy ymm table has an MMX/m64 row. Both AVX tables
// permit qword broadcast and qword writemasking, never rounding or SAE.
var x86DwordProductSpecs = map[Op]x86DwordProductSpec{
	"PMULDQ":   {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, true, "pmuldq"},
	"PMULULQ":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyInteger}, false, "pmuludq"},
	"VPMULDQ":  {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 8, zeroing: true}, true, ""},
	"VPMULUDQ": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 8, zeroing: true}, false, ""},
}

type x86DwordProductForm = x86PackedPhysicalForm

// The operand model grants no initialized bank, native extent or caller role.
// In particular a GP spelling admitted to Ymm still names the physical MMX
// bank, and a named high mode32 vector still needs its physical binding.
func x86DwordProductProperties(op Op, ins Instr, arch string) (x86DwordProductForm, bool, error) {
	return x86PackedPhysicalProperties(op, ins, arch, x86PackedDwordProduct)
}
