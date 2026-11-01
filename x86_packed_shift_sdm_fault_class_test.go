package plan9asm

import "testing"

func TestX86PackedShiftIndependentSDMFullAndMem128FaultClasses(t *testing.T) {
	// Intel SDM 325462-089 Vol.2B 4-453..454 distinguishes the complete
	// tuples, not just the W/D/Q mnemonic: uniform Mem128 counts are E4NF.nb;
	// immediate Full tuples are E4/E4.nb, including W immediate. Byte shifts
	// retain E4NF.nb. Per-lane Full/BCST counts retain E4/E4.nb. A numerical
	// dependency on only the low count qword never narrows a Mem128 access.
	counts := map[string]int{}
	for _, row := range x86PackedShiftRawCases() {
		if row.input == "register" {
			continue
		}
		t.Run(row.name(), func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.instruction())
			form, known, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
			if !known || err != nil || form.memory < 0 {
				t.Fatal("independent complete Go memory row lost its typed grammar", err)
			}
			class, suppressed, bytes := "per-lane", true, row.width
			switch row.member.mode {
			case "uniform":
				class = "immediate-Full"
				if !row.immediate {
					class, suppressed, bytes = "uniform-Mem128", false, 16
				}
			case "bytes":
				class, suppressed = "byte-Full", false
			}
			if row.input == "broadcast" {
				bytes = row.member.bits / 8
			}
			counts[class]++
			if form.faultSuppressed != suppressed || form.memoryBytes != bytes {
				t.Fatal("SDM Full versus Mem128 exception class or complete tuple changed",
					class, form.faultSuppressed, suppressed, form.memoryBytes, bytes)
			}
		})
	}
	if counts["per-lane"] != 145 || counts["immediate-Full"] != 135 ||
		counts["uniform-Mem128"] != 97 || counts["byte-Full"] != 6 {
		t.Fatal("complete independently classified memory-form denominator changed", counts)
	}
}
