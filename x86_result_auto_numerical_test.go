package plan9asm

import (
	"errors"
	"reflect"
	"testing"
)

func TestX86ResultAUTOReplayDoesNotWashUnboundSourceRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$32-4\nMOVL $1,spill-8(SP)\nMOVL spill-8(SP),AX\nMOVL AX,ret+0(FP)\nRET")
		if err != nil {
			t.Fatal(err)
		}
		if extent, err := x86ResultAUTOExtent(file.Funcs[0], arch); err != nil || extent != 32 {
			t.Fatal("unchanged logical source precondition", extent, err)
		}
		for name, mutate := range map[string]func(*Instr){
			"missing binding": func(ins *Instr) { ins.x86NumericalRead = &x86NumericalReadCertificate{} },
			"empty binding": func(ins *Instr) {
				ins.x86NumericalRead = &x86NumericalReadCertificate{binding: &GoX86NumericalReadBinding{}}
			},
			"copied nonfactory token": func(ins *Instr) {
				ins.x86NumericalRead = &x86NumericalReadCertificate{binding: &GoX86NumericalReadBinding{source: &GoX86NumericalReadSource{}}}
			},
			"physical encoding": func(ins *Instr) { ins.x86Encoded = true },
			"source stack role": func(ins *Instr) { ins.x86SourceStackFP = map[int]int64{0: 0} },
			"SDK literal role":  func(ins *Instr) { ins.x86SDKLiteral = &x86SDKLiteralCertificate{} },
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				fn := file.Funcs[0]
				fn.Instrs = append([]Instr(nil), fn.Instrs...)
				mutate(&fn.Instrs[1])
				before := fn.Instrs[1]
				if _, err := x86ResultAUTOExtent(fn, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unbound metadata was silently discarded during source replay", err)
				}
				if !reflect.DeepEqual(before, fn.Instrs[1]) {
					t.Fatal("source role observer mutated the original instruction")
				}
			})
		}
	}
}
