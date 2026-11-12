package plan9asm

import "testing"

func TestX86DirectTailNumericalEmitterKeepsExactOriginalNode(t *testing.T) {
	// A pure coordinate model; this cannot restore a live numerical binding.
	makeEmitter := func() (*amd64Ctx, Instr, numericalSBReadFact) {
		file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-0\nJMP worker<>(SB)\nTEXT worker<>(SB),4,$0\nCMPB feature+7(SB),$1\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		binding := &GoX86NumericalReadBinding{}
		ins := file.Funcs[1].Instrs[1]
		ins.x86NumericalRead = &x86NumericalReadCertificate{binding: binding}
		graph := &x86DirectTailGraph{original: file, numerical: binding, goarch: "amd64",
			symbols: map[string]string{"·entry": "example.entry", "worker<>": "worker<>"}}
		view := &x86DirectTailRoot{graph: graph, text: 0,
			points: []x86DirectTailPoint{{text: 1, instruction: 1}}, instructions: []Instr{ins}}
		graph.roots = map[string]*x86DirectTailRoot{"·entry": view}
		return &amd64Ctx{directTail: view, goarch: "amd64", sig: FuncSig{Name: "example.entry"}}, ins,
			numericalSBReadFact{Function: "worker<>", Instruction: 1, Original: file.Funcs[1].Instrs[1]}
	}
	c, ins, fact := makeEmitter()
	if !c.numericalReadAtOriginalSource(ins, fact, 0, 0) {
		t.Fatal("root emission lost the helper's exact original TEXT/instruction identity")
	}
	for _, kind := range []string{"root name", "helper name", "ordinal", "block", "instruction in block", "binding", "node cert", "Raw", "node opcode", "view root", "mode", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			c, ins, fact := makeEmitter()
			block, ordinal := 0, 0
			switch kind {
			case "root name":
				c.sig.Name = "worker<>"
			case "helper name":
				fact.Function = "example.entry"
			case "ordinal":
				fact.Instruction++
			case "block":
				block++
			case "instruction in block":
				ordinal++
			case "binding":
				c.directTail.graph.numerical = &GoX86NumericalReadBinding{}
			case "node cert":
				ins.x86NumericalRead = &x86NumericalReadCertificate{binding: c.directTail.graph.numerical}
			case "Raw":
				ins.Raw += " changed"
			case "node opcode":
				ins.Op = "MOVB"
			case "view root":
				delete(c.directTail.graph.roots, "·entry")
			case "mode":
				c.goarch = "386"
			case "revoked":
				c.directTail.graph.revoked.Store(true)
			}
			if c.numericalReadAtOriginalSource(ins, fact, block, ordinal) {
				t.Fatal("another original node, root, source or mode borrowed this read")
			}
		})
	}
	plain := &amd64Ctx{sig: FuncSig{Name: "worker<>"}}
	if !plain.numericalReadAtOriginalSource(ins, fact, -1, -1) {
		t.Fatal("ordinary emitter's exact function check changed")
	}
	plain.sig.Name = "example.entry"
	if plain.numericalReadAtOriginalSource(ins, fact, -1, -1) {
		t.Fatal("a standalone function borrowed helper identity without the source graph")
	}
}
