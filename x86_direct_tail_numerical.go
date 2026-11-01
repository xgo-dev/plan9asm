package plan9asm

import "reflect"

// A continuation emits inside its typed root, but a numerical certificate
// retains its original helper TEXT and instruction. Match the current sealed
// point instead of changing that certificate into a fictitious root read.
func (c *amd64Ctx) numericalReadAtOriginalSource(ins Instr, read numericalSBReadFact, block, ordinal int) bool {
	view := c.directTail
	if view == nil {
		return c.sig.Name == read.Function
	}
	graph, cert := view.graph, ins.x86NumericalRead
	if graph == nil || graph.original == nil || graph.revoked.Load() || graph.goarch != c.goarch ||
		cert == nil || graph.numerical == nil || cert.binding != graph.numerical || ordinal != 0 ||
		block < 0 || block >= len(view.points) || block >= len(view.instructions) ||
		view.text < 0 || view.text >= len(graph.original.Funcs) {
		return false
	}
	root := graph.original.Funcs[view.text]
	if graph.roots[root.Sym] != view || c.sig.Name != graph.symbols[root.Sym] ||
		view.instructions[block].x86NumericalRead != cert {
		return false
	}
	point := view.points[block]
	if point.text < 0 || point.text >= len(graph.original.Funcs) {
		return false
	}
	fn := graph.original.Funcs[point.text]
	if point.instruction < 0 || point.instruction >= len(fn.Instrs) || read.Instruction != point.instruction ||
		read.Function != graph.symbols[fn.Sym] {
		return false
	}
	original := fn.Instrs[point.instruction]
	return reflect.DeepEqual(x86DirectTailInstructionSnapshot(ins), original) &&
		reflect.DeepEqual(x86DirectTailInstructionSnapshot(view.instructions[block]), original) &&
		reflect.DeepEqual(x86DirectTailInstructionSnapshot(read.Original), original)
}

func x86DirectTailNumericalRequest(file *File, options Options) (*File, error) {
	binding := options.NumericalReads
	if binding == nil {
		for _, fn := range file.Funcs {
			for _, ins := range fn.Instrs {
				if ins.x86NumericalRead != nil || ins.x86SDKLiteral != nil {
					return nil, x86DirectTailContext("a copied numerical node has no complete live source binding")
				}
			}
		}
		return x86DirectTailSnapshot(file), nil
	}
	if binding.source == nil || binding.source.role != numericalSBSDKSource || binding.source.assembly == nil ||
		binding.source.literals != nil || len(binding.literalAccesses) != 0 || binding.literalMinimum != nil {
		return nil, x86DirectTailContext("numerical continuation needs its independent metadata-only original-node role")
	}
	frozen, _, err := freezeNumericalReadInputs(file, options)
	return frozen, err
}

func (graph *x86DirectTailGraph) joinNumericalNodes(request *File) error {
	if graph.numerical == nil {
		return nil
	}
	for _, view := range graph.roots {
		for pc, point := range view.points {
			original := graph.original.Funcs[point.text].Instrs[point.instruction]
			actual := request.Funcs[point.text].Instrs[point.instruction]
			if !reflect.DeepEqual(x86DirectTailInstructionSnapshot(actual), original) {
				return x86DirectTailContext("numerical continuation original node changed")
			}
			if cert := actual.x86NumericalRead; cert != nil {
				read, _, valid := numericalCertifiedRead(actual, graph.goarch)
				if !valid || cert.binding != graph.numerical || read.Function != graph.numerical.resolve(request.Funcs[point.text].Sym) ||
					read.Instruction != point.instruction {
					return x86DirectTailContext("numerical certificate belongs to another original TEXT/instruction")
				}
			}
			view.instructions[pc] = actual // Immutable request-local original node.
		}
	}
	return nil
}

func x86DirectTailInstructionSnapshot(ins Instr) Instr {
	ins.x86NumericalRead, ins.x86SDKLiteral = nil, nil
	return ins
}

// JSON freezing drops private fields. Restore only this already verified
// request's graph views; no public File or helper signature can create them.
func preserveX86DirectTailNumericalGraph(original, frozen *File, options Options) error {
	graph := original.x86DirectTails
	if graph == nil {
		return nil
	}
	if graph.numerical != options.NumericalReads || !reflect.DeepEqual(x86DirectTailSnapshot(original), x86DirectTailSnapshot(frozen)) {
		return x86DirectTailContext("frozen numerical graph lost its complete original source")
	}
	frozen.x86DirectTails = graph
	for index := range frozen.Funcs {
		frozen.Funcs[index].x86DirectTailRoot = original.Funcs[index].x86DirectTailRoot
		frozen.Funcs[index].x86ResultFlowBudget = original.Funcs[index].x86ResultFlowBudget
	}
	return graph.verify(frozen, options)
}
