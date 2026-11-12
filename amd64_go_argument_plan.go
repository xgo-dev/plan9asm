package plan9asm

import (
	"fmt"
	"go/types"
)

// amd64GoArgumentPlan is a private language-layout calculation, not an entry
// certificate. In particular, it supplies no initialized bytes, native pointer
// backing, FP/spill storage, closure context, or permission to lower a source.
// The private entry consumer separately authenticates the actual declaration,
// selected compiler/ABI, LLVM transport and complete source before using it.
type amd64GoArgumentPlan struct {
	Arguments []amd64GoArgumentAssignment
	GPUsed    int
	FPUsed    int
}

type amd64GoArgumentAssignment struct {
	Index    int
	Type     types.Type // Preserve the original Go parameter grouping and identity.
	Stack    bool       // Descriptive only: there is no stack/backing model here.
	Carriers []amd64GoArgumentCarrier
}

type amd64GoArgumentKind uint8

const (
	amd64GoArgumentInteger amd64GoArgumentKind = iota + 1
	amd64GoArgumentBoolean
	amd64GoArgumentPointer
	amd64GoArgumentFloating
)

type amd64GoArgumentCarrier struct {
	Path     []int // extractvalue path relative to this one LLVM argument.
	Offset   int64 // Go language-model byte offset, not a native memory grant.
	Width    int64 // Only these physical bytes carry the declared scalar value.
	Type     LLVMType
	Kind     amd64GoArgumentKind
	Register Reg
}

const amd64GoArgumentPlanLimit = 4096

func amd64GoArgumentContext(reason string) error {
	return fmt.Errorf("%w: AMD64 Go argument plan: %s", ErrProbeNeedsContext, reason)
}

func planAMD64GoArguments(sig *types.Signature) (*amd64GoArgumentPlan, error) {
	if sig == nil || sig.Recv() != nil || sig.Variadic() || sig.TypeParams().Len() != 0 || sig.RecvTypeParams().Len() != 0 {
		return nil, amd64GoArgumentContext("requires a fixed monomorphic direct function")
	}
	if sig.Params().Len() > amd64GoArgumentPlanLimit {
		return nil, amd64GoArgumentContext("parameter inventory exceeds the bounded plan")
	}
	plan := &amd64GoArgumentPlan{}
	builder := amd64GoArgumentBuilder{sizes: types.SizesFor("gc", "amd64")}
	registers := [...]Reg{AX, BX, CX, DI, SI, "R8", "R9", "R10", "R11"}
	for index := 0; index < sig.Params().Len(); index++ {
		typ := sig.Params().At(index).Type()
		shape, err := builder.shape(typ, 0)
		if err != nil {
			return nil, err
		}
		argument := amd64GoArgumentAssignment{Index: index, Type: typ}
		gp, fp := 0, 0
		for _, leaf := range shape.leaves {
			if leaf.Kind == amd64GoArgumentFloating {
				fp++
			} else {
				gp++
			}
		}
		// Go's abiutils.tryAllocRegs checks the complete parameter before
		// allocateRegs advances either bank. A failure consumes neither bank;
		// a subsequent parameter may still use the remaining registers.
		argument.Stack = shape.size == 0 || shape.stack || gp > len(registers)-plan.GPUsed || fp > 15-plan.FPUsed
		if !argument.Stack {
			argument.Carriers = shape.leaves
			for leaf := range argument.Carriers {
				carrier := &argument.Carriers[leaf]
				if carrier.Kind == amd64GoArgumentFloating {
					carrier.Register = Reg(fmt.Sprintf("X%d", plan.FPUsed))
					plan.FPUsed++
				} else {
					carrier.Register = registers[plan.GPUsed]
					plan.GPUsed++
				}
			}
		}
		plan.Arguments = append(plan.Arguments, argument)
	}
	return plan, nil
}

type amd64GoArgumentShape struct {
	size, align int64
	stack       bool
	leaves      []amd64GoArgumentCarrier
}

type amd64GoArgumentBuilder struct {
	sizes         types.Sizes
	nodes, leaves int
}

// This models the ordinary Go language types in cmd/compile's ABI assignment:
// abiutils.allocateRegs/tryAllocRegs and types.CalcArraySize. Compiler-intrinsic
// SIMD types and an actual compiler's physical layout still need their own
// producer validation. go/types sizes below are language-model offsets only;
// notably, an older go/types model is not native pointee or spill extent.
func (builder *amd64GoArgumentBuilder) shape(typ types.Type, depth int) (amd64GoArgumentShape, error) {
	var shape amd64GoArgumentShape
	builder.nodes++
	if typ == nil || depth > 32 || builder.nodes > amd64GoArgumentPlanLimit {
		return shape, amd64GoArgumentContext("recursive or unbounded parameter type")
	}
	// Preserve argument.Type above, but inspect the actual RHS before using
	// Underlying: an alias of a TypeParam otherwise looks like its constraint
	// interface and can reach Sizes with no concrete layout. Rhs is expressed
	// as a private interface so the base planner still compiles with Go1.20.
	for {
		// A user-supplied Type implementation can execute arbitrary callbacks
		// from Underlying/String/TypeParams. Only concrete parser/compiler
		// go/types nodes may reach a live source's serialized declaration query.
		switch typ.(type) {
		case *types.Basic, *types.Named, *types.Pointer, *types.Array, *types.Slice,
			*types.Struct, *types.Map, *types.Chan, *types.Signature, *types.Interface, *types.TypeParam:
		default:
			if !goAMD64FrameIsAlias(typ) {
				return shape, amd64GoArgumentContext("argument type is not an original concrete go/types node")
			}
		}
		if generic, ok := typ.(interface{ TypeParams() *types.TypeParamList }); ok && generic.TypeParams().Len() != 0 {
			return shape, amd64GoArgumentContext("generic parameter needs its separate type contract")
		}
		if !goAMD64FrameIsAlias(typ) {
			break
		}
		alias, valid := typ.(interface{ Rhs() types.Type })
		if !valid {
			return shape, amd64GoArgumentContext("alias lacks its actual RHS")
		}
		typ = alias.Rhs()
		depth++
		builder.nodes++
		if typ == nil || depth > 32 || builder.nodes > amd64GoArgumentPlanLimit {
			return shape, amd64GoArgumentContext("recursive or unbounded alias RHS")
		}
	}
	if _, parameter := typ.(*types.TypeParam); parameter {
		return shape, amd64GoArgumentContext("unresolved type parameter has no concrete argument layout")
	}
	add := func(llvm LLVMType, kind amd64GoArgumentKind, width, offset int64, path []int) error {
		builder.leaves++
		if builder.leaves > amd64GoArgumentPlanLimit {
			return amd64GoArgumentContext("scalar carrier inventory exceeds the bounded plan")
		}
		shape.leaves = append(shape.leaves, amd64GoArgumentCarrier{
			Path: path, Offset: offset, Width: width, Type: llvm, Kind: kind,
		})
		return nil
	}
	finishLeaf := func(llvm LLVMType, kind amd64GoArgumentKind, width, offset int64, path []int) (amd64GoArgumentShape, error) {
		err := add(llvm, kind, width, offset, path)
		return builder.finish(typ, shape, err)
	}
	appendChild := func(child amd64GoArgumentShape, index int, offset int64) {
		shape.stack = shape.stack || child.stack
		for _, leaf := range child.leaves {
			leaf.Path = append([]int{index}, leaf.Path...)
			leaf.Offset += offset
			shape.leaves = append(shape.leaves, leaf)
		}
	}
	switch underlying := typ.Underlying().(type) {
	case *types.Basic:
		var llvm LLVMType
		kind, width := amd64GoArgumentInteger, int64(0)
		switch underlying.Kind() {
		case types.Bool:
			llvm, kind, width = I1, amd64GoArgumentBoolean, 1
		case types.Int8, types.Uint8:
			llvm, width = I8, 1
		case types.Int16, types.Uint16:
			llvm, width = I16, 2
		case types.Int32, types.Uint32:
			llvm, width = I32, 4
		case types.Int, types.Uint, types.Uintptr, types.Int64, types.Uint64:
			llvm, width = I64, 8
		case types.UnsafePointer:
			llvm, kind, width = Ptr, amd64GoArgumentPointer, 8
		case types.Float32:
			llvm, kind, width = "float", amd64GoArgumentFloating, 4
		case types.Float64:
			llvm, kind, width = "double", amd64GoArgumentFloating, 8
		case types.Complex64, types.Complex128:
			llvm, kind, width = "float", amd64GoArgumentFloating, 4
			if underlying.Kind() == types.Complex128 {
				llvm, width = "double", 8
			}
			if err := add(llvm, kind, width, 0, []int{0}); err != nil {
				return shape, err
			}
			return finishLeaf(llvm, kind, width, width, []int{1})
		case types.String:
			if err := add(Ptr, amd64GoArgumentPointer, 8, 0, []int{0}); err != nil {
				return shape, err
			}
			return finishLeaf(I64, amd64GoArgumentInteger, 8, 8, []int{1})
		default:
			return shape, amd64GoArgumentContext("unsupported or untyped scalar parameter")
		}
		return finishLeaf(llvm, kind, width, 0, nil)
	case *types.Pointer, *types.Map, *types.Chan, *types.Signature:
		// Pointer-shaped values are opaque carriers. Do not inspect or grant
		// numerical bytes, canonical bools, callable bodies or pointee bounds.
		return finishLeaf(Ptr, amd64GoArgumentPointer, 8, 0, nil)
	case *types.Interface:
		if !underlying.IsMethodSet() {
			return shape, amd64GoArgumentContext("constraint interface is not a concrete argument value")
		}
		for index := 0; index < 2; index++ {
			if err := add(Ptr, amd64GoArgumentPointer, 8, int64(index)*8, []int{index}); err != nil {
				return shape, err
			}
		}
	case *types.Slice:
		if err := add(Ptr, amd64GoArgumentPointer, 8, 0, []int{0}); err != nil {
			return shape, err
		}
		for index := 1; index < 3; index++ {
			if err := add(I64, amd64GoArgumentInteger, 8, int64(index)*8, []int{index}); err != nil {
				return shape, err
			}
		}
	case *types.Array:
		child, err := builder.shape(underlying.Elem(), depth+1)
		if err != nil {
			return shape, err
		}
		n := underlying.Len()
		const maxInt64 = int64(1<<63 - 1)
		if n < 0 || child.size > maxInt64-(child.align-1) {
			return shape, amd64GoArgumentContext("unrepresentable array parameter layout")
		}
		stride := (child.size + child.align - 1) / child.align * child.align
		if n > 0 && stride != 0 && n-1 > (maxInt64-child.size)/stride {
			return shape, amd64GoArgumentContext("array parameter layout overflows")
		}
		switch n {
		case 0:
		case 1:
			appendChild(child, 0, 0)
		default:
			shape.stack = true
		}
	case *types.Struct:
		if underlying.NumFields() > amd64GoArgumentPlanLimit-builder.nodes {
			return shape, amd64GoArgumentContext("field inventory exceeds the bounded plan")
		}
		fields := make([]*types.Var, underlying.NumFields())
		children := make([]amd64GoArgumentShape, len(fields))
		for index := range fields {
			fields[index] = underlying.Field(index)
			child, err := builder.shape(fields[index].Type(), depth+1)
			if err != nil {
				return shape, err
			}
			children[index] = child
		}
		// Descendants are concrete and bounded before go/types traverses them.
		offsets := builder.sizes.Offsetsof(fields)
		for index, child := range children {
			if offsets[index] < 0 || child.size > (1<<63-1)-offsets[index] {
				return shape, amd64GoArgumentContext("struct parameter layout overflows")
			}
			appendChild(child, index, offsets[index])
		}
	default:
		return shape, amd64GoArgumentContext("unsupported concrete parameter type")
	}
	return builder.finish(typ, shape, nil)
}

func (builder *amd64GoArgumentBuilder) finish(typ types.Type, shape amd64GoArgumentShape, err error) (amd64GoArgumentShape, error) {
	if err != nil {
		return shape, err
	}
	shape.size, shape.align = builder.sizes.Sizeof(typ), builder.sizes.Alignof(typ)
	if shape.size < 0 || shape.align <= 0 {
		return shape, amd64GoArgumentContext("parameter lacks a representable language layout")
	}
	return shape, nil
}

func (plan *amd64GoArgumentPlan) requireRegisters() error {
	if plan == nil {
		return amd64GoArgumentContext("missing complete argument plan")
	}
	for _, argument := range plan.Arguments {
		if argument.Stack {
			return amd64GoArgumentContext("stack-assigned argument needs an independent backing contract")
		}
	}
	return nil
}
