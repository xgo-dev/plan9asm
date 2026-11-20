package plan9asm

import (
	"context"
	"reflect"
	"strings"
)

type numericalSDKLiteralMinimumJoin struct {
	alignment, originalAlignment *GoX86SDKLiteralAlignment
	Generation                   uint64
	Seal                         [32]byte
	Minima                       map[string]uint32
}

// BindNumericalReadsWithLiteralAlignment borrows the same original SDK literal
// owner's independent linked-minimum observer. It permits only sealed masked
// low-bit predicates, not general numerical addresses or memory/entry authority.
// All borrowed sources, owners and the original bounded context remain live.
func (source *GoX86NumericalReadSource) BindNumericalReadsWithLiteralAlignment(ctx context.Context, pkg GoPackage, file *File, options Options, minimum *GoX86SDKLiteralAlignment) (Options, error) {
	if minimum == nil {
		return Options{}, numericalSBContext("masked literal predicate needs its live linked minimum")
	}
	return source.bindNumericalReads(ctx, pkg, file, options, minimum)
}

func captureNumericalSDKLiteralMinimum(ctx context.Context, source *GoX86NumericalReadSource, minimum *GoX86SDKLiteralAlignment) (*numericalSDKLiteralMinimumJoin, error) {
	if minimum == nil {
		return nil, nil // Ordinary numerical/literal binding grants no address bits.
	}
	if source == nil || source.identity != source || source.role != numericalSBSDKSource || source.literals == nil ||
		minimum.identity != minimum || minimum.owner != source.literals.owner || minimum.owner.source != source.literals.source ||
		minimum.context != ctx || source.sdk == nil || source.sdk.originalContext != ctx {
		return nil, numericalSBContext("linked minimum has a foreign original source/owner/context")
	}
	if err := minimum.Verify(ctx); err != nil {
		return nil, err
	}
	minimum.mu.Lock()
	joined := &numericalSDKLiteralMinimumJoin{alignment: minimum, originalAlignment: minimum,
		Generation: minimum.generation, Seal: minimum.seal, Minima: make(map[string]uint32)}
	rows := append([]sdkLiteralMinimumAlignment(nil), minimum.observation.Minima...)
	profile := minimum.observation
	minimum.mu.Unlock()
	if profile.Target != source.request.Target || profile.PackagePath != source.request.PackagePath ||
		profile.InitializerSHA256 != source.literals.owner.seal || profile.CGOEnabled != source.guard.env["CGO_ENABLED"] {
		return nil, numericalSBContext("linked minimum actual SDK target/profile/initializer differs")
	}
	_, arch, _ := strings.Cut(source.request.Target, "/")
	if arch != "386" && arch != "amd64" {
		return nil, numericalSBContext("linked minimum lost its actual x86 target width")
	}
	for _, global := range source.file.Globl {
		name := numericalNativeName(strings.TrimSuffix(global.Sym, "<>"), source.request.PackagePath)
		for _, row := range rows {
			if row.Name != name || row.SourceOrdinal != source.literals.SourceOrdinal {
				continue
			}
			if _, duplicate := joined.Minima[global.Sym]; duplicate {
				return nil, numericalSBContext("linked minimum has ambiguous original object identity")
			}
			matches := 0
			for _, image := range source.literals.Initializers.Initializers {
				definition := image.Definition
				if image.SourceOrdinal == row.SourceOrdinal && image.MemberOrdinal == row.MemberOrdinal &&
					definition.Namespace == row.Namespace && definition.Index == row.Index && definition.Name == row.Name &&
					definition.Size == row.Size && int64(row.Size) == global.Size && int64(len(image.Initial)) == global.Size {
					matches++
				}
			}
			if matches != 1 || row.MinimumAlignment == 0 || row.MinimumAlignment&(row.MinimumAlignment-1) != 0 ||
				int64(row.MinimumAlignment) > goAssemblyDataAlignment(Arch(arch), global.Size) {
				return nil, numericalSBContext("linked minimum lost its exact original object/extent/emitted floor")
			}
			joined.Minima[global.Sym] = row.MinimumAlignment
		}
	}
	if len(joined.Minima) == 0 {
		return nil, numericalSBContext("no unique retained original linked minimum for this complete source")
	}
	return joined, nil
}

func (joined *numericalSDKLiteralMinimumJoin) live() bool {
	if joined == nil || joined.alignment == nil || joined.alignment != joined.originalAlignment || joined.alignment.identity != joined.alignment {
		return false
	}
	observed := joined.alignment
	observed.mu.Lock()
	defer observed.mu.Unlock()
	return observed.ready && !observed.closePending && observed.generation == joined.Generation && observed.seal == joined.Seal
}

func (joined *numericalSDKLiteralMinimumJoin) verify(ctx context.Context, source *GoX86NumericalReadSource) error {
	if !joined.live() {
		return numericalSBContext("linked minimum factory generation is closed, changed or foreign")
	}
	actual, err := captureNumericalSDKLiteralMinimum(ctx, source, joined.alignment)
	if err != nil {
		return err
	}
	if actual.Generation != joined.Generation || actual.Seal != joined.Seal || !reflect.DeepEqual(actual.Minima, joined.Minima) {
		return numericalSBContext("linked minimum retained projection changed")
	}
	return nil
}

func validSDKLiteralLowBitForm(ins Instr, bits *x86SDKLiteralLowBits, arch string) bool {
	if bits == nil || arch != "amd64" && arch != "386" || bits.Mask >= uint64(goAssemblyDataAlignment(Arch(arch), 1<<32)) || bits.Value&^bits.Mask != 0 {
		return false
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil && form.spec.stem == "OR" {
		return int64(form.spec.bits/8) == x86ResultPointerWord(arch) && bits.Bytes == x86ResultPointerWord(arch) && form.source.Kind == OpReg && form.destination.Kind == OpReg
	}
	form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch)
	if !known || err != nil || !form.test || bits.Bytes != int64(form.bits/8) || form.args[0].Kind != OpImm || form.args[1].Kind != OpReg {
		return false
	}
	mask := uint64(form.args[0].Imm)
	if form.bits < 64 {
		mask &= uint64(1)<<uint(form.bits) - 1
	}
	return mask == bits.Mask
}

func x86ResultSDKLiteralLowBitStep(ins Instr, bits *x86SDKLiteralLowBits, state *x86ResultState, arch string) bool {
	if !validSDKLiteralLowBitForm(ins, bits, arch) {
		return false
	}
	read := func(operand Operand, width int64) bool {
		root, _, valid := x86ResultGP(operand.Reg, width, arch)
		return operand.Kind == OpReg && valid && (state.shapeOnly || state.pointerGP[root])
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil {
		if !read(form.source, x86ResultPointerWord(arch)) || !read(form.destination, x86ResultPointerWord(arch)) {
			return false
		}
		root, _, _ := x86ResultGP(form.destination.Reg, x86ResultPointerWord(arch), arch)
		state.gp[root], state.pointerGP[root] = 0, true
	} else if !read(ins.Args[1], bits.Bytes) {
		return false
	}
	state.flags = state.flags&^x86ByteFlagAF | (x86ByteFlagsAll &^ x86ByteFlagAF)
	return true // Only FLAGS/opaque carrier effects, never full GP bytes.
}
