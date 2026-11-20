package plan9asm

import (
	"crypto/sha256"
	"encoding/json"
	"go/types"
	"reflect"
)

// Only a complete numerical source binder or the call-local GoModule issuer
// creates this private token. It authenticates declared argument carriers,
// not physical stack, closure, caller, call target, pointer extent or result
// transport permissions.
type amd64GoArgumentBinding struct {
	identity    *amd64GoArgumentBinding
	owner       *GoX86NumericalReadBinding
	virtual     *amd64GoVirtualArguments
	declaration *types.Func
	symbol      string
	signature   FuncSig
	plan        *amd64GoArgumentPlan
	seal        [32]byte
}

func (entry *amd64GoArgumentBinding) digest() ([32]byte, error) {
	type argument struct {
		Index    int
		Carriers []amd64GoArgumentCarrier
	}
	var arguments []argument
	if entry.plan != nil {
		for _, input := range entry.plan.Arguments {
			arguments = append(arguments, argument{input.Index, input.Carriers})
		}
	}
	data, err := json.Marshal(struct {
		Symbol    string
		Signature FuncSig
		Arguments []argument
	}{entry.symbol, entry.signature, arguments})
	return sha256.Sum256(data), err
}

func (entry *amd64GoArgumentBinding) valid(fn Func, sig FuncSig, arch string) bool {
	if entry != nil && entry.virtual != nil {
		if entry.identity != entry || entry.owner != nil || entry.declaration == nil || entry.plan == nil || entry.virtual.entries[sig.Name] != entry ||
			entry.virtual.live() != nil || arch != "amd64" || fn.Sym != entry.symbol || fn.FrameSize != 0 ||
			len(fn.X86RawText) != 0 || fn.x86FixedLocal != nil || fn.x86SourceStack != nil {
			return false
		}
		return entry.matches(sig)
	}
	if entry == nil || entry.identity != entry || entry.owner == nil || arch != "amd64" || fn.Sym != entry.symbol ||
		entry.owner.originalBinding != entry.owner || entry.owner.source == nil || entry.owner.source != entry.owner.originalSource ||
		entry.declaration == nil || entry.plan == nil || entry.owner.originalTypes == nil ||
		entry.owner.originalTypes.Scope().Lookup(entry.declaration.Name()) != entry.declaration ||
		entry.owner.capabilities[sig.Name].arguments != entry || entry.owner.options.Sigs[sig.Name].amd64GoArguments != entry {
		return false
	}
	source := entry.owner.source
	source.mu.Lock()
	ready := source.identity == source && source.ready && !source.revoked.Load()
	source.mu.Unlock()
	if !ready || fn.FrameSize != 0 || len(fn.X86RawText) != 0 || fn.x86FixedLocal != nil || fn.x86SourceStack != nil {
		return false
	}
	return entry.matches(sig)
}

func (entry *amd64GoArgumentBinding) matches(sig FuncSig) bool {
	// Feature references are rendered after the complete public options check.
	// They are not part of a language argument's physical carrier assignment.
	shape := numericalSignatureShape(sig)
	shape.Attrs = entry.signature.Attrs
	if !reflect.DeepEqual(shape, entry.signature) {
		return false
	}
	declaration, valid := entry.declaration.Type().(*types.Signature)
	if !valid {
		return false
	}
	plan, err := planAMD64GoArguments(declaration)
	if err != nil || plan.requireRegisters() != nil || !reflect.DeepEqual(plan, entry.plan) {
		return false
	}
	for index, argument := range plan.Arguments {
		if argument.Type != entry.plan.Arguments[index].Type {
			return false
		}
	}
	digest, err := entry.digest()
	if entry.virtual != nil {
		return err == nil && digest == entry.seal && entry.virtual.live() == nil
	}
	source := entry.owner.source
	source.mu.Lock()
	ready := source.identity == source && source.ready && !source.revoked.Load()
	source.mu.Unlock()
	return err == nil && digest == entry.seal && ready
}

func amd64GoArgumentInitialState(plan *amd64GoArgumentPlan) (x86ResultState, bool) {
	var initial x86ResultState
	if plan == nil || plan.requireRegisters() != nil {
		return initial, false
	}
	for _, argument := range plan.Arguments {
		for _, carrier := range argument.Carriers {
			if carrier.Kind == amd64GoArgumentFloating {
				index, valid := amd64ParseXReg(carrier.Register)
				if !valid || index >= 15 || carrier.Width != 4 && carrier.Width != 8 {
					return x86ResultState{}, false
				}
				initial.xmm[index] = uint16(1<<uint(carrier.Width)) - 1
				continue
			}
			reg, mask, valid := x86ResultGP(carrier.Register, carrier.Width, "amd64")
			if !valid || carrier.Register == DX {
				return x86ResultState{}, false
			}
			switch carrier.Kind {
			case amd64GoArgumentPointer:
				initial.pointerGP[reg], initial.callerAddressGP[reg] = true, true
			case amd64GoArgumentBoolean:
				initial.gp[reg], initial.canonicalGP[reg] = mask, mask
			case amd64GoArgumentInteger:
				initial.gp[reg] = mask
			default:
				return x86ResultState{}, false
			}
		}
	}
	return initial, true
}
