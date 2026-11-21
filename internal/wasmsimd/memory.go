package wasmsimd

import "fmt"

type MemoryOperation uint8

const (
	MemoryWiden MemoryOperation = iota
	MemorySplat
	MemoryZero
	MemoryLoadLane
	MemoryStoreLane
)

// MemoryForm separates the 128-bit lane shape from the bytes actually accessed.
type MemoryForm struct {
	Operation   MemoryOperation
	Shape       Shape
	AccessType  string
	AccessBytes int
	Signed      bool
}

func (f MemoryForm) HasLaneIndex() bool {
	return f.Operation == MemoryLoadLane || f.Operation == MemoryStoreLane
}

var memoryForms = buildMemoryForms()

func LookupMemory(name string) *MemoryForm {
	return memoryForms[name]
}

func buildMemoryForms() map[string]*MemoryForm {
	result := make(map[string]*MemoryForm)
	for _, bits := range []int{8, 16, 32, 64} {
		shape := integerShape(bits)
		prefix := fmt.Sprintf("V128LOAD%d", bits)
		splat := MemoryForm{
			Operation: MemorySplat, Shape: shape,
			AccessType: string(shape.Element), AccessBytes: bits / 8,
		}
		result[prefix+"SPLAT"] = &splat
		if bits >= 32 {
			zero := splat
			zero.Operation = MemoryZero
			result[prefix+"ZERO"] = &zero
		}
		loadLane, storeLane := splat, splat
		loadLane.Operation = MemoryLoadLane
		storeLane.Operation = MemoryStoreLane
		result[prefix+"LANE"] = &loadLane
		result[fmt.Sprintf("V128STORE%dLANE", bits)] = &storeLane

		if bits == 64 {
			continue
		}
		lanes := 64 / bits
		widen := MemoryForm{
			Operation: MemoryWiden, Shape: integerShape(bits * 2),
			AccessType: vectorType(lanes, shape.Element), AccessBytes: 8,
		}
		signed := widen
		signed.Signed = true
		base := fmt.Sprintf("%sX%d", prefix, lanes)
		result[base+"S"] = &signed
		result[base+"U"] = &widen
	}
	return result
}
