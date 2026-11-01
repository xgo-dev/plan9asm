package gostaticstorage

// SDK globals retain the complete recursive original owner tree (including
// ignored files, separate nested packages and testdata), plus every selected
// dependency's original Go/ASM/header bytes. This is a larger source role than
// the flat owned-module prototype, not permission to omit unselected inputs.
// The same finite accounting applies to capture, live verification and offline
// report validation. CPU's separately pinned whole inventory stays unchanged.
type sourceInventoryBudget struct {
	files int
	bytes int64
}

func sourceBudget(protocol string) sourceInventoryBudget {
	if protocol == SDKGlobalsProtocol {
		return sourceInventoryBudget{files: 4096, bytes: 64 << 20}
	}
	return sourceInventoryBudget{files: 256, bytes: 16 << 20}
}

func (budget sourceInventoryBudget) checkCount(count int) error {
	if count > budget.files {
		return contextError("source inventory bound exceeded")
	}
	return nil
}

func (budget sourceInventoryBudget) checkBytes(total int64, length int) error {
	if length > 16<<20 {
		return contextError("source file byte bound exceeded")
	}
	if total > budget.bytes || int64(length) > budget.bytes-total {
		return contextError("source byte bound exceeded")
	}
	return nil
}

type sourceInventoryUsage struct {
	budget sourceInventoryBudget
	files  int
	bytes  int64
}

func sourceUsage(source map[string][]byte, protocol string) (sourceInventoryUsage, error) {
	usage := sourceInventoryUsage{budget: sourceBudget(protocol)}
	if err := usage.budget.checkCount(len(source)); err != nil {
		return sourceInventoryUsage{}, err
	}
	for _, data := range source {
		if err := usage.add(len(data)); err != nil {
			return sourceInventoryUsage{}, err
		}
	}
	return usage, nil
}

// A caller adds only a previously absent source key, after independently
// checking any duplicate's original bytes. Failed additions leave the complete
// inventory unchanged and are rejected before bytes enter the retained map.
func (usage *sourceInventoryUsage) add(length int) error {
	if err := usage.budget.checkCount(usage.files + 1); err != nil {
		return err
	}
	if err := usage.budget.checkBytes(usage.bytes, length); err != nil {
		return err
	}
	usage.files++
	usage.bytes += int64(length)
	return nil
}

func validateSourceInventory(source map[string][]byte, protocol string) error {
	_, err := sourceUsage(source, protocol)
	return err
}
