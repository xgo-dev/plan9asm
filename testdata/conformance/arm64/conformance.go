//go:build arm64

package arm64conformance

func families(out *[76]uint64, data *[8]uint64)

func pairStores(out *[20]uint64, data *[8]uint64)

var pairStoreData [10]uint64
