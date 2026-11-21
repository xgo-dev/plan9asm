// Package arm64atomic defines the scalar atomic instruction forms shared by
// ARM64 lowering, source effects, and diagnostics.
package arm64atomic

type Kind uint8

const (
	LoadOrdered Kind = iota + 1
	StoreOrdered
	LoadExclusive
	StoreExclusive
	CompareExchange
	ReadModifyWrite
)

// Order encodes the independent LSE release and acquire bits.
type Order uint8

const (
	Relaxed Order = iota
	Release
	Acquire
	AcquireRelease
)

type Form struct {
	Kind        Kind
	Size        uint8 // log2 of the access size in bytes
	Order       Order
	Operation   string
	Invert      bool
	encodedOnly bool
}

const widths = "BHWD"

var orderSuffixes = [...]string{"", "L", "A", "AL"}

type memoryFamily struct {
	stem  string
	kind  Kind
	order Order
}

var memoryFamilies = [...]memoryFamily{
	{"LDAR", LoadOrdered, Acquire},
	{"STLR", StoreOrdered, Release},
	{"LDXR", LoadExclusive, Relaxed},
	{"LDAXR", LoadExclusive, Acquire},
	{"STXR", StoreExclusive, Relaxed},
	{"STLXR", StoreExclusive, Release},
}

type rmwFamily struct {
	stem      string
	operation string
	invert    bool
}

// Indexed by the LSE o3:opc field.
var rmwFamilies = [...]rmwFamily{
	0: {"LDADD", "add", false},
	1: {"LDCLR", "and", true},
	2: {"LDEOR", "xor", false},
	3: {"LDOR", "or", false},
	8: {"SWP", "xchg", false},
}

var forms = buildForms()

func buildForms() map[string]Form {
	out := make(map[string]Form)
	for size := range widths {
		suffix := string(widths[size])
		if suffix == "D" {
			suffix = "" // Ordered and exclusive accesses omit the D.
		}
		for _, family := range memoryFamilies {
			out[family.stem+suffix] = Form{Kind: family.kind, Size: uint8(size), Order: family.order}
		}
		for order := range orderSuffixes {
			cas := Form{Kind: CompareExchange, Size: uint8(size), Order: Order(order)}
			// Go's named CASB/CASH rows omit acquire-only and release-only.
			cas.encodedOnly = size < 2 && (cas.Order == Acquire || cas.Order == Release)
			out[lseOpcode("CAS", cas.Size, cas.Order)] = cas
			for _, family := range rmwFamilies {
				if family.stem == "" {
					continue
				}
				form := Form{
					Kind: ReadModifyWrite, Size: uint8(size), Order: Order(order),
					Operation: family.operation, Invert: family.invert,
				}
				out[lseOpcode(family.stem, form.Size, form.Order)] = form
			}
		}
	}
	return out
}

// Lookup resolves a canonical Plan 9 opcode. Only a decoded word may select
// a form absent from Go's named opcode table.
func Lookup(opcode string, encoded bool) (Form, bool) {
	form, ok := forms[opcode]
	return form, ok && (encoded || !form.encodedOnly)
}

// AddNamed records the exact spellings accepted as named scalar atomics.
func AddNamed(names map[string]struct{}) {
	for name, form := range forms {
		if !form.encodedOnly {
			names[name] = struct{}{}
		}
	}
}

func lseOpcode(stem string, size uint8, order Order) string {
	return stem + orderSuffixes[order] + string(widths[size])
}

// DecodeLSE returns the canonical scalar CAS or RMW opcode of an A64 word.
func DecodeLSE(word uint32) (string, bool) {
	const registersAndSize = uint32(3<<30 | 31<<16 | 31<<5 | 31)
	const casFields = registersAndSize | 1<<22 | 1<<15
	const rmwFields = registersAndSize | 3<<22 | 15<<12
	size := uint8(word >> 30)
	switch {
	case word&^casFields == 0x08a07c00:
		order := Order((word>>21)&2 | (word>>15)&1)
		return lseOpcode("CAS", size, order), true
	case word&^rmwFields == 0x38200000:
		operation := word >> 12 & 15
		if operation < uint32(len(rmwFamilies)) && rmwFamilies[operation].stem != "" {
			return lseOpcode(rmwFamilies[operation].stem, size, Order(word>>22&3)), true
		}
	}
	return "", false
}
