package gotoolprofile

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

const DataOnlyAssemblyProtocol = "actual_go_data_only_symbol_listing_v1"

// The producer derives the complete compact symbol inventory from a successful
// original Go -S listing, rejecting every TEXT and unknown listing record.
// Full data dumps stay out of the ledger. Like native empty-object evidence,
// offline validation relies on the frozen producer, not a digest claiming to
// cryptographically authenticate unavailable object bytes.
type DataOnlyAssemblyProof struct {
	Native  EmptyAssemblyProof `json:"native"`
	Symbols []DataOnlySymbol   `json:"symbols"`
}

type DataOnlySymbol struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Static bool   `json:"static,omitempty"`
	Size   int64  `json:"size"`
}

func (symbol DataOnlySymbol) Key() string {
	if symbol.Static {
		return symbol.Name + "<>"
	}
	return symbol.Name
}

var dataSymbolHeader = regexp.MustCompile(`^(\S+) (S[A-Z0-9]+) (static )?(dupok )?(cfunc )?size=([0-9]+) align=0x[0-9a-f]+$`)
var legacyDataSymbolHeader = regexp.MustCompile(`^(\S+) (S[A-Z0-9]+) (static )?(dupok )?(cfunc )?size=([0-9]+)$`)
var dataListingBytes = regexp.MustCompile(`^\t0x[0-9a-f]+( [0-9a-f]{2}){1,16} {2,}`)
var dataListingRelocation = regexp.MustCompile(`^\trel -?[0-9]+\+[0-9]+ t=R_[A-Za-z0-9_:]+ .+\+-?[0-9a-f]+$`)

func isDataOnlySymbolKind(kind string) bool {
	switch kind {
	case "SRODATA", "SRODATAFIPS", "SDATA", "SDATAFIPS", "SNOPTRDATA", "SNOPTRDATAFIPS", "SBSS", "SNOPTRBSS", "STLSBSS":
		return true
	default:
		return false
	}
}

func DataOnlySymbolsFromListing(listing []byte) ([]DataOnlySymbol, error) {
	return dataOnlySymbolsFromListing(listing, dataSymbolHeader)
}

// DataOnlySymbolsFromListingForGoVersion selects the actual producer's header
// grammar. Go 1.20-1.26 print alignment only for TEXT; Go 1.27 also prints it
// for DATA. A missing current field or an extra historical field is not valid.
// This parses an inventory, not a source, memory or object capability.
func DataOnlySymbolsFromListingForGoVersion(listing []byte, version string) ([]DataOnlySymbol, error) {
	minor, err := goMinor(version)
	if err != nil || minor < 20 || minor > 27 {
		return nil, fmt.Errorf("data-only listing requires a supported actual Go producer version")
	}
	header := dataSymbolHeader
	if minor < 27 {
		header = legacyDataSymbolHeader
	}
	return dataOnlySymbolsFromListing(listing, header)
}

func dataOnlySymbolsFromListing(listing []byte, header *regexp.Regexp) ([]DataOnlySymbol, error) {
	if len(listing) == 0 || len(listing) > 4<<20 || listing[len(listing)-1] != '\n' {
		return nil, fmt.Errorf("data-only native listing is empty, incomplete or too large")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(listing)))
	scanner.Buffer(nil, 64<<10)
	var symbols []DataOnlySymbol
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "\t") {
			if len(symbols) == 0 || !dataListingBytes.MatchString(line) && !dataListingRelocation.MatchString(line) {
				return nil, fmt.Errorf("unknown non-data native listing record")
			}
			continue
		}
		match := header.FindStringSubmatch(line)
		if match == nil || !isDataOnlySymbolKind(match[2]) {
			return nil, fmt.Errorf("native data-only listing contains TEXT or an unknown symbol kind")
		}
		size, err := strconv.ParseInt(match[6], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid native data symbol size: %w", err)
		}
		symbols = append(symbols, DataOnlySymbol{Name: match[1], Kind: match[2], Static: match[3] != "", Size: size})
		if len(symbols) > 16384 {
			return nil, fmt.Errorf("native data-only symbol inventory exceeds its bound")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(symbols, func(i, j int) bool { return symbols[i].Key() < symbols[j].Key() })
	if err := validateDataOnlySymbols(symbols); err != nil {
		return nil, err
	}
	return symbols, nil
}

func validateDataOnlySymbols(symbols []DataOnlySymbol) error {
	if len(symbols) == 0 || len(symbols) > 16384 {
		return fmt.Errorf("data-only assembly lacks a bounded nonempty symbol inventory")
	}
	for index, symbol := range symbols {
		if symbol.Name == "" || strings.ContainsAny(symbol.Name, "\x00\r\n\t <>") ||
			!isDataOnlySymbolKind(symbol.Kind) || symbol.Size < 0 ||
			index > 0 && symbol.Key() <= symbols[index-1].Key() {
			return fmt.Errorf("noncanonical, duplicate or non-data native symbol inventory")
		}
	}
	return nil
}

// ValidateDataOnlySourceSymbols compares the complete parsed source's global
// identities and sizes with the actual original assembler listing inventory.
// It neither supplies bytes nor grants a source, object or native-memory role.
func ValidateDataOnlySourceSymbols(file *plan9asm.File, packagePath string, symbols []DataOnlySymbol) error {
	if file == nil || len(file.Funcs) != 0 || len(file.Globl) == 0 {
		return fmt.Errorf("data-only source requires global declarations and no TEXT")
	}
	if err := validateDataOnlySymbols(symbols); err != nil {
		return err
	}
	wanted := make(map[string]int64)
	for _, global := range file.Globl {
		name := strings.TrimSuffix(global.Sym, "<>")
		if strings.HasPrefix(name, "·") {
			name = NativeGoPackagePrefix(packagePath) + name
		}
		name = strings.ReplaceAll(strings.ReplaceAll(name, "·", "."), "∕", "/")
		if strings.HasSuffix(global.Sym, "<>") {
			name += "<>"
		}
		if _, duplicate := wanted[name]; duplicate || global.SizeRaw != "" {
			return fmt.Errorf("data-only source has duplicate or unresolved GLOBL")
		}
		wanted[name] = global.Size
	}
	if len(wanted) != len(symbols) {
		return fmt.Errorf("Go native data symbols differ from translated global declarations")
	}
	for _, symbol := range symbols {
		if size, present := wanted[symbol.Key()]; !present || size != symbol.Size {
			return fmt.Errorf("Go native data symbol name/size differs from translated GLOBL")
		}
	}
	return nil
}

// NativeGoPackagePrefix is cmd/asm's byte-level objabi.PathToPrefix spelling,
// not the LLVM logical symbol namespace and not URL escaping.
func NativeGoPackagePrefix(packagePath string) string {
	return gosym.PackagePrefix(packagePath)
}

func ValidateDataOnlyAssembly(input *ConsumerInput, cpp CPPProof, pkg PackageProof) error {
	proof := cpp.DataOnlyAssembly
	if (cpp.Emission == "data_only") != (proof != nil) {
		return fmt.Errorf("data-only assembly requires an explicit same-scope native witness")
	}
	if proof == nil {
		return nil
	}
	native := proof.Native
	if input == nil || input.Observed == nil || input.SignatureSourceProtocol != SignatureSourceProtocol ||
		native.Protocol != DataOnlyAssemblyProtocol || cpp.EmptyAssembly != nil || len(cpp.Signatures) != 0 ||
		native.File != cpp.File || native.SourceSHA256 != input.Sources[cpp.File] ||
		native.PackagePath != pkg.PackagePath || native.ProfileID != input.ID ||
		native.Target != input.Observed.Target || native.GoVersion != input.Observed.GoVersion ||
		native.AsmToolSHA256 != input.Observed.ToolBinarySHA256["asm"] ||
		!discoverySHA256Pattern.MatchString(native.ObjectSHA256) ||
		native.ObjectSHA256 == bytesSHA256(nil) ||
		!discoverySHA256Pattern.MatchString(native.ListingSHA256) || native.ListingSHA256 == bytesSHA256(nil) {
		return fmt.Errorf("data-only evidence differs from its actual Go/source/package/profile scope")
	}
	return validateDataOnlySymbols(proof.Symbols)
}
