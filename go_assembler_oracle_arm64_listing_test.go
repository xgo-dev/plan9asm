package plan9asm

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

// This namespace describes DRconv's diagnostic metadata, not accepted operand
// forms or ISA support. AUTO/OREG share the complete Go displacement directory.
var goAssemblerOracleARM64Classes = func() map[string]bool {
	result := make(map[string]bool)
	for _, name := range strings.Fields(`
		NONE REG ZREG RSP FREG VREG PAIR SHIFT EXTREG SPR COND SPOP ARNG ELEM LIST
		ZCON ABCON0 ADDCON0 ABCON AMCON ADDCON MBCON MOVCON BITCON ADDCON2 LCON
		MOVCON2 MOVCON3 VCON FCON VCONADDR AACON AACON2 LACON AECON SBRA LBRA
		SEXT1 SEXT2 SEXT4 SEXT8 SEXT16 LEXT ADDR GOTADDR TLS_LE TLS_IE ROFF GOK TEXTSIZE NCLASS
	`) {
		result[name] = true
	}
	for _, address := range []string{"AUTO", "OREG"} {
		for _, form := range strings.Fields(`
			Z@ NS@ NS@_16 NS@_8 NS@_4 NP@ NP@_16 NQ@_16 N@4K
			PS@ PS@_16 PS@_8 PS@_4 PP@ PP@_16 PQ@_16
			U@4K U@4K_16 U@4K_8 U@4K_4 U@4K_2
			U@8K U@8K_16 U@8K_8 U@8K_4 U@16K U@16K_16 U@16K_8
			U@32K U@32K_16 U@64K L@POOL L@
		`) {
			result[strings.Replace(form, "@", address, 1)] = true
		}
	}
	return result
}()

// Go 1.22-1.23 already print five classes and pool names, but retain the
// UAUTO32K_8 spelling. Class spelling and diagnostic arity changed separately.
var goAssemblerOracleARM64TransitionalClasses = func() map[string]bool {
	result := make(map[string]bool, len(goAssemblerOracleARM64Classes))
	for name := range goAssemblerOracleARM64Classes {
		result[name] = true
	}
	delete(result, "UAUTO32K_16")
	result["UAUTO32K_8"] = true
	return result
}()

var goAssemblerOracleARM64HistoricalClasses = func() map[string]bool {
	result := make(map[string]bool, len(goAssemblerOracleARM64TransitionalClasses))
	for name := range goAssemblerOracleARM64TransitionalClasses {
		result[name] = true
	}
	delete(result, "LAUTOPOOL")
	delete(result, "LOREGPOOL")
	return result
}()

func goAssemblerOracleARM64SourceDiagnostic(source, arch, output string) bool {
	if arch != "arm64" {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "asm: illegal combination: ") &&
			goasmoracle.SourceDiagnosticLineWithListing(source, line, 0, goAssemblerOracleARM64Listing) {
			return true
		}
	}
	return false
}

func goAssemblerOracleARM64Suffix(suffix string) (string, bool) {
	if suffix == "" {
		return "", true
	}
	post, pre := false, false
	for _, part := range strings.Split(strings.TrimPrefix(suffix, "."), ".") {
		switch part {
		case "P":
			post = true
		case "W":
			pre = true
		default:
			return "", false
		}
	}
	canonical := ""
	if post {
		canonical += ".P"
	}
	if pre {
		canonical += ".W"
	}
	return canonical, true
}

func goAssemblerOracleARM64Listing(original, listing []string) bool {
	for _, schema := range []struct {
		slots   int
		classes map[string]bool
	}{
		{5, goAssemblerOracleARM64Classes},
		{5, goAssemblerOracleARM64TransitionalClasses},
		{4, goAssemblerOracleARM64HistoricalClasses},
	} {
		if goAssemblerOracleARM64ListingSchema(original, listing, schema.slots, schema.classes) {
			return true
		}
	}
	return false
}

func goAssemblerOracleARM64ListingSchema(original, listing []string, slots int, classes map[string]bool) bool {
	tailSize := slots + 3 // Complete class directory, comma, From.Type, To.Type.
	if len(listing) <= tailSize {
		return false
	}
	tail := listing[len(listing)-tailSize:]
	for _, class := range tail[:slots] {
		if !classes[class] {
			return false
		}
	}
	if tail[slots] != "," {
		return false
	}
	for _, text := range tail[slots+1:] {
		kind, err := strconv.Atoi(text)
		if err != nil || kind < 0 || kind > 14 || strconv.Itoa(kind) != text {
			return false
		}
	}
	sourceOp, sourceSuffix, args, sourceOK := goAssemblerOracleX86Statement(original)
	listedOp, listedSuffix, listedArgs, listedOK := goAssemblerOracleX86Statement(listing[:len(listing)-tailSize])
	if !sourceOK || !listedOK {
		return false
	}
	canonical, valid := goAssemblerOracleARM64Suffix(sourceSuffix)
	if !valid || listedSuffix != canonical {
		return false
	}
	alias := ""
	switch sourceOp {
	case "B":
		alias = "JMP"
	case "BL":
		alias = "CALL"
	}
	if alias == "" || listedOp != alias {
		return false
	}
	if reflect.DeepEqual(args, listedArgs) {
		return true
	}
	// asmJump's two-operand form puts the first operand in From. A bare
	// symbol is TYPE_MEM/NAME_NONE with zero offset, not a To TYPE_BRANCH
	// label. Dconv prints only that offset; no label-PC rewrite is allowed.
	return len(args) == 2 && len(listedArgs) == 2 && len(args[0]) == 1 &&
		goAssemblerOracleARM64BareSymbol(args[0][0]) &&
		len(args[1]) == 1 && goAssemblerOracleARM64Register(args[1][0]) &&
		reflect.DeepEqual(listedArgs[0], []string{"0"}) &&
		reflect.DeepEqual(args[1], listedArgs[1]) &&
		tail[0] == "ZOREG" && tail[slots+1] == "3" && tail[slots+2] == "7"
}
