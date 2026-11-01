package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
)

var globlFlagName = regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9]*`)

// Values are defined by Go's runtime/textflag.h and cmd/internal/obj/textflag.go.
// In particular NOPTR is GC metadata, not a promise that storage is immutable.
var goTextFlagValues = map[string]string{
	"NOPROF": "1", "DUPOK": "2", "NOSPLIT": "4", "RODATA": "8",
	"NOPTR": "16", "WRAPPER": "32", "NEEDCTXT": "64", "TLSBSS": "256",
	"NOFRAME": "512", "REFLECTMETHOD": "1024", "TOPFRAME": "2048", "ABIWRAPPER": "4096",
}

func globlReadOnly(flags string) (bool, error) {
	if strings.TrimSpace(flags) == "" {
		return false, nil
	}
	expression := globlFlagName.ReplaceAllStringFunc(flags, func(name string) string {
		if value, ok := goTextFlagValues[name]; ok {
			return value
		}
		return name
	})
	value, ok := parseImmExpr(expression)
	if !ok {
		return false, fmt.Errorf("unresolved GLOBL flags %q", flags)
	}
	return value&8 != 0, nil
}
