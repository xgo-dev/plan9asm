package main

import (
	"strings"
	"testing"
)

func TestBlockExtractStoreCoverageRequiresInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, suffix := range []string{"F128", "I128", "F32X4", "I32X4", "F64X2", "I64X2", "F32X8", "I32X8", "F64X4", "I64X4"} {
			banks := []string{"Y", "Z"}
			if strings.HasSuffix(suffix, "128") {
				banks = []string{"Y"}
			} else if strings.HasSuffix(suffix, "32X8") || strings.HasSuffix(suffix, "64X4") {
				banks = []string{"Z"}
			}
			for _, bank := range banks {
				t.Run(arch+"/"+suffix+"/"+bank, func(t *testing.T) {
					valueProbeNeedsContext(t, arch, "VEXTRACT"+suffix+" $255,"+bank+"1,(BX)")
				})
			}
		}
	}
}
