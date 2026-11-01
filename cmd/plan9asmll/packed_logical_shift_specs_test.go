package main

import "testing"

func TestExtractSupportedOpsFindsCompletePackedLogicalShiftFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps("../..", arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{
			"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ",
			"VPSLLW", "VPSLLD", "VPSLLQ", "VPSRLW", "VPSRLD", "VPSRLQ",
			"VPSLLVW", "VPSLLVD", "VPSLLVQ", "VPSRLVW", "VPSRLVD", "VPSRLVQ",
			"PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ", "VPSLLDQ", "VPSRLDQ",
		} {
			if _, present := supported[op]; !present {
				t.Errorf("%s logical shift extraction omitted %s", arch, op)
			}
		}
	}
}
