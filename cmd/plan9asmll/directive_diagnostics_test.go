package main

import "testing"

func TestDirectiveDiagnosticsIncludesCompletePCAlignmentFamily(t *testing.T) {
	for _, name := range []string{"PCALIGN", "PCALIGNMAX", "PCDATA", "FUNCDATA"} {
		if !isDirective(name) {
			t.Errorf("%s is misclassified as a missing machine instruction", name)
		}
	}
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			supported, err := extractSupportedOps("../..", arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"PCALIGN", "PCALIGNMAX", "PCDATA", "FUNCDATA"} {
				if _, known := supported[name]; !known {
					t.Errorf("diagnostic inventory omitted directive %s", name)
				}
			}
		})
	}
}
