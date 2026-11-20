package gotoolprofile

import (
	"reflect"
	"strings"
	"testing"
)

func TestNativeHeaderAuditedPatchRegistration(t *testing.T) {
	previous := nativeHeaderSourceHashes("go1.27.2")
	current := nativeHeaderSourceHashes("go1.27.3")
	if len(previous) != 22 || !reflect.DeepEqual(current, previous) {
		t.Fatal("byte-identical audited header sources lost their complete registration", len(previous), len(current))
	}
	for _, version := range []string{"go1.27.2", "go1.27.3"} {
		proof := &NativeHeaderSourceRules{Protocol: nativeHeaderSourceRulesProtocol, GoVersion: version, SourceSHA256: current}
		if err := ValidateNativeHeaderSourceRules(proof, version); err != nil {
			t.Fatal("audited exact header patch rejected", err)
		}
	}
	for _, version := range []string{"go1.27.2", "go1.27.3"} {
		for name := range current {
			t.Run(version+"/changed/"+name, func(t *testing.T) {
				changed := make(map[string]string, len(current))
				for role, hash := range current {
					changed[role] = hash
				}
				changed[name] = strings.Repeat("0", 64)
				proof := &NativeHeaderSourceRules{Protocol: nativeHeaderSourceRulesProtocol, GoVersion: version, SourceSHA256: changed}
				if ValidateNativeHeaderSourceRules(proof, version) == nil {
					t.Fatal("changed exact header source acquired a registration")
				}
				delete(changed, name)
				if ValidateNativeHeaderSourceRules(proof, version) == nil {
					t.Fatal("missing exact header source acquired a registration")
				}
			})
		}
	}
	for _, version := range []string{"go1.27.4", "go1.27", "go1.27.3-custom", "devel go1.27.3"} {
		if nativeHeaderSourceHashes(version) != nil {
			t.Fatal("unaudited header patch acquired source hashes", version)
		}
	}
}
