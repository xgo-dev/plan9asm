package gotoolchain

import "testing"

func TestAuditedGo127(t *testing.T) {
	for _, version := range []string{"go1.27.1", "go1.27.2", "go1.27.3"} {
		if !AuditedGo127(version) {
			t.Errorf("audited release %q rejected", version)
		}
	}
	for _, version := range []string{
		"", "go1.27", "go1.27.0", "go1.27.4", "go1.28.1", "go1.26.2",
		"go1.27.3rc1", "go1.27.3-custom", "devel go1.27.3", "go1.27.3\n",
	} {
		if AuditedGo127(version) {
			t.Errorf("unaudited release %q accepted", version)
		}
	}
}
