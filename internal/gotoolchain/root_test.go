package gotoolchain

import (
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseRootRejectsMismatchedOrInvalidGo(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct {
		name    string
		output  string
		version string
		wantErr bool
	}{
		{
			name: "matching", output: `{"GOROOT":` + strconv.Quote(root) + `,"GOVERSION":"go1.27.1"}`,
			version: "go1.27.1",
		},
		{
			name: "different version", output: `{"GOROOT":` + strconv.Quote(root) + `,"GOVERSION":"go1.27.0"}`,
			version: "go1.27.1", wantErr: true,
		},
		{
			name: "relative root", output: `{"GOROOT":"relative","GOVERSION":"go1.27.1"}`,
			version: "go1.27.1", wantErr: true,
		},
		{
			name: "missing root", output: `{"GOVERSION":"go1.27.1"}`,
			version: "go1.27.1", wantErr: true,
		},
		{
			name: "invalid JSON", output: `{`, version: "go1.27.1", wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseRoot([]byte(test.output), test.version)
			if (err != nil) != test.wantErr {
				t.Fatalf("root = %q, error = %v, want error %v", got, err, test.wantErr)
			}
			if !test.wantErr && filepath.Clean(got) != root {
				t.Fatalf("root = %q, want %q", got, root)
			}
		})
	}
}
