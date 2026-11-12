package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type auditedNamespaceCounts struct {
	official, frontend int
}

var namespaceArchitectures = []string{"386", "amd64", "arm", "arm64", "wasm"}

// These distinct denominators come from the audited original source trees:
// official is architecture-specific Anames; frontend also retains common,
// alias, pseudo and sentinel registrations with their case-sensitive spelling.
// Neither count is a lowering, object or runtime coverage assertion.
var auditedGoNamespaces = map[string]map[string]auditedNamespaceCounts{
	"go1.20": {
		"386":   {official: 1598, frontend: 1655},
		"amd64": {official: 1598, frontend: 1655},
		"arm":   {official: 135, frontend: 155},
		"arm64": {official: 535, frontend: 554},
		"wasm":  {official: 208, frontend: 226},
	},
	"go1.21": {
		"386":   {official: 1599, frontend: 1656},
		"amd64": {official: 1599, frontend: 1656},
		"arm":   {official: 135, frontend: 155},
		"arm64": {official: 531, frontend: 550},
		"wasm":  {official: 207, frontend: 225},
	},
	"go1.22": {
		"386":   {official: 1599, frontend: 1656},
		"amd64": {official: 1599, frontend: 1656},
		"arm":   {official: 135, frontend: 155},
		"arm64": {official: 531, frontend: 550},
		"wasm":  {official: 207, frontend: 225},
	},
	"go1.23": {
		"386":   {official: 1599, frontend: 1657},
		"amd64": {official: 1599, frontend: 1657},
		"arm":   {official: 135, frontend: 156},
		"arm64": {official: 531, frontend: 551},
		"wasm":  {official: 207, frontend: 226},
	},
	"go1.24": {
		"386":   {official: 1599, frontend: 1657},
		"amd64": {official: 1599, frontend: 1657},
		"arm":   {official: 137, frontend: 158},
		"arm64": {official: 531, frontend: 551},
		"wasm":  {official: 207, frontend: 226},
	},
	"go1.25": {
		"386":   {official: 1600, frontend: 1658},
		"amd64": {official: 1600, frontend: 1658},
		"arm":   {official: 137, frontend: 158},
		"arm64": {official: 532, frontend: 552},
		"wasm":  {official: 207, frontend: 226},
	},
	"go1.26": {
		"386":   {official: 1600, frontend: 1658},
		"amd64": {official: 1600, frontend: 1658},
		"arm":   {official: 137, frontend: 158},
		"arm64": {official: 538, frontend: 558},
		"wasm":  {official: 207, frontend: 226},
	},
	"go1.27": {
		"386":   {official: 1600, frontend: 1658},
		"amd64": {official: 1600, frontend: 1658},
		"arm":   {official: 137, frontend: 158},
		"arm64": {official: 1342, frontend: 1362},
		"wasm":  {official: 463, frontend: 502},
	},
}

var auditedGoRelease = regexp.MustCompile(`^(go1\.[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?$`)

func lookupAuditedGoNamespaces(version, arch string) (auditedNamespaceCounts, error) {
	match := auditedGoRelease.FindStringSubmatch(version)
	if match == nil {
		return auditedNamespaceCounts{}, fmt.Errorf("unaudited Go source version %q", version)
	}
	counts, ok := auditedGoNamespaces[match[1]][arch]
	if !ok {
		return auditedNamespaceCounts{}, fmt.Errorf("unaudited Go source namespace %s/%s", version, arch)
	}
	return counts, nil
}

func actualGoNamespaceCounts(t *testing.T, arch string) auditedNamespaceCounts {
	t.Helper()
	version := runtime.Version()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if first := strings.Split(string(data), "\n")[0]; first != version {
		t.Fatalf("actual driver %s differs from GOROOT source VERSION %q", version, first)
	}
	counts, err := lookupAuditedGoNamespaces(version, arch)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual source %s/%s: official=%d frontend=%d", version, arch, counts.official, counts.frontend)
	return counts
}

func TestAuditedGoSourceNamespacesRejectUnknownVersions(t *testing.T) {
	for _, arch := range namespaceArchitectures {
		t.Run(arch, func(t *testing.T) {
			for _, version := range []string{"", "go1.19.13", "go1.28.1", "go1.270.1", "devel go1.27", "go1.27rc1", "go1.27.1-unknown", "go1.27.01"} {
				if _, err := lookupAuditedGoNamespaces(version, arch); err == nil {
					t.Errorf("unknown version %q supplied %s namespace counts", version, arch)
				}
			}
			if _, err := lookupAuditedGoNamespaces("go1.27.1", arch+"-unknown"); err == nil {
				t.Fatal("unknown architecture supplied namespace counts")
			}
		})
	}
}
