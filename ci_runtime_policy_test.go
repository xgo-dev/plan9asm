package plan9asm

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCIFullSuitesHaveExplicitTimeout(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	commands := 0
	for line, command := range strings.Split(string(data), "\n") {
		if !strings.Contains(command, "go test ") || !strings.Contains(command, "./...") {
			continue
		}
		commands++
		var timeout time.Duration
		for _, field := range strings.Fields(command) {
			if strings.HasPrefix(field, "-timeout=") {
				timeout, err = time.ParseDuration(strings.TrimPrefix(field, "-timeout="))
				if err != nil {
					t.Errorf("line %d: invalid timeout: %v", line+1, err)
				}
			}
		}
		if timeout < 20*time.Minute {
			t.Errorf("line %d: full suite requires an explicit timeout of at least 20m: %s", line+1, strings.TrimSpace(command))
		}
	}
	if commands == 0 {
		t.Fatal("no full-suite CI commands found")
	}
}

func TestCICrossRuntimeUsesPinnedQEMU(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	cross, found := ciWorkflowJob(string(data), "cross-runtime")
	if !found {
		t.Fatal("cross-runtime job not found")
	}
	if !strings.Contains(cross, "bash scripts/install-ci-qemu.sh") || strings.Contains(cross, "qemu-user") {
		t.Fatal("cross-runtime must install checksum-pinned QEMU, not Ubuntu 24.04's broken 8.2 dot-product implementation")
	}
	script, err := os.ReadFile("scripts/install-ci-qemu.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"version=10.2.3",
		"release=deploy/v10.2.3-68",
		"checksum=8e7d8f4c0c7809fc3fea0085199fd6b16f671e7c73d9bf6bec711e1cb535920a",
		"sha256sum --check --status",
		"tools=(qemu-aarch64 qemu-arm qemu-i386)",
		"GITHUB_PATH",
	} {
		if !strings.Contains(string(script), required) {
			t.Errorf("QEMU installer missing %q", required)
		}
	}
}

func TestCIDiscoveredCorpusRetainsAuthenticatedProxyFallback(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	corpus, found := ciWorkflowJob(string(data), "discovered_library_corpus")
	if !found {
		t.Fatal("discovered corpus job not found")
	}
	if !strings.Contains(corpus, "GOPROXY: https://proxy.golang.org,https://goproxy.cn,direct") {
		t.Fatal("exact-version corpus must try both public module caches before the origin")
	}
	for _, disabled := range []string{"GOSUMDB:", "GONOSUMDB:", "GOPRIVATE:"} {
		if strings.Contains(corpus, disabled) {
			t.Fatalf("public corpus must not bypass checksum-database authentication with %s", disabled)
		}
	}
}

func ciWorkflowJob(source, name string) (string, bool) {
	source = strings.ReplaceAll(source, "\r\n", "\n")
	_, job, found := strings.Cut(source, "\n  "+name+":\n")
	if !found {
		return "", false
	}
	lines := strings.Split(job, "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '#' {
			return strings.Join(lines[:index], "\n"), true
		}
	}
	return job, true
}

func TestCIWorkflowJobLineEndings(t *testing.T) {
	const source = "jobs:\n  first:\n    run: first\n\n  second:\n    run: second\n"
	for _, ending := range []string{"\n", "\r\n"} {
		text := strings.ReplaceAll(source, "\n", ending)
		job, found := ciWorkflowJob(text, "first")
		if !found || !strings.Contains(job, "run: first") || strings.Contains(job, "second") {
			t.Fatalf("line ending %q: job=%q found=%v", ending, job, found)
		}
		if _, found := ciWorkflowJob(text, "absent"); found {
			t.Fatal("missing job accepted")
		}
	}
}
