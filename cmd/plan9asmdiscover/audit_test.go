package main

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditModeRanksUnsupportedFormsInMemory(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	files := map[string]string{
		"example.com/crypto@v1.0.0/pkg/pkg.go": "package pkg\n",
		"example.com/crypto@v1.0.0/pkg/fast_amd64.s": `
TEXT ·add(SB),0,$0-0
	MOVQ AX, BX
	ADDQ BX, AX
	BOGUSOP AX, BX
	BOGUSOP CX, DX
	RET
`,
		"example.com/crypto@v1.0.0/pkg/neon_arm64_simd.s": `
TEXT ·vadd(SB),0,$0-0
	ADD R0, R1, R2
	VADD V0.B16, V1.B16, V2.B16
	RET
`,
		"example.com/crypto@v1.0.0/pkg/tagged.s": `//go:build arm && !arm64
TEXT ·armfn(SB),0,$0-0
	ADD R0, R1, R2
	RET
`,
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = io.WriteString(w, `{"Version":"v1.0.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip"):
			serveRangeData(t, w, r, archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rep, err := discover(context.Background(), server.Client(), config{
		indexURL:    defaultIndexURL,
		proxyURL:    server.URL,
		modules:     []moduleVersion{{Path: "example.com/crypto"}},
		audit:       true,
		auditTop:    10,
		workers:     2,
		maxZipSize:  int64(archive.Len()) + 1024,
		httpTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("discover() error = %v", err)
	}
	if rep.Audit == nil {
		t.Fatal("expected non-nil audit summary")
	}
	if rep.Audit.FilesAudited != 3 {
		t.Fatalf("FilesAudited = %d, want 3", rep.Audit.FilesAudited)
	}
	if rep.Audit.ParseErrors != 0 {
		t.Fatalf("ParseErrors = %d, want 0 (%v)", rep.Audit.ParseErrors, rep.Audit.ParseErrorSamples)
	}
	if rep.Audit.SupportedForms < 4 {
		t.Fatalf("SupportedForms = %d, want >= 4", rep.Audit.SupportedForms)
	}
	if rep.Audit.UnsupportedForms != 1 || len(rep.Audit.TopGaps) != 1 {
		t.Fatalf("UnsupportedForms = %d, TopGaps = %#v, want 1", rep.Audit.UnsupportedForms, rep.Audit.TopGaps)
	}
	gap := rep.Audit.TopGaps[0]
	if gap.Arch != "amd64" || gap.Opcode != "BOGUSOP" || gap.Hits != 2 || gap.ModuleCount != 1 {
		t.Fatalf("unexpected top gap: %#v", gap)
	}

	// 2. Pinned mod@v1.0.0 must audit v1.0.0 directly without calling /@latest.
	// 3. Indexed version already equal to @latest must download the ZIP only once.
	var latestHits, zipOpenHits int
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			latestHits++
			_, _ = io.WriteString(w, `{"Version":"v1.0.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip"):
			if r.Method == http.MethodHead {
				zipOpenHits++
			}
			serveRangeData(t, w, r, archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv2.Close()

	pinnedMods, err := parseModuleSpecs("example.com/crypto@v1.0.0")
	if err != nil || len(pinnedMods) != 1 || !pinnedMods[0].Pinned {
		t.Fatalf("parseModuleSpecs pinned = %#v, err=%v", pinnedMods, err)
	}
	repPinned, err := discover(context.Background(), srv2.Client(), config{
		indexURL:    defaultIndexURL,
		proxyURL:    srv2.URL,
		modules:     pinnedMods,
		audit:       true,
		auditTop:    10,
		workers:     1,
		maxZipSize:  int64(archive.Len()) + 1024,
		httpTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("discover pinned error = %v", err)
	}
	if latestHits != 0 {
		t.Fatalf("pinned module called /@latest %d times, want 0", latestHits)
	}
	if repPinned.Audit == nil || repPinned.Audit.FilesAudited != 3 {
		t.Fatalf("pinned audit = %#v, want 3 files", repPinned.Audit)
	}

	zipOpenHits = 0
	repIndexed, err := discover(context.Background(), srv2.Client(), config{
		indexURL:    defaultIndexURL,
		proxyURL:    srv2.URL,
		modules:     []moduleVersion{{Path: "example.com/crypto", Version: "v1.0.0"}},
		audit:       true,
		auditTop:    10,
		workers:     1,
		maxZipSize:  int64(archive.Len()) + 1024,
		httpTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("discover indexed error = %v", err)
	}
	if zipOpenHits != 1 {
		t.Fatalf("indexed==latest opened ZIP %d times, want 1", zipOpenHits)
	}
	if repIndexed.Audit == nil || repIndexed.Audit.FilesAudited != 3 {
		t.Fatalf("indexed==latest audit = %#v, want 3 files", repIndexed.Audit)
	}
}

func TestParseModuleSpecsCSVAndFile(t *testing.T) {
	mods, err := parseModuleSpecs("golang.org/x/sys@v0.30.0, golang.org/x/crypto, golang.org/x/crypto")
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].Version != "v0.30.0" || mods[1].Version != "" {
		t.Fatalf("parseModuleSpecs(csv) = %#v", mods)
	}

	p := filepath.Join(t.TempDir(), "mods.txt")
	if err := os.WriteFile(p, []byte("# comment\ngithub.com/klauspost/compress@v1.17.0\n\ngithub.com/cloudflare/circl # inline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mods2, err := parseModuleSpecs("@" + p)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods2) != 2 || mods2[0].Path != "github.com/klauspost/compress" || mods2[1].Path != "github.com/cloudflare/circl" {
		t.Fatalf("parseModuleSpecs(file) = %#v", mods2)
	}
}

func TestInferAuditArchBuildTagsAndTokens(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
		ok   bool
	}{
		{"sha256_amd64_avx2.s", "", "amd64", true},
		{"aes_arm64_ce.s", "", "arm64", true},
		{"legacy_386_sse.s", "", "386", true},
		{"wasm_exec_wasm.s", "", "wasm", true},
		{"generic.s", "//go:build arm && !arm64\nTEXT ·f(SB),0,$0\n", "arm", true},
		{"plusbuild.s", "// +build amd64\nTEXT ·f(SB),0,$0\n", "amd64", true},
		{"dual.s", "//go:build amd64 || arm64\nTEXT ·f(SB),0,$0\n", "", false},
		{"plain.s", "TEXT ·f(SB),0,$0\n", "", false},
	}
	for _, tc := range cases {
		_, got, ok := inferAuditArch(tc.name, []byte(tc.src))
		if ok != tc.ok || got != tc.want {
			t.Errorf("inferAuditArch(%q) = (%q, %v), want (%q, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAuditCollectorParseErrorAndTopNAndContext(t *testing.T) {
	col := newAuditCollector()
	col.auditFile("example.com/a", "p/parse_amd64.s", []byte("not valid plan9 asm at all"))
	col.auditFile("example.com/a", "p/ctx_amd64.s", []byte("TEXT ·f(SB),0,$0-0\n\tJMP target\n\tBOGUSA AX, BX\n\tBOGUSB $1, AX\n\tBOGUSB $1, AX\n\tBOGUSB $2, AX\n\tRET\n"))
	col.auditFile("example.com/b", "p/more_amd64.s", []byte("TEXT ·g(SB),0,$0-0\n\tBOGUSA CX, DX\n\tRET\n"))
	col.auditFile("example.com/c", "p/unknown.s", []byte("TEXT ·u(SB),0,$0-0\n\tRET\n"))

	sum := col.summarize(1)
	if sum.ParseErrors != 1 || len(sum.ParseErrorSamples) != 1 {
		t.Fatalf("ParseErrors = %d samples=%v, want 1", sum.ParseErrors, sum.ParseErrorSamples)
	}
	if sum.ContextForms < 1 {
		t.Fatalf("expected >=1 context form, got %d", sum.ContextForms)
	}
	if len(sum.TopGaps) != 1 {
		t.Fatalf("TopGaps len = %d, want 1 (capped by topN)", len(sum.TopGaps))
	}
	if _, err := parseModuleSpecs("@/nonexistent/path/to/mods.txt"); err == nil {
		t.Fatal("expected error for missing -modules file")
	}
	if _, err := parseModuleSpecs("   "); err != nil {
		t.Fatalf("empty spec should not error: %v", err)
	}
}

func TestDiscoverFromIndexWithAudit(t *testing.T) {
	archive := testModuleZip(t)
	ts := time.Date(2025, time.February, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/index":
			_, _ = io.WriteString(w, `{"Path":"example.com/lib","Version":"v1.0.0","Timestamp":"`+ts+`"}`+"\n")
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			_, _ = io.WriteString(w, `{"Version":"v1.0.0"}`)
		case strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip"):
			serveRangeData(t, w, r, archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	rep, err := discover(context.Background(), server.Client(), config{
		indexURL:    server.URL + "/index",
		proxyURL:    server.URL,
		limit:       10,
		audit:       true,
		auditTop:    10,
		workers:     1,
		maxZipSize:  int64(len(archive)) + 1024,
		httpTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("discover(index+audit) error = %v", err)
	}
	if rep.IndexEntries != 1 || rep.Audit == nil || rep.Audit.FilesAudited != 1 {
		t.Fatalf("unexpected index+audit report: entries=%d audit=%#v", rep.IndexEntries, rep.Audit)
	}
}
