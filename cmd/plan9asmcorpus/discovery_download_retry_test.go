package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryDownloadRetriesTransientProxyFailure(t *testing.T) {
	const module = "example.com/discovery-retry"
	const version = "v1.0.0"
	const goMod = "module " + module + "\n\ngo 1.20\n"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create(module + "@" + version + "/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(goMod)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		status   int
		failures int32
		wantRuns int32
		wantErr  bool
	}{
		{"recover", http.StatusServiceUnavailable, 2, 3, false},
		{"bounded-retries", http.StatusServiceUnavailable, 9, 3, true},
		{"permanent-not-found", http.StatusNotFound, 9, 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/" + module + "/@v/" + version + ".info":
					if requests.Add(1) <= test.failures {
						http.Error(w, http.StatusText(test.status), test.status)
						return
					}
					fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, version)
				case "/" + module + "/@v/" + version + ".mod":
					fmt.Fprint(w, goMod)
				case "/" + module + "/@v/" + version + ".zip":
					_, _ = w.Write(archive.Bytes())
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			t.Setenv("GOPROXY", server.URL)
			t.Setenv("GOSUMDB", "off") // Only this local, synthetic proxy fixture.
			t.Setenv("GONOPROXY", "none")
			t.Setenv("GOMODCACHE", t.TempDir())
			work := filepath.Join(t.TempDir(), "candidate")
			_, _, _, err := runDiscoveryCandidate(
				discoveryCorpusConfig{CandidateTimeout: 30 * time.Second},
				discoveryCandidate{Module: module, Version: version}, work,
			)
			if (err != nil) != test.wantErr || requests.Load() != test.wantRuns {
				t.Fatalf("download requests=%d, error=%v; want requests=%d, error=%v", requests.Load(), err, test.wantRuns, test.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), http.StatusText(test.status)) {
				t.Fatalf("lost final proxy diagnostic: %v", err)
			}
			if _, err := os.Stat(work); !os.IsNotExist(err) {
				t.Fatalf("download attempt leaked its candidate workspace: %v", err)
			}
		})
	}
}

func TestDiscoveryNetworkRetryKeepsDeadlineAndDeterministicFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := retryDiscoveryGoNetwork(ctx, nil, func() error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("canceled download started: calls=%d error=%v", calls, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	transient := errors.New("proxy: TLS handshake timeout")
	err = retryDiscoveryGoNetwork(ctx, []time.Duration{time.Hour}, func() error {
		cancel()
		return transient
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, transient) {
		t.Fatalf("retry lost cancellation or network diagnostic: %v", err)
	}

	for _, diagnostic := range []string{
		"checksum mismatch: SECURITY ERROR",
		"compile: version does not match go tool version",
		"write object: no space left on device",
		"file.s:2: unexpected EOF\nasm: assembly of file.s failed",
	} {
		calls = 0
		failure := errors.New(diagnostic)
		err := retryDiscoveryGoNetwork(context.Background(), []time.Duration{0, 0}, func() error {
			calls++
			return failure
		})
		if !errors.Is(err, failure) || calls != 1 {
			t.Fatalf("retried deterministic failure: calls=%d error=%v", calls, err)
		}
	}
}
