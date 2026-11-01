package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestTestToolCacheLazyLifetime(t *testing.T) {
	callerCache := t.TempDir()
	t.Setenv("GOCACHE", callerCache)
	marker := filepath.Join(callerCache, "caller-owned")
	if err := os.WriteFile(marker, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	var unused testToolCache
	if err := unused.close(); err != nil || unused.path != "" {
		t.Fatalf("unused cache acquired resources: %v", err)
	}
	if _, err := unused.directory(); err == nil {
		t.Fatal("closed cache was reopened")
	}

	var cache testToolCache
	t.Cleanup(func() {
		if err := cache.close(); err != nil {
			t.Error(err)
		}
	})
	const callers = 8
	paths, failures := make(chan string, callers), make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			path, err := cache.directory()
			paths <- path
			failures <- err
		}()
	}
	group.Wait()
	close(paths)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := <-paths
	if first == callerCache {
		t.Fatal("test cache borrowed the caller's compiler cache")
	}
	for path := range paths {
		if path != first {
			t.Fatal("concurrent callers acquired different compiler caches")
		}
	}
	if err := cache.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("owned cache survived cleanup: %v", err)
	}
	if _, err := cache.directory(); err == nil {
		t.Fatal("disposed cache was recreated")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "retain" {
		t.Fatalf("test cache changed the caller's artifacts: %q %v", data, err)
	}

	t.Run("concurrent close", func(t *testing.T) {
		var cache testToolCache
		t.Cleanup(func() {
			if err := cache.close(); err != nil {
				t.Error(err)
			}
		})
		path, err := cache.directory()
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		type result struct {
			path string
			err  error
		}
		results := make(chan result, callers)
		closed := make(chan error, 1)
		for index := 0; index < callers; index++ {
			go func() {
				<-start
				path, err := cache.directory()
				results <- result{path, err}
			}()
		}
		go func() {
			<-start
			closed <- cache.close()
		}()
		close(start)
		for index := 0; index < callers; index++ {
			got := <-results
			if got.err != nil {
				if !strings.Contains(got.err.Error(), "test compiler cache is closed") || got.path != "" {
					t.Errorf("unexpected acquisition result: %q %v", got.path, got.err)
				}
			} else if got.path != path {
				t.Errorf("concurrent acquisition changed the owned cache: %q, %q", path, got.path)
			}
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if _, err := cache.directory(); err == nil {
			t.Fatal("concurrent close allowed the cache to reopen")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("concurrent close retained its cache: %v", err)
		}
	})
}

func TestTestToolCacheProcessCleanup(t *testing.T) {
	const receiptKey = "PLAN9ASM_TEST_TOOL_CACHE_RECEIPT"
	const replaceKey = "PLAN9ASM_TEST_TOOL_CACHE_REPLACE"
	if receipt := os.Getenv(receiptKey); receipt != "" {
		rootTemporary := t.TempDir()
		for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
			t.Setenv(key, rootTemporary)
		}
		path, err := fixedLocalProcessToolCache.directory()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(receipt, []byte(path), 0600); err != nil {
			t.Fatal(err)
		}
		if os.Getenv(replaceKey) == "1" {
			if err := os.Rename(path, filepath.Join(filepath.Dir(receipt), "original")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "foreign-owner"), []byte("retain"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return // The real TestMain must perform cleanup and choose the exit status.
	}
	for _, mode := range []string{"normal", "replaced"} {
		t.Run(mode, func(t *testing.T) {
			receipt := filepath.Join(t.TempDir(), "cache-path")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTestToolCacheProcessCleanup$", "-test.count=1")
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				switch strings.ToUpper(key) {
				case receiptKey, replaceKey, "TMPDIR", "TMP", "TEMP":
					continue
				}
				command.Env = append(command.Env, entry)
			}
			command.Env = append(command.Env, receiptKey+"="+receipt,
				"TMPDIR="+filepath.Dir(receipt), "TMP="+filepath.Dir(receipt), "TEMP="+filepath.Dir(receipt))
			if mode == "replaced" {
				command.Env = append(command.Env, replaceKey+"=1")
			}
			output, err := runtimeOracleCombinedOutput(ctx, command)
			pathBytes, readErr := os.ReadFile(receipt)
			if readErr != nil {
				t.Fatalf("child did not create its cache: %v\n%s", readErr, output)
			}
			path := string(pathBytes)
			owned, pathErr := filepath.EvalSymlinks(filepath.Dir(receipt))
			if pathErr != nil || filepath.Dir(path) != owned || !strings.HasPrefix(filepath.Base(path), "plan9asm-test-compiler-cache-") {
				t.Fatalf("child cache escaped the parent's owned cleanup directory: %q %v", path, pathErr)
			}
			if mode == "normal" {
				if err != nil {
					t.Fatalf("normal TestMain cleanup: %v\n%s", err, output)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("TestMain retained its cache: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), "refusing to remove a replaced test compiler cache") {
				t.Fatalf("cleanup failure did not fail the process: %v\n%s", err, output)
			}
			if data, err := os.ReadFile(filepath.Join(path, "foreign-owner")); err != nil || string(data) != "retain" {
				t.Fatalf("TestMain removed another owner's replacement: %q %v", data, err)
			}
		})
	}
}

func TestFixedLocalProcessToolCacheKeepsSourcesIndependent(t *testing.T) {
	for _, key := range []string{"GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		t.Setenv(key, "")
	}
	var previous GoAMD64FrameCaptureRequest
	var cache string
	for _, name := range []string{"first-root", "second-root"} {
		t.Run(name, func(t *testing.T) {
			goAMD64FramePrepareOwnedToolCache(t)
			_, request := goAMD64FrameSourceFixture(t)
			if cache != "" && os.Getenv("GOCACHE") != cache {
				t.Fatal("another root replaced the process-owned compiler cache")
			}
			cache = os.Getenv("GOCACHE")
			if previous.Directory != "" {
				if previous.Directory == request.Directory {
					t.Fatal("compiler cache reuse shared original source ownership")
				}
				for _, key := range []string{"GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
					first, second := "", ""
					for _, entry := range previous.Environment {
						if strings.HasPrefix(entry, key+"=") {
							first = strings.TrimPrefix(entry, key+"=")
						}
					}
					for _, entry := range request.Environment {
						if strings.HasPrefix(entry, key+"=") {
							second = strings.TrimPrefix(entry, key+"=")
						}
					}
					if first == "" || second == "" || first == second || second == cache {
						t.Fatalf("compiler artifacts shared a private %s workspace", key)
					}
				}
			}
			previous = request
		})
		if _, err := os.Stat(cache); err != nil {
			t.Fatalf("root cleanup removed the process-owned cache: %v", err)
		}
	}
}
