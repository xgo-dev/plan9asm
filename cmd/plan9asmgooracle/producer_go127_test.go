//go:build go1.27

package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestActualGoProbeAndCompleteObjectGuards(t *testing.T) {
	inputs, _ := actualInputs(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := canonicalTemp(t)
	accepted := probe(ctx, filepath.Join(dir, "case0"), inputs, 0, "00000000 | MOVD R0,R1")
	logProbe(t, accepted)
	if accepted.Status != "accepted" || accepted.ExitCode != 0 || !accepted.Complete || accepted.ObjectSHA256 == "" {
		t.Fatalf("actual Go acceptance failed: %+v", accepted)
	}
	rejected := probe(ctx, filepath.Join(dir, "case1"), inputs, 1, "00000000 | MOVD (R0),RSP")
	logProbe(t, rejected)
	if rejected.Status != "rejected" || rejected.ExitCode != 1 || !rejected.Complete || !strings.Contains(rejected.Stderr, "probe.s:3") {
		t.Fatalf("actual exact Go source refusal failed: %+v", rejected)
	}
	object, ok := goasmoracle.ReadSource(accepted.Object)
	if !ok {
		t.Fatal("actual object missing")
	}
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"native-bytes", func(_ []byte) []byte { return []byte("ELF native object") }},
		{"wrong-target", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), "linux arm64", "linux amd64", 1))
		}},
		{"wrong-version", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), accepted.ObjectVersion, "go1.26.1", 1))
		}},
		{"truncated", func(data []byte) []byte { return data[:len(data)-1] }},
		{"extra-EOF", func(data []byte) []byte { return append(data, 0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if gostaticstorage.ObserveDecoderARM64Object(test.edit(append([]byte(nil), object...)), "<unlinkable>.probe0") == nil {
				t.Fatal("invalid original object kind/target/version/EOF accepted")
			}
		})
	}
	if gostaticstorage.ObserveDecoderARM64Object(object, "<unlinkable>.probe1") == nil {
		t.Fatal("old probe TEXT borrowed by another case")
	}
	// Controlled tools are only infrastructure counterexamples, never source
	// rejection certificates. The real Go object is retained for the stale case.
	inputs.driver = os.Args[0]
	inputs.environment = append(inputs.environment, "GO_ORACLE_OLD_OBJECT="+base64.StdEncoding.EncodeToString(object))
	for _, mode := range []string{"exit1", "exit2", "footer", "foreign", "foreign-prefix", "wrong-listing", "bad-PC", "panic", "line", "column", "header", "blank", "split", "missing-object", "empty-object", "directory-object", "wrong-kind", "stale-object", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			local := *inputs
			local.environment = append(append([]string(nil), inputs.environment...), "GO_ORACLE_CONTROL="+mode)
			stage, cancel := context.WithTimeout(ctx, 5*time.Second)
			if mode == "timeout" {
				cancel()
				stage, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
			}
			defer cancel()
			item := probe(stage, filepath.Join(dir, mode), &local, 2, "00000000 | MOVD R0,R1")
			logProbe(t, item)
			if item.Status != "failed" || item.Failure == "" {
				t.Fatalf("infrastructure became a source observation: %+v", item)
			}
			if mode == "timeout" && (!item.TimedOut || item.Complete) {
				t.Fatal("timeout counted complete")
			}
		})
	}
}

func TestInputTransactionAndTrustedDriverGuards(t *testing.T) {
	inputs, opt := actualInputs(t)
	if err := inputs.snapshot.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opt.families, []byte("MOVK\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if inputs.snapshot.Verify() == nil {
		t.Fatal("changed complete family input retained authority")
	}
	opt.driver = os.Args[0]
	if _, err := captureInputs(context.Background(), opt); err == nil {
		t.Fatal("test driver minted trusted Go role")
	}
	opt.driver = filepath.Join(opt.goroot, "bin", "go")
	opt.cases = filepath.Join(filepath.Dir(opt.cases), "alias")
	if err := os.Symlink(filepath.Join(filepath.Dir(opt.cases), "cases.txt"), opt.cases); err != nil {
		t.Fatal(err)
	}
	if _, err := captureInputs(context.Background(), opt); err == nil {
		t.Fatal("uncaptured source alias accepted")
	}
}
