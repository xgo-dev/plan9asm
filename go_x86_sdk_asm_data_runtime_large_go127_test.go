//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSDKX86RelativeIncludeActualRuntimeFactory(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, arch, "runtime")
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				t.Fatal("complete actual SDK factory/compiler/original-expanded objects", err)
			}
			defer source.Close()
			header := filepath.Join(source.guard.env["GOROOT"], "src", "runtime", "go_tls.h")
			if arch == "amd64" {
				header = filepath.Join(source.guard.env["GOROOT"], "src", "runtime", "cgo", "abi_amd64.h")
			}
			if _, present := source.guard.inputs[header]; !present || source.observation.Objects == nil ||
				len(source.observation.CPP) != len(source.guard.selection.SFiles) || source.guard.ready {
				t.Fatal("actual factory lost selected headers, full original-object join or role separation")
			}
			if arch == "386" {
				// go_tls.h is also in the direct primary inventory. Require its
				// actual CPP source record, not just the inventory's prior read.
				wantSHA256 := fmt.Sprintf("%x", source.guard.inputs[header])
				observedHeader := false
				for _, cpp := range source.observation.CPP {
					for _, observed := range cpp.Sources {
						if observed.File == header && observed.SHA256 == wantSHA256 && observed.Bytes > 0 {
							observedHeader = true
						}
					}
				}
				if !observedHeader {
					t.Fatal("actual 386 CPP execution did not observe its exact SDK TLS header")
				}
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("actual complete SDK capture did not verify", err)
			}
			// Mutate only this factory's owned expanded program, never installed SDK
			// files. The same published-generation guard owns every selected input.
			program := filepath.Join(source.guard.owned, "expanded-0.s")
			original, err := os.ReadFile(program)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(program, append(append([]byte(nil), original...), []byte("\n// changed owned input\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("changed actual input kept its published source generation")
			}
			if err := os.WriteFile(program, original, 0600); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restoring owned bytes revived a revoked SDK source")
			}
		})
	}
}
