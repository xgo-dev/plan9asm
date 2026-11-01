package gotoolprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAMD64OriginalCPPUsesVerifiedPhysicalPackageDirectory(t *testing.T) {
	for _, role := range []string{"root", "nested"} {
		t.Run(role, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, role)
			physical := request.Directory
			root := physical
			if role == "nested" {
				root = filepath.Dir(filepath.Dir(physical))
			}
			alias := filepath.Join(t.TempDir(), "selected")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			request.Directory = alias
			if role == "nested" {
				request.Directory = filepath.Join(alias, "internal", "kernel")
			}
			request.Environment = replaceEnv(request.Environment, map[string]string{"PWD": request.Directory})
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			selected := observed.state.packages[request.PackagePath]
			resolved, err := filepath.EvalSymlinks(selected.Dir)
			if err != nil || resolved != physical {
				t.Fatalf("actual package lost its verified physical identity: %q; %v", selected.Dir, err)
			}
			assembly := filepath.Join(physical, "value_amd64.s")
			proof, present := observed.state.files.cpp[assembly]
			if !present || len(proof.Inputs) != 2 || proof.Inputs[0] != assembly || proof.Expanded == "" {
				t.Fatalf("CPP did not retain the actual assembly and active tool header: %#v", proof)
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), alias); err != nil {
				t.Fatal(err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("redirected package alias retained the old source observation")
			}
		})
	}
}
