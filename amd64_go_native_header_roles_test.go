package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keep the complete actual listing and change only one independently named
// writer role. Attribute parsing must not authorize a different entry contract.
func nativeHeaderRoleChanges() []struct{ name, before, after string } {
	return []struct{ name, before, after string }{
		{"dupok", " nosplit", " dupok nosplit"},
		{"cfunc", " nosplit", " cfunc nosplit"},
		{"topframe", " asm", " topframe asm"},
		{"leaf", "", " leaf"},
		{"funcid", "funcid=0x0", "funcid=0x1"},
		{"missing-funcid", " funcid=0x0", ""},
		{"missing-asm", " asm", ""},
	}
}

func nativeHeaderChangedRole(header, before, after string) string {
	if before == "" {
		return header + after
	}
	return strings.Replace(header, before, after, 1)
}

func TestGoAMD64NativeHeaderSpecialRolesKeepEntryContext(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	listing, err := os.ReadFile(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := source.preprocess(request.AssemblyFile, raw)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := goAMD64FrameListing(listing, file, pkg, source.origins); err != nil {
		t.Fatal("complete original ordinary listing positive", err)
	}
	header, body, found := bytes.Cut(listing, []byte{'\n'})
	if !found {
		t.Fatal("actual listing lacks its complete header")
	}
	for _, change := range nativeHeaderRoleChanges() {
		t.Run(change.name, func(t *testing.T) {
			if !strings.Contains(string(header), change.before) {
				t.Fatal("actual ordinary header precondition changed", string(header))
			}
			changed := nativeHeaderChangedRole(string(header), change.before, change.after)
			mutated := []byte(changed + "\n" + string(body))
			if _, err := goAMD64FrameListing(mutated, file, pkg, source.origins); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("observed special or unknown header role acquired ordinary entry authority", err)
			}
		})
	}
}

func TestGoAMD64NativeHeaderActualSpecialRolesStayContext(t *testing.T) {
	for _, row := range []struct{ name, flags string }{
		{"dupok", "6"},
		{"topframe", "2052"},
		{"wrapper-funcid", "36"},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			path := filepath.Join(request.Directory, request.AssemblyFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Official TEXT bits: NOSPLIT=4, DUPOK=2, WRAPPER=32,
			// TOPFRAME=2048. Keep every original body instruction.
			assembly := strings.Replace(string(raw), "#include \"textflag.h\"\n", "", 1)
			assembly = strings.Replace(assembly, "NOSPLIT", row.flags, 1)
			x86InsertExtractGoListing(t, "amd64", assembly)
			if err := os.WriteFile(path, []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if owner != nil {
				if closeErr := owner.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("actual Go special role acquired ordinary fixed-local entry authority", err)
			}
		})
	}
}
