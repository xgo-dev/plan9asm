package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func frameRelocationOriginal(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest) []byte {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	env := append(append([]string(nil), request.Environment...),
		"GOOS="+strings.Split(request.Target, "/")[0], "GOARCH=amd64", "CGO_ENABLED=0",
		"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
	object := filepath.Join(t.TempDir(), "original.o")
	listing, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
		"tool", "asm", "-S", "-p", pkg.Path, "-o", object, request.AssemblyFile)
	if err != nil {
		t.Fatalf("original Go assembly failed: %v\n%s", err, listing)
	}
	info, err := os.Stat(object)
	if err != nil || info.Size() == 0 {
		t.Fatal("successful original assembler did not produce a complete object", err)
	}
	t.Logf("original Go %s %s listing:\n%s", runtime.Version(), request.Target, listing)
	return listing
}

func frameRelocationCallListing(listing, numericKind, callee string) error {
	legacy := `""` + callee[strings.LastIndex(callee, "."):]
	var calls [][]string
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "rel" {
			continue
		}
		if len(fields) != 4 {
			return fmt.Errorf("incomplete relocation record: %q", line)
		}
		if fields[2] == "t=R_CALL" || fields[2] == "t="+numericKind ||
			strings.HasPrefix(fields[3], callee+"+") || strings.HasPrefix(fields[3], legacy+"+") {
			calls = append(calls, fields)
		}
	}
	if len(calls) != 1 {
		return fmt.Errorf("expected one exact ordinary callee relocation, got %v", calls)
	}
	call := calls[0]
	span := strings.Split(call[1], "+")
	if len(span) != 2 {
		return fmt.Errorf("invalid CALL relocation span: %v", call)
	}
	offset, err := strconv.ParseUint(span[0], 10, 64)
	if err != nil || call[1] != strconv.FormatUint(offset, 10)+"+4" ||
		(call[2] != "t=R_CALL" && call[2] != "t="+numericKind) ||
		(call[3] != callee+"+0" && call[3] != legacy+"+0") {
		return fmt.Errorf("ordinary CALL lost its exact kind, width, callee or addend: %v", call)
	}
	return nil
}

func TestGoAMD64FrameOrdinaryCallListingIdentity(t *testing.T) {
	const callee = "example.invalid/framefixture.External"
	const named = "rel 38+4 t=R_CALL " + callee + "+0\n"
	numeric := strings.ReplaceAll(named, "t=R_CALL", "t=93")
	for _, test := range []struct {
		name, listing string
		accepted      bool
	}{
		{"named", named, true},
		{"selected-SDK-numeric", numeric, true},
		{"legacy-namespace", strings.ReplaceAll(named, "example.invalid/framefixture.", `"".`), true},
		{"numeric-legacy-namespace", strings.ReplaceAll(numeric, "example.invalid/framefixture.", `"".`), true},
		{"unwind-sibling", "rel 0+8 t=R_ADDR go:sehuw.fixture+0\n" + named, true},
		{"missing", "", false},
		{"foreign-numeric", strings.ReplaceAll(numeric, "t=93", "t=94"), false},
		{"foreign-kind", strings.ReplaceAll(named, "t=R_CALL", "t=R_PCREL"), false},
		{"indirect-kind", strings.ReplaceAll(named, "t=R_CALL", "t=R_CALLIND"), false},
		{"wrong-callee", strings.ReplaceAll(named, ".External", ".Other"), false},
		{"wrong-package", strings.ReplaceAll(named, "framefixture.", "other."), false},
		{"wrong-addend", strings.ReplaceAll(named, "+0", "+1"), false},
		{"wrong-width", strings.ReplaceAll(named, "38+4", "38+8"), false},
		{"invalid-offset", strings.ReplaceAll(named, "38+4", "-1+4"), false},
		{"trailing-fields", strings.TrimSpace(named) + " extra\n", false},
		{"truncated", "rel 38+4 t=R_CALL\n", false},
		{"duplicate", named + named, false},
		{"duplicate-mixed", named + numeric, false},
		{"extra-foreign-callee-kind", named + strings.ReplaceAll(named, "t=R_CALL", "t=R_ADDR"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := frameRelocationCallListing(test.listing, "93", callee); (err == nil) != test.accepted {
				t.Fatal("ordinary relocation print form changed its identity contract", err, test.listing)
			}
		})
	}
}

func TestGoAMD64FrameOrdinaryCallDoesNotMintPermission(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			const assembly = "TEXT ·Caller(SB),4,$24-24\nMOVQ dst+0(FP),AX\nMOVQ AX,0(SP)\n" +
				"MOVQ src+8(FP),AX\nMOVQ AX,8(SP)\nMOVQ n+16(FP),AX\nMOVQ AX,16(SP)\nCALL ·External(SB)\nRET\n"
			pkg, request := goAMD64FrameTypedFixture(t, "func Caller(dst,src *byte,n uintptr)\nfunc External(dst,src *byte,n uintptr)\n", assembly)
			request.Target = target
			listing := frameRelocationOriginal(t, pkg, request)
			// Display spelling is independent of the audited object-schema epoch.
			// Bind numeric relocation names to this request's actual SDK source.
			sdk := filepath.Dir(filepath.Dir(request.GoBinary))
			enum, err := os.ReadFile(filepath.Join(sdk, "src/cmd/internal/objabi/reloctype_string.go"))
			if err != nil {
				t.Fatal(err)
			}
			kinds := regexp.MustCompile(`(?m)^[\t ]*_ = x\[R_CALL-([0-9]+)\][\t ]*$`).FindAllStringSubmatch(string(enum), -1)
			if len(kinds) != 1 {
				t.Fatal("selected SDK lacks one exact R_CALL enum assertion")
			}
			if err := frameRelocationCallListing(string(listing), kinds[0][1], pkg.Path+".External"); err != nil {
				t.Fatal("original ordinary direct CALL relocation was not observed", err, string(listing))
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
				t.Fatal("an ordinary relocation acquired a private-call or callee frame contract", err)
			}
			t.Log("ordinary CALL relocation remained without a callee frame contract")
		})
	}
}
