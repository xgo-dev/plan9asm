//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The outgoing words and declarations describe the source. Observing CALL's
// relocation does not prove a callee ABI, reachable inputs or stack ownership.
const frameOrdinaryCallAssembly = `TEXT ·Caller(SB),4,$24-24
	MOVQ dst+0(FP),AX
	MOVQ AX,0(SP)
	MOVQ src+8(FP),AX
	MOVQ AX,8(SP)
	MOVQ n+16(FP),AX
	MOVQ AX,16(SP)
	CALL ·First(SB)
	CALL ·Second(SB)
	RET
`

func TestGoAMD64FrameOrdinaryCallObjectListingIdentity(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		for _, data := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/DATA=%t", target, data), func(t *testing.T) {
				assembly := frameOrdinaryCallAssembly
				if data {
					assembly = "DATA literal<>+0(SB)/8,$7\nGLOBL literal<>(SB),8,$8\n" + assembly
				}
				declarations := "func Caller(dst,src *byte,n uintptr)\nfunc First(dst,src *byte,n uintptr)\nfunc Second(dst,src *byte,n uintptr)\n"
				pkg, request := goAMD64FrameTypedFixture(t, declarations, assembly)
				request.Target = target
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				objectPath := filepath.Join(t.TempDir(), "original.o")
				env := append(append([]string(nil), request.Environment...),
					"GOOS="+strings.Split(target, "/")[0], "GOARCH=amd64", "CGO_ENABLED=0",
					"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
				listing, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
					"tool", "asm", "-S", "-p", pkg.Path, "-o", objectPath, request.AssemblyFile)
				if err != nil {
					t.Fatalf("original Go CALL object: %v\n%s", err, listing)
				}
				object, err := os.ReadFile(objectPath)
				if err != nil {
					t.Fatal(err)
				}
				builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src/cmd/internal/goobj/builtinlist.go"))
				if err != nil {
					t.Fatal(err)
				}
				observed, err := gostaticstorage.ObserveAMD64AssemblyData([]byte(assembly), object, builtin, pkg.Path, target)
				if err != nil || len(observed.Member.Texts) != 1 || len(observed.Member.Texts[0].Relocations) != 2 {
					t.Fatal("independent complete CALL object observation", err)
				}
				for ordinal, relocation := range observed.Member.Texts[0].Relocations {
					t.Logf("actual original relocation %d: %+v", ordinal, relocation)
					want := fmt.Sprintf("rel %d+4 t=R_CALL %s+0", relocation.Offset, relocation.Target.Name)
					if relocation.Type != 7 || relocation.Size != 4 || relocation.Add != 0 ||
						!relocation.Target.ABIKnown || relocation.Target.ABI != 0 ||
						!strings.Contains(string(listing), want) {
						t.Fatal("the original Go producer did not emit the expected direct ABI0 CALL format", relocation, string(listing))
					}
					if got := goAMD64FrameDataRelocationLine(relocation, &observed); got != want {
						t.Error("ordinary CALL record lost exact object/listing association", got, want)
					}
				}
				// This is a deliberately distinct source-contract negative. A
				// correct observation still cannot make these external CALLs into
				// the existing same-source private-leaf frame contract.
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				if err := goAMD64FrameSourceInstructions(file.Funcs[0], map[string]bool{}); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("object observation granted an ordinary callee/frame role", err)
				}
				if target != "windows/amd64" {
					frameOrdinaryCallListingGuards(t, pkg, request, file, assembly, listing, &observed)
				}
				owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
				if owner != nil {
					if closeErr := owner.Close(); closeErr != nil {
						t.Error(closeErr)
					}
				}
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "original CALL needs its complete same-source leaf") {
					t.Fatal("ordinary CALL acquired an unaudited fixed-local frame", err)
				}
			})
		}
	}
}

func frameOrdinaryCallListingGuards(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest,
	file *File, assembly string, listing []byte, observed *gostaticstorage.AMD64AssemblyData) {
	t.Helper()
	input := listing
	if len(observed.Layouts) != 0 {
		var err error
		input, err = goAMD64FrameDataListing(listing, observed)
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(value []byte) error {
		_, err := goAMD64FrameListingWithDataObject(value, file, pkg,
			map[string]int{request.AssemblyFile: strings.Count(assembly, "\n") + 1},
			observed, nil, request.Target, request.Directory, "")
		return err
	}
	if err := check(input); !errors.Is(err, ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "original CALL needs its complete same-source leaf") {
		t.Fatal("exact complete CALL listing did not reach the independent source permission check", err)
	}
	relocations := observed.Member.Texts[0].Relocations
	first := []byte("\t" + goAMD64FrameDataRelocationLine(relocations[0], observed) + "\n")
	second := []byte("\t" + goAMD64FrameDataRelocationLine(relocations[1], observed) + "\n")
	for name, replacement := range map[string][]byte{
		"foreign":   bytes.Replace(first, []byte(pkg.Path+".First"), []byte("foreign.First"), 1),
		"offset":    bytes.Replace(first, []byte(fmt.Sprintf("rel %d+", relocations[0].Offset)), []byte(fmt.Sprintf("rel %d+", relocations[0].Offset+1)), 1),
		"width":     bytes.Replace(first, []byte("+4 t="), []byte("+8 t="), 1),
		"type":      bytes.Replace(first, []byte("R_CALL"), []byte("R_PCREL"), 1),
		"addend":    bytes.Replace(first, []byte("First+0"), []byte("First+1"), 1),
		"missing":   nil,
		"duplicate": append(append([]byte(nil), first...), first...),
		"reordered": second,
	} {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Replace(input, first, replacement, 1)
			err := check(changed)
			if bytes.Equal(changed, input) || !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "object/listing relocation") {
				t.Fatal("changed CALL listing retained its exact original association", err)
			}
		})
	}
}

func TestGoAMD64FrameCallRelocationRetainsPrivateIdentity(t *testing.T) {
	assembly := fixedLocalPrivateLeafSource("CALL leaf<>(SB)\nCALL other<>(SB)", "MOVQ (BP),AX") +
		"TEXT other<>(SB),4,$0\nADDQ $1,AX\nRET\n"
	pkg, request, _ := fixedLocalPrivateLeafFixture(t, assembly)
	owner := requireGoAMD64FrameCapture(t, pkg, request)
	expanded, err := owner.preprocess(request.AssemblyFile, []byte(assembly))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := owner.fixedLocalDataObservation(request.AssemblyFile, expanded)
	if err != nil {
		t.Fatal(err)
	}
	root := observed.TextOrder[0].ObjectOrdinal
	if len(observed.Member.Texts[root].Relocations) != 2 {
		t.Fatal("the private CALL control lost its two exact source/object targets")
	}
	original := observed.Member.Texts[root].Relocations[0]
	if goAMD64FrameDataRelocationLine(original, observed) == "" {
		t.Fatal("existing private CALL lost its observation")
	}
	for _, test := range []struct {
		name string
		edit func(*gostaticstorage.TextRelocation)
	}{
		{"bank", func(r *gostaticstorage.TextRelocation) { r.Target.PackageIndex++ }},
		{"relative", func(r *gostaticstorage.TextRelocation) { r.Target.SymbolIndex++ }},
		{"ABI", func(r *gostaticstorage.TextRelocation) { r.Target.ABI++ }},
		{"unknown-ABI", func(r *gostaticstorage.TextRelocation) { r.Target.ABIKnown = false }},
		{"width", func(r *gostaticstorage.TextRelocation) { r.Size = 8 }},
		{"addend", func(r *gostaticstorage.TextRelocation) { r.Add = 1 }},
		{"kind", func(r *gostaticstorage.TextRelocation) { r.Type = 10 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := original
			test.edit(&changed)
			if goAMD64FrameDataRelocationLine(changed, observed) != "" {
				t.Fatal("ordinary CALL formatting reclassified a mismatched local identity", changed)
			}
		})
	}
}
