//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64FrameDataOrdinaryReferenceIsNotPermission(t *testing.T) {
	const assembly = `DATA literal<>+0(SB)/8,$7
GLOBL literal<>(SB),8,$8
TEXT ·Value(SB),4,$16-16
	MOVQ a+0(FP),AX
	MOVQ AX,0(SP)
	MOVQ literal<>(SB),CX
	MOVQ $·Global(SB),BX
	MOVQ 0(SP),AX
	MOVQ AX,ret+8(FP)
	RET
`
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
		"func Global() {}\nfunc Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete original DATA and ordinary reference", err)
	}
	if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("observing an ordinary code reference granted a variable address role", err)
	}
}

// DATA coexistence is an original-object observation, not a new memory,
// address, native-entry or fixed-local permission.
func TestGoAMD64FrameSourceMixedDataOriginalObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		for _, used := range []bool{false, true} {
			name := "unused"
			if used {
				name = "referenced"
			}
			t.Run(target+"/"+name, func(t *testing.T) {
				pkg, request := goAMD64FrameSourceFixture(t)
				request.Target = target
				assembly := "DATA literal<>+0(SB)/8,$0x102030405060708\n" +
					"DATA literal<>+16(SB)/4,$\"abcd\"\n" +
					"GLOBL literal<>(SB),8,$32\n" +
					"DATA mutable<>+0(SB)/8,$0x55667788\n" +
					"GLOBL mutable<>(SB),16,$8\n" +
					"GLOBL zero<>(SB),16,$24\n" +
					"DATA pointer<>+0(SB)/8,$literal<>+8(SB)\n" +
					"GLOBL pointer<>(SB),8,$8\n" +
					"TEXT ·Value(SB),4,$160-16\n" +
					"MOVQ a+0(FP),AX\nMOVQ AX,16(SP)\n"
				if used {
					assembly += "MOVQ literal<>+8(SB),CX\n"
				}
				assembly += "MOVQ 16(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				env := append(append([]string(nil), request.Environment...),
					"GOOS="+strings.Split(target, "/")[0], "GOARCH=amd64", "CGO_ENABLED=0",
					"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
				listing, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
					"tool", "asm", "-S", "-p", pkg.Path, "-o", filepath.Join(t.TempDir(), "original.o"), request.AssemblyFile)
				if err != nil {
					t.Fatalf("independent original Go mixed TEXT/DATA control: %v\n%s", err, listing)
				}
				t.Logf("original Go listing:\n%s", listing)
				source := requireGoAMD64FrameCapture(t, pkg, request)
				if len(source.functions) != 1 || source.functions[pkg.Path+".Value"].locals != 168 {
					t.Fatal("mixed DATA lost the original complete frame inventory")
				}
				if err := source.Verify(ctx); err != nil {
					t.Fatal(err)
				}
				goAMD64FrameMixedDataJoinGuards(t, pkg, source, used)
				changed := strings.Replace(assembly, "0x102030405060708", "0x102030405060709", 1)
				path := filepath.Join(request.Directory, request.AssemblyFile)
				if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
					t.Fatal(err)
				}
				if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed original DATA retained the frame observation", err)
				}
				if err := os.WriteFile(path, []byte(assembly), 0600); err != nil {
					t.Fatal(err)
				}
				if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("restored DATA revived a revoked frame observation", err)
				}
			})
		}
	}
}

func goAMD64FrameMixedDataJoinGuards(t *testing.T, pkg GoPackage, source *GoAMD64FrameSource, used bool) {
	t.Helper()
	objectPath := filepath.Join(source.owned, source.request.AssemblyFile+".o")
	object, err := source.read(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := source.read(objectPath + ".listing")
	if err != nil {
		t.Fatal(err)
	}
	original, err := source.read(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := source.preprocess(source.request.AssemblyFile, original)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := source.frameDataObject(expanded, object)
	if err != nil {
		t.Fatal(err)
	}
	var unwind *gostaticstorage.WindowsAMD64AssemblyUnwind
	if source.request.Target == "windows/amd64" {
		value, err := source.observeWindowsUnwind(object)
		if err != nil {
			t.Fatal(err)
		}
		unwind = &value
	}
	check := func(input []byte) error {
		filtered, err := goAMD64FrameDataListing(input, observed)
		if err != nil {
			return err
		}
		functions, err := goAMD64FrameListingWithDataObject(filtered, file, pkg, source.origins, observed, unwind,
			source.request.Target, source.request.Directory, "")
		if err != nil {
			return err
		}
		return goAMD64FrameDataTextJoin(functions, observed, source.request.Directory, source.origins, "")
	}
	if err := check(listing); err != nil {
		t.Fatal("complete unmodified source/object/listing control", err)
	}
	changes := map[string][2]string{
		"DATA kind":       {"literal SRODATA", "literal SDATA"},
		"DATA static":     {"literal SRODATA static", "literal SRODATA"},
		"DATA dupok":      {"literal SRODATA static", "literal SRODATA static dupok"},
		"DATA size":       {"size=32 align=0x0", "size=33 align=0x0"},
		"DATA alignment":  {"size=32 align=0x0", "size=32 align=0x8"},
		"DATA byte":       {"08 07 06 05", "09 07 06 05"},
		"DATA ASCII":      {"abcd\n", "abce\n"},
		"DATA offset":     {"0x0010 61 62 63 64", "0x0011 61 62 63 64"},
		"DATA relocation": {"R_ADDR literal+8", "R_ADDR literal+16"},
		"DATA target":     {"R_ADDR literal+8", "R_ADDR mutable+8"},
		"DATA BSS extent": {"zero SNOPTRBSS static size=24", "zero SNOPTRBSS static size=25"},
		"TEXT bytes":      {"55 48 89 e5", "90 48 89 e5"},
	}
	if used {
		changes["TEXT relocation"] = [2]string{"R_PCREL literal+8", "R_PCREL literal+16"}
		changes["TEXT target"] = [2]string{"R_PCREL literal+8", "R_PCREL mutable+8"}
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Replace(listing, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(changed, listing) {
				t.Fatal("listing mutation did not touch the independent Go control")
			}
			if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed complete listing acquired an observation", err)
			}
		})
	}
	for _, suffix := range []string{"UNKNOWN_NATIVE_RECORD\n", "\trel 0+8 t=R_ADDR literal+8\n", "zero SNOPTRBSS static size=24 align=0x0\n"} {
		if err := check(append(bytes.Clone(listing), suffix...)); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("extra DATA/listing record was ignored", err)
		}
	}
	if used {
		relocation := observed.Member.Texts[0].Relocations[0]
		for _, mutate := range []func(*gostaticstorage.TextRelocation){
			func(r *gostaticstorage.TextRelocation) { r.Type = 1 },
			func(r *gostaticstorage.TextRelocation) { r.Size = 8 },
			func(r *gostaticstorage.TextRelocation) { r.Target.ABIKnown = false },
			func(r *gostaticstorage.TextRelocation) { r.Target.ABI = 1 },
			func(r *gostaticstorage.TextRelocation) { r.Target.PackageIndex = 2147483647 },
			func(r *gostaticstorage.TextRelocation) { r.Target.SymbolIndex++ },
		} {
			changed := relocation
			mutate(&changed)
			if changed == relocation || goAMD64FrameDataRelocationLine(changed, observed) != "" {
				t.Fatal("DATA relocation lost exact object-local identity", changed)
			}
		}
	}
}
