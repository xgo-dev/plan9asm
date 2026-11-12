package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoX86NumericalReadOriginalSourceABIIdentity(t *testing.T) {
	for _, role := range []numericalSBSourceRole{numericalSBOwnedSource, numericalSBSDKSource} {
		for _, arch := range []string{"386", "amd64"} {
			for _, selector := range []string{"", "<ABI0>", "<ABIInternal>", "<ABI99>", "<>"} {
				name, abi, valid := numericalFunctionSourceIdentity("·entry"+selector, "example.invalid/owner", arch, role)
				want := selector == "" || selector == "<ABI0>" || selector == "<ABIInternal>" && arch == "amd64" && role == numericalSBSDKSource
				if valid != want || valid && name != "example.invalid/owner.entry" || valid && (abi == 1) != (selector == "<ABIInternal>") {
					t.Fatal("source selector changed its genuine owner/mode/native ABI", role, arch, selector, name, abi, valid)
				}
			}
		}
	}
}

func TestGoX86NumericalReadSDKOpaquePointerLanguageIdentity(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		sizes := types.SizesFor("gc", arch)
		unsafePointer := types.Typ[types.UnsafePointer]
		if _, err := goAMD64FrameLanguageType(unsafePointer, sizes); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("opaque SDK declaration identity widened ordinary frame transport", err)
		}
		opaque, err := goAMD64FrameLanguageTypeRole(unsafePointer, sizes, true)
		if err != nil || !strings.Contains(opaque, "opaque_unsafe_pointer") {
			t.Fatal("SDK observer discarded the actual unsafe.Pointer language role", err)
		}
		for _, other := range []types.Type{types.Typ[types.Uintptr], types.NewPointer(types.Typ[types.Uint8]), types.NewPointer(unsafePointer)} {
			identity, err := goAMD64FrameLanguageTypeRole(other, sizes, true)
			if err != nil || identity == opaque {
				t.Fatal("equal-size numerical/pointee types replaced opaque pointer identity", identity, err)
			}
		}
	}
}

func TestGoX86NumericalReadExactEmptyLiteralMember(t *testing.T) {
	joined := &numericalSDKLiteralJoin{SourceOrdinal: 0,
		Observation:  sdkASMDataLiveObservation{Objects: &gostaticstorage.SDKASMDataObservation{Sources: []gostaticstorage.ASMDataSourceObservation{{}}}},
		Initializers: sdkReadonlyLiteralDataReport{Initializers: []gostaticstorage.ReadonlyLiteralDataImage{{SourceOrdinal: 1}}},
	}
	file := &File{Arch: ArchAMD64}
	if err := joined.verifyFile(file, "example.invalid/owner"); err != nil {
		t.Fatal("complete empty member borrowed another member's DATA inventory", err)
	}
	for _, source := range []string{
		"GLOBL empty<>(SB),8,$0\n", "DATA local<>+0(SB)/1,$7\n", "GLOBL local<>(SB),8,$1\nDATA local<>+0(SB)/1,$7\n",
	} {
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if err := joined.verifyFile(file, "example.invalid/owner"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unobserved DATA appeared in an empty source member", source, err)
		}
	}
}
