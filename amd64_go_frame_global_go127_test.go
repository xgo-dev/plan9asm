//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

const fixedLocalGlobalAssembly = `TEXT ·Value(SB),4,$32-16
	MOVQ a+0(FP),AX
	MOVQ AX,0(SP)
	MOVQ $·Table(SB),SI
	MOVQ SI,8(SP)
	MOVQ 8(SP),DX
	MOVOU (DX),X0
	ADDQ $16,DX
	MOVOU (DX),X1
	PADDQ X1,X0
	MOVQ X0,CX
	MOVQ 0(SP),AX
	ADDQ CX,AX
	MOVQ AX,ret+8(FP)
	RET
`

const fixedLocalGlobalDeclarations = "var Table [4]uint64\nfunc Value(a uint64) uint64\n"

func TestGoAMD64FrameOrdinaryRelocationWithoutData(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			pkg, request := goAMD64FrameTypedFixture(t, fixedLocalGlobalDeclarations, fixedLocalGlobalAssembly)
			request.Target = target
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			object, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o"))
			if err != nil {
				t.Fatal(err)
			}
			listing, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
			if err != nil {
				t.Fatal(err)
			}
			expanded, err := source.preprocess(request.AssemblyFile, []byte(fixedLocalGlobalAssembly))
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := source.frameDataObject(expanded, object)
			if err != nil || len(observed.Layouts) != 0 || len(observed.Member.Texts) != 1 || len(observed.Member.Texts[0].Relocations) != 1 {
				t.Fatal("ordinary reference changed the complete no-DATA inventory", err)
			}
			var unwind *gostaticstorage.WindowsAMD64AssemblyUnwind
			if target == "windows/amd64" {
				value, err := source.observeWindowsUnwind(object)
				if err != nil {
					t.Fatal(err)
				}
				unwind = &value
			}
			check := func(input []byte) error {
				functions, err := goAMD64FrameListingWithDataObject(input, file, pkg, source.origins, observed, unwind, target, request.Directory, "")
				if err != nil {
					return err
				}
				return goAMD64FrameDataTextJoin(functions, observed, request.Directory, source.origins, "")
			}
			if err := check(listing); err != nil {
				t.Fatal("complete unmodified original source/object/listing", err)
			}
			for name, replacement := range map[string]string{
				"target": "foreign.Table+0", "addend": pkg.Path + ".Table+1", "missing zero": pkg.Path + ".Table",
			} {
				t.Run(name, func(t *testing.T) {
					changed := bytes.Replace(listing, []byte(pkg.Path+".Table+0"), []byte(replacement), 1)
					if bytes.Equal(changed, listing) || !errors.Is(check(changed), ErrProbeNeedsContext) {
						t.Fatal("changed ordinary relocation retained the complete original observation")
					}
				})
			}
			relocation := []byte("\t" + goAMD64FrameDataRelocationLine(observed.Member.Texts[0].Relocations[0], observed) + "\n")
			for name, replacement := range map[string][]byte{"missing": nil, "duplicate": append(append([]byte(nil), relocation...), relocation...)} {
				t.Run(name, func(t *testing.T) {
					changed := bytes.Replace(listing, relocation, replacement, 1)
					if bytes.Equal(changed, listing) || !errors.Is(check(changed), ErrProbeNeedsContext) {
						t.Fatal("incomplete or duplicate relocation inventory accepted")
					}
				})
			}
		})
	}
}
