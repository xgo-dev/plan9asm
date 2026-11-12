//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// Reuse the existing complete live SDK producer. No extra assembly reference,
// declaration, compiler flag or synthetic wrapper is added to the SDK. This is
// an inventory, not a carrier-placement proof or successful file translation.
func amd64SDKArgumentWrapperInventory(t *testing.T, member string) {
	t.Helper()
	ctx, request, metadata, _ := numericalSDKAssemblyFixture(t)
	request.AssemblyFile = member
	before, err := os.ReadFile(filepath.Join(request.Directory, member))
	if err != nil {
		t.Fatal(err)
	}
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("complete original compiler/source/CPU observation", err)
	}
	defer closeNumericalConsumerSource(t, source)
	pkg, file, options := numericalSDKOriginalTypedPackage(t, metadata, member)
	if len(file.Funcs) != 3 || len(file.Data) != 0 || len(file.Globl) != 0 {
		t.Fatal("original complete assembly member changed; no TEXT may be cropped")
	}
	if metadata.observation.Objects == nil || len(metadata.observation.Objects.Members) < 2 ||
		len(metadata.observation.Objects.Sources) != len(metadata.guard.selection.SFiles) ||
		len(metadata.guard.selection.SFiles) == 0 || len(source.native.ArchiveMembers) != len(metadata.observation.Objects.Members) ||
		!reflect.DeepEqual(source.native.ArchiveMembers[1].Texts, metadata.observation.Objects.Members[1].Texts) {
		t.Fatal("inventory lacks the complete selected package assembly/compiler archive")
	}
	sizes := types.SizesFor("gc", "amd64")
	options.Sigs, err = goSigsForAsmFile(pkg, file, options.ResolveSym, "amd64", sizes, sizes, nil)
	if err != nil {
		t.Fatal("actual complete declaration signatures", err)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil || bound.NumericalReads == nil {
		t.Fatal("original declaration/compiler/native association", err)
	}
	names, err := numericalGoDeclarationLinknames(pkg.Syntax, pkg.Types)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := numericalTypedSourceDeclarations(file, pkg.Path, "amd64", source.role, names, source.native.CompilerAliases)
	if err != nil || len(entries) != len(options.Sigs) {
		t.Fatal("actual bodyless entry inventory differs from original source", err)
	}
	generated, err := gostaticstorage.ObserveX86SDKCompilerText(metadata.observation.Header.CompilerObject,
		metadata.observation.ObjectInputs.BuiltinSource, request.Target, metadata.observation.ObjectInputs.Referenced)
	if err != nil {
		t.Fatal("existing complete header compiler object", err)
	}
	selected := metadata.observation.Objects.Members[1].Texts
	var ordered []string
	for native := range entries {
		ordered = append(ordered, native)
	}
	sort.Strings(ordered)
	present := 0
	var absent []string
	for _, native := range ordered {
		entry := entries[native]
		declaration, valid := pkg.Types.Scope().Lookup(entry.local).(*types.Func)
		if !valid {
			t.Fatal("inventory entry lacks its original typed declaration", native)
		}
		plan, err := planAMD64GoArguments(declaration.Type().(*types.Signature))
		if err != nil || plan.requireRegisters() != nil {
			t.Fatal("original argument shape exceeds this private register-only model", native, err)
		}
		wrapper, found, err := amd64ArgumentWrapperInventory(generated, selected, native)
		if err != nil {
			t.Fatal("actual generated/selected wrapper inventory differs", native, err)
		}
		if !found {
			absent = append(absent, native)
			t.Logf("native=%q local=%q parameters=%d GP=%d FP=%d wrapper=ABSENT; no carrier evidence", native, entry.local, len(plan.Arguments), plan.GPUsed, plan.FPUsed)
			continue
		}
		present++
		t.Logf("native=%q local=%q parameters=%d GP=%d FP=%d wrapperABI=%d namespace=%d flags=%d/%d bytes=%x relocations=%+v; placement UNPROVED",
			native, entry.local, len(plan.Arguments), plan.GPUsed, plan.FPUsed, wrapper.ABI, wrapper.Namespace, wrapper.Flags, wrapper.Flags2, wrapper.Code, wrapper.Relocations)
	}
	if present+len(absent) != len(entries) {
		t.Fatal("wrapper inventory omitted an original declared entry")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete original numerical source final verification", err)
	}
	if err := metadata.Verify(ctx); err != nil {
		t.Fatal("borrowed complete SDK source/header/archive final verification", err)
	}
	after, err := os.ReadFile(filepath.Join(request.Directory, member))
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("inventory changed the unchanged original assembly", err)
	}
	t.Logf("inventory-only member=%s originalTEXTs=%d selectedASM=%d entries=%d wrapperCandidates=%d explicitlyAbsent=%v; no translation or entry permission",
		member, len(file.Funcs), len(metadata.guard.selection.SFiles), len(entries), present, absent)
}

func TestGoX86SDKAMD64CompareArgumentWrapperInventory(t *testing.T) {
	amd64SDKArgumentWrapperInventory(t, "compare_amd64.s")
}

func TestGoX86SDKAMD64EqualArgumentWrapperInventory(t *testing.T) {
	amd64SDKArgumentWrapperInventory(t, "equal_amd64.s")
}
