package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// Assembly returns the complete parsed CPP of one exact selected member.
// It does not bind Options or certify an initializer, numerical read, frame,
// native entry or caller. The independently supplied live source remains the
// sole owner; returned diagnostic values cannot restore that owner.
func (source *GoX86SDKASMDataSource) Assembly(ctx context.Context, assemblyFile string) (file *File, result error) {
	if source == nil || source.identity != source {
		return nil, sdkASMDataContext("metadata requires its original live source")
	}
	raw, err := source.Readback(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		result = errors.Join(result, source.Verify(ctx))
		if result != nil {
			file = nil
		}
	}()
	var observation sdkASMDataLiveObservation
	if json.Unmarshal(raw, &observation) != nil || !reflect.DeepEqual(observation.Request, source.request) {
		return nil, sdkASMDataContext("metadata readback lost its exact source/tool/profile")
	}
	// The live source's sealed Readback already includes the existing complete
	// object frontend's join and retained input bytes. Do not decode those whole
	// objects again or turn an empty DATA inventory into an initializer owner.
	file, _, err = sdkASMMetadataSelectedMember(observation, assemblyFile)
	return file, err
}

// This is a pure complete-inventory selector, not a live-source constructor.
// The SDK graph consumer can reuse its original member ordinal without
// reordering physical records or relabeling helper instructions as roots.
func sdkASMMetadataSelectedMember(observation sdkASMDataLiveObservation, assemblyFile string) (*File, int, error) {
	fail := func(message string) (*File, int, error) {
		return nil, -1, sdkASMDataContext("metadata %s", message)
	}
	if assemblyFile == "" || filepath.Base(assemblyFile) != assemblyFile || !strings.HasSuffix(assemblyFile, ".s") {
		return fail("requires an exact package-local selected assembly name")
	}
	objects, inputs := observation.Objects, observation.ObjectInputs
	if observation.Protocol != "actual_go_sdk_asm_data_live_observation_v1" || objects == nil ||
		objects.Protocol != gostaticstorage.ASMDataCPPProtocol || !gostaticstorage.X86SDKTarget(observation.Request.Target) ||
		objects.PackagePath != observation.Request.PackagePath || objects.Target != observation.Request.Target ||
		inputs.PackagePath != objects.PackagePath || inputs.Target != objects.Target {
		return fail("lost its independent complete CPP/source role")
	}
	var selected goAMD64FrameSelection
	if json.Unmarshal(observation.RawSelection, &selected) != nil || !selected.Standard || selected.Module != nil ||
		selected.ImportPath != objects.PackagePath || selected.nonordinaryRole() ||
		len(selected.Error)+len(selected.DepsErrors) != 0 {
		return fail("differs from its actual ordinary SDK selection")
	}
	count := len(selected.SFiles)
	if count == 0 || count > gostaticstorage.ArchiveMemberInventoryLimit-2 || len(objects.Sources) != count || len(observation.CPP) != count ||
		len(observation.Positions) != count || len(inputs.Sources) != count || len(objects.Members) != count+2 {
		return fail("omits or adds a complete selected source/member/CPP/position inventory")
	}
	digest := func(data []byte) string {
		value := sha256.Sum256(data)
		return hex.EncodeToString(value[:])
	}
	if objects.ArchiveSHA256 != digest(inputs.Archive) {
		return fail("changed its complete compiler archive bytes")
	}
	ordinal := -1
	names := make(map[string]bool, count)
	for index, name := range selected.SFiles {
		observed, input, cpp := objects.Sources[index], inputs.Sources[index], observation.CPP[index]
		member := objects.Members[index+2]
		if filepath.Base(name) != name || !strings.HasSuffix(name, ".s") || names[name] ||
			observed.Name != name || input.Name != name || member.Ordinal != index+2 ||
			member.Name == "" || !bytes.Equal(member.NameBytes, []byte(member.Name)) ||
			member.Flags != observed.Original.Flags || !reflect.DeepEqual(member.Texts, observed.Original.Texts) ||
			!reflect.DeepEqual(observed.Original.Texts, observed.Expanded.Texts) {
			return fail("changed a source/compiler ordinal or complete native TEXT tuple")
		}
		names[name] = true
		if observed.OriginalSHA256 != digest(input.Original) || observed.ExpandedSHA256 != digest(input.Expanded) ||
			observed.OriginalObjectSHA256 != digest(input.OriginalObject) || observed.ExpandedObjectSHA256 != digest(input.ExpandedObject) ||
			cpp.Output != string(input.Expanded) {
			return fail("changed whole original/CPP/object input bytes")
		}
		// The common association grammar admits complete comments-only members;
		// unlike a numerical native consumer, metadata requires no nonempty body.
		grammar := []byte(cpp.Output)
		if len(grammar) == 0 {
			// Match the existing CPP observer's zero-statement lexer view,
			// without changing any retained or returned source bytes.
			grammar = []byte("\n")
		}
		order, err := gostaticstorage.ASMSourceTextOrder(grammar, objects.PackagePath, observed.Original)
		if err != nil || !reflect.DeepEqual(order, observed.TextOrder) {
			return fail("changed its complete original source/physical TEXT association")
		}
		replayed, err := gostaticstorage.ASMSourceTextOrder(grammar, objects.PackagePath, observed.Expanded)
		if err != nil || !reflect.DeepEqual(order, replayed) {
			return fail("changed its complete expanded source/physical TEXT association")
		}
		if name == assemblyFile {
			ordinal = index
		}
	}
	if ordinal < 0 {
		return fail("does not contain that exact selected member")
	}
	if observation.CPP[ordinal].Output == "" {
		// A real comments-only member may have zero expanded statements. This
		// is its complete empty file, not a replacement for an unsupported body.
		return &File{Arch: ArchAMD64}, ordinal, nil
	}
	file, err := Parse(ArchAMD64, observation.CPP[ordinal].Output)
	if err != nil {
		return fail("selected complete CPP cannot be parsed: " + err.Error())
	}
	return file, ordinal, nil
}
