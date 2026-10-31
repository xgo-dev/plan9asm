// Source-only TLS observations, separate from translator/runtime permissions.
package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type x86TLSFallbackSourceObservation struct {
	ID, Instruction, Origin, Target, SDKVersion string
	SourceSHA, ObjectSHA, ListingSHA            string
	SDKSourceSHA                                map[string]string
	Shared                                      bool
	Encoding                                    []byte
	Relocations                                 []string
	sourceBytes, objectBytes, listingBytes      []byte
}

func x86TLSFallbackOriginalID(t *testing.T, catalog goasmrules.X86LegacyCatalog, opcode string) string {
	t.Helper()
	if len(catalog.Movtab) != 113 {
		t.Fatal("complete original move table changed")
	}
	var result string
	for _, row := range catalog.Movtab {
		if row.Code != "movTLSReg" || row.Opcode != opcode {
			continue
		}
		if result != "" || row.Kind != "encoding" || row.From != "Ytls" || row.From3 != "Ynone" ||
			row.To != "Yrl" || strings.TrimPrefix(row.OpcodeExpression, "obj.") != "A"+opcode || len(row.OpBytes) > 4 {
			t.Fatal("complete original TLS fallback row identity changed", row)
		}
		// Implicit zero cells are equivalent to the four explicit zero cells.
		for _, atom := range row.OpBytes {
			value, err := strconv.ParseUint(atom, 0, 8)
			if err != nil || value != 0 {
				t.Fatal("TLS fallback acquired an opaque nonzero payload", row)
			}
		}
		result = fmt.Sprintf("ymovtab/%d/%s/movTLSReg", row.TableIndex, row.Opcode)
	}
	if result == "" {
		t.Fatal("original TLS fallback source row missing", opcode)
	}
	return result
}

func x86TLSFallbackRelocationLines(t *testing.T, listing string) []string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/objabi/reloctype_string.go"))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, name := range []string{"R_CALL", "R_TLS_IE"} {
		matches := regexp.MustCompile(`(?m)^[\t ]*_ = x\[`+name+`-([0-9]+)\][\t ]*$`).FindAllStringSubmatch(string(source), -1)
		if len(matches) != 1 {
			t.Fatal("selected SDK lacks one exact TLS relocation enum", name)
		}
		kinds[matches[0][1]] = name
	}
	var result []string
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "rel" {
			continue
		}
		if len(fields) != 4 || !strings.HasPrefix(fields[2], "t=") {
			t.Fatal("incomplete actual TLS relocation", line)
		}
		if name := kinds[strings.TrimPrefix(fields[2], "t=")]; name != "" {
			fields[2] = "t=" + name
		}
		result = append(result, strings.Join(fields, " "))
	}
	return result
}

func x86TLSFallbackDirectNOP(t *testing.T, listing string) {
	t.Helper()
	headers := x86TLSListingTextHeaders([]byte(listing))
	if len(headers) != 1 || !strings.Contains(headers[0], " size=1 ") {
		t.Fatal("direct TLS rewrite lost its complete one-byte RET object", headers)
	}
	var code []byte
	nops, returns := 0, 0
	inside := false
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "0x") && strings.HasPrefix(fields[1], "S") {
			inside = fields[1] == "STEXT"
		}
		if !inside {
			continue
		}
		code = append(code, x86InsertExtractListedBytes(line)...)
		if match := x86OfficialPackedListingInstruction.FindStringSubmatch(line); match != nil &&
			match[1] == "0000" && match[2] == "00000" {
			if match[3] == "2" && match[4] == "NOP" {
				nops++
			} else if match[3] == "3" && match[4] == "RET" {
				returns++
			}
		}
	}
	if !bytes.Equal(code, []byte{0xc3}) || nops != 1 || returns != 1 {
		t.Fatal("direct TLS NOP must retain its own zero-width source row, not fallback bytes", code, nops, returns)
	}
}

func x86TLSFallbackActualProfile(t *testing.T, arch string, shared bool) x86TLSFallbackSourceObservation {
	t.Helper()
	opcode := "MOVQ"
	if arch == "386" {
		opcode = "MOVL"
	}
	instruction := opcode + " TLS,CX"
	source := "TEXT ·TLSProfile(SB),516,$0-0\n" + instruction + "\nRET\n"
	listing, object, _ := x86ScalarLiteralGoProfileObject(t, arch, "linux", source, shared, true)
	end := bytes.IndexByte(object, '\n')
	if end < 0 {
		t.Fatal("actual Go object lacks a complete header")
	}
	header := strings.Fields(string(object[:end]))
	if len(header) < 5 || header[0] != "go" || header[1] != "object" || header[2] != "linux" ||
		header[3] != arch || header[4] != runtime.Version() {
		t.Fatal("actual original object target/SDK provenance changed", header)
	}
	observation := x86TLSFallbackSourceObservation{Instruction: instruction, Target: "linux/" + arch,
		SDKVersion: header[4], Shared: shared, SourceSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(source))),
		ObjectSHA: fmt.Sprintf("%x", sha256.Sum256(object)), ListingSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(listing))),
		SDKSourceSHA: map[string]string{}, Relocations: x86TLSFallbackRelocationLines(t, listing),
		sourceBytes: []byte(source), objectBytes: append([]byte(nil), object...), listingBytes: []byte(listing)}
	if artifacts := os.Getenv("PLAN9ASM_TLS_FALLBACK_ARTIFACT_DIR"); artifacts != "" {
		owner := filepath.Join(artifacts, strings.ReplaceAll(t.Name(), "/", "_"))
		if err := os.MkdirAll(owner, 0700); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(owner, fmt.Sprintf("%s-shared-%v", arch, shared))
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal("actual profile evidence must never overwrite an earlier observation", err)
		}
		for name, data := range map[string][]byte{"source.s": []byte(source), "original.o": object, "listing.txt": []byte(listing)} {
			if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"cmd/internal/obj/x86/asm6.go", "cmd/internal/obj/x86/obj6.go", "cmd/internal/objabi/reloctype_string.go"} {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", name))
		if err != nil {
			t.Fatal(err)
		}
		observation.SDKSourceSHA[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	var expectedRelocations []string
	switch {
	case arch == "386" && !shared:
		observation.Origin = "stock-asm/movTLSReg"
		observation.Encoding = []byte{0x65, 0x8b, 0x0d, 0, 0, 0, 0}
	case arch == "amd64" && shared:
		observation.Origin = "stock-asm/movTLSReg"
		observation.Encoding = []byte{0x48, 0x8b, 0x0d, 0, 0, 0, 0}
		expectedRelocations = []string{"rel 3+4 t=R_TLS_IE +-4"}
	case arch == "386" && shared:
		observation.Origin = "stock-asm/movTLSReg/shared386-control"
		observation.Encoding = []byte{0xe8, 0, 0, 0, 0, 0x8b, 0x89, 0, 0, 0, 0}
		expectedRelocations = []string{"rel 1+4 t=R_CALL __x86.get_pc_thunk.cx+0", "rel 7+4 t=R_TLS_IE +2"}
	case arch == "amd64" && !shared:
		observation.Origin = "stock-asm/progedit-direct-NOP-control"
		x86TLSFallbackDirectNOP(t, listing)
	default:
		t.Fatal("unmodeled source profile", arch, shared)
	}
	if !reflect.DeepEqual(observation.Relocations, expectedRelocations) {
		t.Fatal("actual TLS byte/relocation/profile mismatch", observation, expectedRelocations)
	}
	if observation.Origin != "stock-asm/progedit-direct-NOP-control" {
		fixture := x86OfficialPackedCase{row: "actualTLSProfile", symbol: "TLSProfile", line: 2,
			witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Destination: "CX", Encoding: observation.Encoding}}
		if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{fixture}); err != nil {
			t.Fatal("actual complete TLS source bytes/PC differ", err)
		}
	}
	if observation.Origin == "stock-asm/movTLSReg" {
		catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
		if err != nil {
			t.Fatal(err)
		}
		observation.ID = x86TLSFallbackOriginalID(t, catalog, opcode)
	}
	t.Logf("ACTUAL_TLS_SOURCE_PROFILE id=%s origin=%s target=%s shared=%t SDK=%s sourceSHA=%s objectSHA=%s listingSHA=%s bytes=%x relocations=%q",
		observation.ID, observation.Origin, observation.Target, observation.Shared, observation.SDKVersion,
		observation.SourceSHA, observation.ObjectSHA, observation.ListingSHA, observation.Encoding, observation.Relocations)
	return observation
}

func x86TLSFallbackValidateJoin(observation x86TLSFallbackSourceObservation, expectedID string) error {
	if observation.ID == "" || observation.ID != expectedID || observation.Origin != "stock-asm/movTLSReg" ||
		observation.SDKVersion != runtime.Version() || len(observation.SourceSHA) != 64 || len(observation.ObjectSHA) != 64 ||
		len(observation.ListingSHA) != 64 || len(observation.SDKSourceSHA) != 3 {
		return fmt.Errorf("incomplete actual TLS source/profile provenance")
	}
	for _, receipt := range []struct {
		data []byte
		hash string
	}{
		{observation.sourceBytes, observation.SourceSHA},
		{observation.objectBytes, observation.ObjectSHA},
		{observation.listingBytes, observation.ListingSHA},
	} {
		if len(receipt.data) == 0 || fmt.Sprintf("%x", sha256.Sum256(receipt.data)) != receipt.hash {
			return fmt.Errorf("TLS source receipt digest no longer matches its actual captured bytes")
		}
	}
	expectedSource := "TEXT ·TLSProfile(SB),516,$0-0\n" + observation.Instruction + "\nRET\n"
	if string(observation.sourceBytes) != expectedSource {
		return fmt.Errorf("TLS source receipt no longer matches the observed instruction")
	}
	end := bytes.IndexByte(observation.objectBytes, '\n')
	if end < 0 {
		return fmt.Errorf("TLS source receipt lacks an actual object header")
	}
	header := strings.Fields(string(observation.objectBytes[:end]))
	if len(header) < 5 || header[0] != "go" || header[1] != "object" ||
		header[2]+"/"+header[3] != observation.Target || header[4] != observation.SDKVersion {
		return fmt.Errorf("TLS source receipt no longer matches the selected target and SDK")
	}
	id := strings.Split(expectedID, "/")
	instruction := strings.Fields(observation.Instruction)
	if len(id) != 4 || len(instruction) != 2 || id[0] != "ymovtab" || id[2] != instruction[0] || id[3] != "movTLSReg" {
		return fmt.Errorf("TLS source identity no longer matches its observed instruction width")
	}
	for _, name := range []string{"cmd/internal/obj/x86/asm6.go", "cmd/internal/obj/x86/obj6.go", "cmd/internal/objabi/reloctype_string.go"} {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", name))
		if err != nil || observation.SDKSourceSHA[name] != fmt.Sprintf("%x", sha256.Sum256(data)) {
			return fmt.Errorf("actual TLS profile is no longer bound to the selected SDK source: %s", name)
		}
	}
	var code []byte
	var relocations []string
	switch {
	case observation.Target == "linux/386" && !observation.Shared && observation.Instruction == "MOVL TLS,CX":
		code = []byte{0x65, 0x8b, 0x0d, 0, 0, 0, 0}
	case observation.Target == "linux/amd64" && observation.Shared && observation.Instruction == "MOVQ TLS,CX":
		code = []byte{0x48, 0x8b, 0x0d, 0, 0, 0, 0}
		relocations = []string{"rel 3+4 t=R_TLS_IE +-4"}
	default:
		return fmt.Errorf("a NOP, shared386 control or unrelated source profile cannot join a new fallback ID")
	}
	if !bytes.Equal(code, observation.Encoding) || !reflect.DeepEqual(relocations, observation.Relocations) {
		return fmt.Errorf("TLS metadata lacks its exact actual byte/relocation counterpart")
	}
	return nil
}

func TestX86TLSFallbackActualObjectProfiles(t *testing.T) {
	for _, profile := range []struct {
		arch   string
		shared bool
	}{
		{"386", false}, {"amd64", true}, {"amd64", false}, {"386", true},
	} {
		t.Run(fmt.Sprintf("linux/%s/shared=%v", profile.arch, profile.shared), func(t *testing.T) {
			observed := x86TLSFallbackActualProfile(t, profile.arch, profile.shared)
			wantID := profile.arch == "386" && !profile.shared || profile.arch == "amd64" && profile.shared
			if (observed.ID != "") != wantID {
				t.Fatal("control profile was counted as a new fallback identity", observed)
			}
		})
	}
}

// Add only the independently validated contextual source observations.
// The production source grammar still excludes unbound TLS and grants no
// runtime, numerical or native authority.
func x86TLSFallbackSourceUnion(t *testing.T, catalog goasmrules.X86LegacyCatalog, observed []x86TLSFallbackSourceObservation) map[string]bool {
	t.Helper()
	result := map[string]bool{}
	for id := range movtabCompleteSourceJoin(t, catalog, "amd64") {
		result[id] = true
	}
	if len(observed) != 2 {
		t.Fatal("expected exactly two independently observed TLS fallback identities", len(observed))
	}
	for _, observation := range observed {
		opcode := strings.Fields(observation.Instruction)[0]
		id := x86TLSFallbackOriginalID(t, catalog, opcode)
		if err := x86TLSFallbackValidateJoin(observation, id); err != nil {
			t.Fatal(err)
		}
		if result[id] {
			t.Fatal("duplicate contextual TLS source identity", id)
		}
		result[id] = true
	}
	return result
}

func TestX86TLSFallbackCompleteSourceIDJoin(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	observations := []x86TLSFallbackSourceObservation{
		x86TLSFallbackActualProfile(t, "386", false), x86TLSFallbackActualProfile(t, "amd64", true),
	}
	joined := x86TLSFallbackSourceUnion(t, catalog, observations)
	for _, observation := range observations {
		t.Run(observation.ID, func(t *testing.T) {
			opcode := strings.Fields(observation.Instruction)[0]
			if err := x86TLSFallbackValidateJoin(observation, x86TLSFallbackOriginalID(t, catalog, opcode)); err != nil {
				t.Fatal(err)
			}
			if !joined[observation.ID] {
				t.Fatal("TLS_FALLBACK_SOURCE_ID_FEATURE_GAP", observation.ID)
			}
		})
	}
	if !t.Failed() {
		if len(joined) != 112 {
			t.Fatal("complete source union including actual contextual TLS observations changed", len(joined))
		}
		x86Legacy127SaveIdentity(t, "PLAN9ASM_TLS_FALLBACK_SOURCE_OUTPUT", struct {
			Source   goasmrules.X86LegacyCatalog
			Observed []x86TLSFallbackSourceObservation
		}{catalog, observations})
	}
}

func TestX86TLSFallbackSourceProfileCounterfeits(t *testing.T) {
	original := x86TLSFallbackActualProfile(t, "amd64", true)
	if err := x86TLSFallbackValidateJoin(original, original.ID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*x86TLSFallbackSourceObservation){
		"lost-shared-profile":     func(o *x86TLSFallbackSourceObservation) { o.Shared = false },
		"wrong-OS":                func(o *x86TLSFallbackSourceObservation) { o.Target = "darwin/amd64" },
		"wrong-width":             func(o *x86TLSFallbackSourceObservation) { o.Instruction = "MOVL TLS,CX" },
		"direct-NOP-origin":       func(o *x86TLSFallbackSourceObservation) { o.Origin = "stock-asm/progedit-direct-NOP-control" },
		"missing-relocation":      func(o *x86TLSFallbackSourceObservation) { o.Relocations = nil },
		"wrong-relocation-kind":   func(o *x86TLSFallbackSourceObservation) { o.Relocations = []string{"rel 3+4 t=R_PCREL +-4"} },
		"wrong-relocation-addend": func(o *x86TLSFallbackSourceObservation) { o.Relocations = []string{"rel 3+4 t=R_TLS_IE +-3"} },
		"wrong-relocation-PC":     func(o *x86TLSFallbackSourceObservation) { o.Relocations = []string{"rel 2+4 t=R_TLS_IE +-4"} },
		"missing-object":          func(o *x86TLSFallbackSourceObservation) { o.ObjectSHA = "" },
		"foreign-source-hash":     func(o *x86TLSFallbackSourceObservation) { o.SourceSHA = strings.Repeat("0", 64) },
		"foreign-object-hash":     func(o *x86TLSFallbackSourceObservation) { o.ObjectSHA = strings.Repeat("0", 64) },
		"foreign-listing-hash":    func(o *x86TLSFallbackSourceObservation) { o.ListingSHA = strings.Repeat("0", 64) },
		"changed-source-bytes":    func(o *x86TLSFallbackSourceObservation) { o.sourceBytes[0] ^= 1 },
		"changed-object-bytes":    func(o *x86TLSFallbackSourceObservation) { o.objectBytes[0] ^= 1 },
		"changed-listing-bytes":   func(o *x86TLSFallbackSourceObservation) { o.listingBytes[0] ^= 1 },
		"wrong-SDK":               func(o *x86TLSFallbackSourceObservation) { o.SDKVersion = "go0.0" },
		"wrong-SDK-source": func(o *x86TLSFallbackSourceObservation) {
			o.SDKSourceSHA = map[string]string{"foreign": "", "other": "", "third": ""}
		},
		"zero-width-bytes": func(o *x86TLSFallbackSourceObservation) { o.Encoding = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			changed.sourceBytes = append([]byte(nil), original.sourceBytes...)
			changed.objectBytes = append([]byte(nil), original.objectBytes...)
			changed.listingBytes = append([]byte(nil), original.listingBytes...)
			mutate(&changed)
			if err := x86TLSFallbackValidateJoin(changed, original.ID); err == nil {
				t.Fatal("metadata/control evidence was counted as a passing source join", name)
			}
		})
	}
	if err := x86TLSFallbackValidateJoin(original, original.ID); err != nil {
		t.Fatal("counterfeits must not modify the valid actual observation", err)
	}
}

func TestX86TLSFallbackSourceCannotRetagObservedWidth(t *testing.T) {
	observed := x86TLSFallbackActualProfile(t, "amd64", true)
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	foreign := x86TLSFallbackOriginalID(t, catalog, "MOVL")
	observed.ID = foreign
	if err := x86TLSFallbackValidateJoin(observed, foreign); err == nil {
		t.Fatal("actual MOVQ source observation was retagged as the MOVL fallback row")
	}
}

func TestX86TLSFallbackObservedSourceDoesNotGrantRuntime(t *testing.T) {
	for _, source := range []struct{ instruction, arch string }{{"MOVL TLS,CX", "386"}, {"MOVQ TLS,CX", "amd64"}} {
		instruction := x86PureGPUnknownInstruction(t, source.instruction)
		if err := x86SourceTLSMoveError(instruction, source.arch); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("source proof must not grant TLS/runtime/NUM authority", source, err)
		}
	}
}
