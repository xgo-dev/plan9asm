//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGoStaticStorageARM64AssemblyDefaultTargetRoles(t *testing.T) {
	directory, goBinary, _ := fixture(t)
	oracle := officialReaderForSource(t, goBinary, sdkTextReaderSource)
	consumer := filepath.Join(directory, "armcarrier")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	goSource := "package armcarrier\nfunc callee(input uint64) uint32\n" +
		"func entry(input uint64) uint32 { return callee(input) }\n"
	assembly := "TEXT ·callee(SB),4,$0-12\nMOVD input+0(FP),R0\nMOVD R0,ret+8(FP)\nRET\n"
	for name, data := range map[string]string{"value.go": goSource, "value_arm64.s": assembly} {
		if err := os.WriteFile(filepath.Join(consumer, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goRoot := filepath.Dir(filepath.Dir(goBinary))
	builtins, err := os.ReadFile(filepath.Join(goRoot, "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd", "openbsd"} {
		t.Run(goos, func(t *testing.T) {
			target := goos + "/arm64"
			environment := fixtureEnv(t, target)
			selection := run(t, goBinary, consumer, environment, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
			var selected struct {
				Export string
				SFiles []string
			}
			if err := json.Unmarshal(selection, &selected); err != nil ||
				len(selected.SFiles) != 1 || selected.SFiles[0] != "value_arm64.s" || selected.Export == "" {
				t.Fatal("actual ARM64 member selection differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, consumer, environment, selected.Export)
			var official []TextMember
			if err := json.Unmarshal(raw, &official); err != nil || len(official) != 3 {
				t.Fatal("independent SDK complete ARM64 archive differs", err)
			}
			compilerFlags := uint32(0)
			if goos == "darwin" {
				compilerFlags = 1 // default PIE: SDK work/init.go and platform.DefaultPIE
			}
			if official[1].Flags != compilerFlags || official[2].Flags != compilerFlags|4 {
				t.Fatal("actual default driver member roles differ from pinned SDK")
			}
			observed, err := ObserveARM64AssemblyArchive(archive, builtins, target, selected.SFiles)
			if err != nil || !reflect.DeepEqual(observed, official) {
				t.Fatal("all original ARM64 bytes/positions/flags differ from SDK reader", err)
			}
			// Exact role flags are required, not a union of plausible flags.
			// In particular Darwin's default Shared bit cannot authorize Std,
			// Unlinkable or a mismatched compiler/assembler member role.
			for memberIndex := 1; memberIndex < len(official); memberIndex++ {
				member := official[memberIndex]
				for _, flags := range []uint32{0, 1, 4, 5, 8, 16, 31} {
					if flags == member.Flags {
						continue
					}
					t.Run(fmt.Sprintf("member%d-flags%d", memberIndex, flags), func(t *testing.T) {
						changed := append([]byte(nil), archive...)
						body := changed[member.Offset : member.Offset+member.Size]
						headerEnd := bytes.Index(body, []byte("\n!\n"))
						if headerEnd < 0 || len(body)-headerEnd-3 < 20 {
							t.Fatal("actual member flag position is missing")
						}
						binary.LittleEndian.PutUint32(body[headerEnd+3+16:headerEnd+3+20], flags)
						if _, err := ObserveARM64AssemblyArchive(changed, builtins, target, selected.SFiles); err == nil {
							t.Fatal("offline observation accepted wrong original member role")
						}
					})
				}
			}
			objectPath := filepath.Join(t.TempDir(), "original.o")
			listing := run(t, goBinary, consumer, environment, "tool", "asm", "-S", "-p",
				fixtureModule+"/armcarrier", "-o", objectPath, "value_arm64.s")
			object, err := os.ReadFile(objectPath)
			if err != nil {
				t.Fatal(err)
			}
			standaloneRaw := run(t, oracle, consumer, environment, objectPath)
			var standalone []TextMember
			if err := json.Unmarshal(standaloneRaw, &standalone); err != nil || len(standalone) != 1 || standalone[0].Flags != 4 {
				t.Fatal("actual direct tool asm role differs", err)
			}
			texts, err := ObserveARM64AssemblyText(object, builtins, target)
			if err != nil || !reflect.DeepEqual(texts, standalone[0].Texts) {
				t.Fatal("standalone original ARM64 object differs from SDK reader", err)
			}
			retainTextArtifact(t, target, "arm64-byte-carrier", map[string][]byte{
				"archive-original.a": archive, "archive-sdk.json": raw,
				"object-original.o": object, "object-sdk.json": standaloneRaw,
				"object-listing.txt": listing, "selection.json": selection,
				"source-value.go": []byte(goSource), "source-value.s": []byte(assembly),
			})
		})
	}
}
