//go:build go1.23

package plan9asm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64WindowsUnwindCompleteObjectListingJoinGuards(t *testing.T) {
	goAMD64WindowsUnwindCompleteObjectListingJoinGuards(t)
}

func TestGoAMD64WindowsUnwindCompleteJoinTemporaryParentAlias(t *testing.T) {
	goAMD64WindowsUnwindTemporaryParentAlias(t)
	// A new child owns a fresh testing.TempDir root under the explicit alias.
	// The parent's root was already created while constructing that alias.
	t.Run("AliasedTemporaryParent", goAMD64WindowsUnwindCompleteObjectListingJoinGuards)
}

func goAMD64WindowsUnwindCompleteObjectListingJoinGuards(t *testing.T) {
	t.Helper()
	pkg, request := goAMD64FrameSourceFixture(t)
	request.Target = "windows/amd64"
	source := requireGoAMD64FrameCapture(t, pkg, request)
	t.Logf("ACTUAL_WINDOWS_SOURCE_CAPTURE request=%q observed=%q functions=%d",
		request.Directory, source.request.Directory, len(source.functions))
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	object, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o"))
	if err != nil {
		t.Fatal(err)
	}
	listing, err := source.read(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := source.read(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := source.preprocess(request.AssemblyFile, original)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := source.observeWindowsUnwind(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"go1.27.1", "go1.27.2", "go1.99.1"} {
		if version == observed.Version {
			continue
		}
		changed := bytes.Replace(object, []byte(observed.Version+" "), []byte(version+" "), 1)
		if bytes.Equal(changed, object) {
			t.Fatal("object version mutation did not replace its producer")
		}
		if _, err := source.observeWindowsUnwind(changed); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("object substituted another actual producer", version, err)
		}
	}
	functions, err := goAMD64FrameWindowsUnwindListing(listing, file, pkg, source.origins, request.Directory, observed)
	if err != nil {
		t.Fatal("independent actual original metadata join control failed", err)
	}
	for _, spelling := range []string{"absolute", "slash absolute", "relative", "conflicting extent", "foreign directory"} {
		t.Run("source origins/"+spelling, func(t *testing.T) {
			origins := make(map[string]int)
			relativeNames := 0
			for name, lines := range source.origins {
				if !filepath.IsAbs(name) {
					name = filepath.Join(request.Directory, name)
				}
				if spelling == "slash absolute" {
					name = filepath.ToSlash(name)
				}
				if spelling == "relative" {
					relative, err := filepath.Rel(request.Directory, name)
					if err != nil {
						// A Windows SDK can live on another volume. That
						// header must remain absolute; own assembly inputs
						// below still exercise actual relative spellings.
						if filepath.VolumeName(request.Directory) == filepath.VolumeName(name) {
							t.Fatal(err)
						}
					} else {
						name = relative
						relativeNames++
					}
				}
				if spelling == "foreign directory" {
					name = filepath.Join(request.Directory, "foreign", filepath.Base(name))
				}
				origins[name] = lines
			}
			if spelling == "relative" && relativeNames == 0 {
				t.Fatal("relative-source control did not exercise any relative path")
			}
			if spelling == "conflicting extent" {
				origins[request.AssemblyFile] = source.origins[request.AssemblyFile] + 1
			}
			for _, text := range observed.Texts {
				err := goAMD64FrameSourcePCs(text, functions[text.Name], request.Directory, origins, "")
				if spelling == "conflicting extent" || spelling == "foreign directory" {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unbound or contradictory source origin acquired a PC witness", err)
					}
				} else if err != nil {
					t.Fatal("actual source origin was lost through its host path spelling", err)
				}
			}
		})
	}
	serialized, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	// These are ordinary read-only observations, deliberately copied only for
	// decoder negatives. None are accepted as a public Source/factory input.
	type mutation func([]byte, *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte
	metadataStart := bytes.Index(listing, []byte(observed.Unwind[0].Name+" SSEHUNWINDINFO"))
	if metadataStart < 0 {
		t.Fatal("original listing omitted its actual complete metadata section")
	}
	mutations := map[string]mutation{
		"wrong metadata name": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return bytes.Replace(v, []byte("go:sehuw.12."), []byte("go:sehuw.13."), 1)
		},
		"wrong metadata kind": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return bytes.Replace(v, []byte("SSEHUNWINDINFO"), []byte("SRODATA"), 1)
		},
		"wrong metadata flags": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return bytes.Replace(v, []byte("SSEHUNWINDINFO dupok"), []byte("SSEHUNWINDINFO"), 1)
		},
		"wrong metadata alignment": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return bytes.Replace(v, []byte("SSEHUNWINDINFO dupok size=12"), []byte("SSEHUNWINDINFO dupok size=12 align=0x8"), 1)
		},
		"other SDK alignment spelling": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			if observed.ListingAlignment {
				return bytes.Replace(v, []byte("size=12 align=0x4"), []byte("size=12"), 1)
			}
			return bytes.Replace(v, []byte("SSEHUNWINDINFO dupok size=12"), []byte("SSEHUNWINDINFO dupok size=12 align=0x4"), 1)
		},
		"wrong metadata byte": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return bytes.Replace(v, []byte("01 04 02 05"), []byte("02 04 02 05"), 1)
		},
		"wrong metadata ASCII": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return bytes.Replace(v, []byte(".......P...."), []byte("............"), 1)
		},
		"missing metadata section": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte { return v[:metadataStart] },
		"duplicate metadata section": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return append(v, v[metadataStart:]...)
		},
		"unknown trailing record": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			return append(v, []byte("UNKNOWN_NATIVE_RECORD\n")...)
		},
		"truncated metadata EOF": func(v []byte, _ *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte { return v[:len(v)-5] },
		"different actual TEXT bytes": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts[0].Code[0] ^= 1
			return v
		},
		"different actual TEXT ABI": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte { o.Texts[0].ABI = 1; return v },
		"extra actual TEXT": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts = append(o.Texts, o.Texts[0])
			return v
		},
		"missing actual TEXT": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte { o.Texts = nil; return v },
		"wrong object source line": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts[0].Positions[0].Line++
			return v
		},
		"wrong object source file": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts[0].Positions[0].File = "other.s"
			return v
		},
		"object source-PC gap": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts[0].Positions[0].Start = 1
			return v
		},
		"object source-PC overlap": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts[0].Positions = append(o.Texts[0].Positions, o.Texts[0].Positions[0])
			return v
		},
		"object source-PC missing tail": func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			o.Texts[0].Positions = o.Texts[0].Positions[:len(o.Texts[0].Positions)-1]
			return v
		},
	}
	for _, role := range []string{"wrong push end", "wrong prologue end"} {
		mutations[role] = func(v []byte, o *gostaticstorage.WindowsAMD64AssemblyUnwind) []byte {
			metadata := &o.Unwind[0]
			oldName := metadata.Name
			if role == "wrong push end" {
				metadata.PushEnd, metadata.Data[6] = 2, 2
			} else {
				metadata.PrologueEnd, metadata.Data[1], metadata.Data[4] = 5, 5, 5
			}
			metadata.Name = "go:sehuw.12." + base64.StdEncoding.EncodeToString(metadata.Data)
			for index := range o.Texts[0].Auxiliary {
				if o.Texts[0].Auxiliary[index].Type == o.AuxType {
					o.Texts[0].Auxiliary[index].Target.Name = metadata.Name
				}
			}
			v = bytes.ReplaceAll(v, []byte(oldName), []byte(metadata.Name))
			rowStart := bytes.Index(v[metadataStart:], []byte("\n")) + metadataStart + 1
			return append(append(v[:rowStart:rowStart], goAMD64WindowsUnwindTestByteRow(metadata.Data)...), '\n')
		}
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			var independent gostaticstorage.WindowsAMD64AssemblyUnwind
			if err := json.Unmarshal(serialized, &independent); err != nil {
				t.Fatal(err)
			}
			changed := change(append([]byte(nil), listing...), &independent)
			if _, err := goAMD64FrameWindowsUnwindListing(changed, file, pkg, source.origins, request.Directory, independent); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed original Windows binary/listing join was accepted", err)
			}
		})
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("read-only metadata negative controls changed original source/artifacts", err)
	}
}

func goAMD64WindowsUnwindTestByteRow(data []byte) []byte {
	var result, ascii strings.Builder
	result.WriteString("\t0x0000")
	for _, value := range data {
		fmt.Fprintf(&result, " %02x", value)
		if value < ' ' || value > 0x7e {
			value = '.'
		}
		ascii.WriteByte(value)
	}
	fmt.Fprintf(&result, "  %s", ascii.String())
	return []byte(result.String())
}
