//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"context"
	encodingbinary "encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sdkRequest(t *testing.T, binary, target string) Request {
	t.Helper()
	return Request{GoBinary: binary, Directory: filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", "internal", "cpu"),
		PackagePath: "internal/cpu", Target: target, Environment: fixtureEnv(t, target),
		Variables: []Reference{{"internal/cpu", "X86"}, {"internal/cpu", "CacheLineSize"}}}
}

func sdkCaptured(t *testing.T, req Request) (*Observation, Report) {
	t.Helper()
	o, err := CaptureSDKCPU(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	report, err := o.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return o, report
}

func TestGoSDKStaticStorageTypedProducerAndReader(t *testing.T) {
	_, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkMemberReaderSource)
	for _, target := range []string{
		"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm",
		"darwin/amd64", "windows/386", "windows/amd64",
	} {
		t.Run(target, func(t *testing.T) {
			o, report := sdkCaptured(t, sdkRequest(t, binary, target))
			pad, word := int64(64), int64(8)
			if target == "linux/arm" {
				pad = 32
			}
			if target == "linux/arm64" {
				pad = 128
			}
			if target == "linux/386" || target == "windows/386" || target == "linux/arm" {
				word = 4
			}
			for _, v := range report.Variables {
				expectedSize, expectedSpans, kind := word, []Span{{0, word}}, uint8(5)
				if v.Name == "X86" {
					expectedSize, expectedSpans, kind = 2*pad+36, []Span{{pad, 36}}, 10
				}
				if v.Size != expectedSize || v.Kind != kind || v.Alignment != 0 || !reflect.DeepEqual(v.Numerical, expectedSpans) {
					t.Fatalf("actual target numerical/BSS/DATA/blank layout differs: %+v", v)
				}
			}
			packages, err := sdkCPUPackages(report)
			if err != nil {
				t.Fatal(err)
			}
			pkg := packages["internal/cpu"]
			raw := run(t, oracle, report.CommandDirectory, fixtureEnv(t, target), pkg.Export)
			var members []sdkMember
			if err := json.Unmarshal(raw, &members); err != nil {
				t.Fatal(err)
			}
			records, err := readSDKCPUArchive(report.Archives["internal/cpu"], target, pkg.SFiles)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range members {
				for name, record := range m.Variables {
					if !reflect.DeepEqual(records[name], record) {
						t.Fatal("SDK original all-member oracle differs", name)
					}
				}
			}
			encoded, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			var decoded Report
			if json.Unmarshal(encoded, &decoded) != nil || o.CheckReport(context.Background(), decoded) != nil {
				t.Fatal("actual SDK readback failed")
			}
			if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
				folder := filepath.Join(artifact, strings.ReplaceAll(target, "/", "-"))
				if err := os.MkdirAll(folder, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string][]byte{"sdk-producer-report.json": encoded, "sdk-producer-members.json": raw} {
					if err := os.WriteFile(filepath.Join(folder, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func changeSDKSelection(t *testing.T, report *Report, key string, value any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(report.RawSelection))
	var buf bytes.Buffer
	for {
		var pkg map[string]json.RawMessage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		var path string
		_ = json.Unmarshal(pkg["ImportPath"], &path)
		if path == "internal/cpu" {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			pkg[key] = raw
		}
		if err := json.NewEncoder(&buf).Encode(pkg); err != nil {
			t.Fatal(err)
		}
	}
	report.RawSelection = buf.Bytes()
}

func TestGoSDKStaticStorageOwnerAndReaderGuards(t *testing.T) {
	dir, binary, _ := fixture(t)
	o, report := sdkCaptured(t, sdkRequest(t, binary, "linux/amd64"))
	for name, mutate := range map[string]func(*Report){
		"standard alone":                 func(r *Report) { changeSDKSelection(t, r, "Goroot", false) },
		"module nil arbitrary directory": func(r *Report) { changeSDKSelection(t, r, "Dir", dir) },
		"wrong root":                     func(r *Report) { changeSDKSelection(t, r, "Root", dir) },
		"module owner": func(r *Report) {
			changeSDKSelection(t, r, "Module", map[string]any{"Path": "internal/cpu", "Dir": dir, "Main": true})
		},
		"import map":                     func(r *Report) { changeSDKSelection(t, r, "ImportMap", map[string]string{"unsafe": "elsewhere"}) },
		"native member":                  func(r *Report) { changeSDKSelection(t, r, "SysoFiles", []string{"cpu.syso"}) },
		"wrong assembly role":            func(r *Report) { changeSDKSelection(t, r, "SFiles", []string{"cpu_x86.s", "cpu.s"}) },
		"assembly command rule":          func(r *Report) { r.Tools["src/cmd/go/internal/work/gc.go"] = strings.Repeat("0", 64) },
		"unbound target tuning":          func(r *Report) { r.CommandEnvironment["GOARM"] = "6,softfloat" },
		"report target/profile mismatch": func(r *Report) { r.Target = "darwin/amd64" },
		"original source changed with hash": func(r *Report) {
			r.Source["cpu.go"] = append(r.Source["cpu.go"], '\n')
			r.SourceSHA256["cpu.go"] = digest(r.Source["cpu.go"])
		},
		"original inventory omitted": func(r *Report) { delete(r.Source, "cpu_windows.go"); delete(r.SourceSHA256, "cpu_windows.go") },
		"aliased linkname": func(r *Report) {
			r.Source["cpu.go"] = bytes.Replace(r.Source["cpu.go"], []byte("//go:linkname X86"), []byte("//go:linkname X86 other.X86"), 1)
			r.SourceSHA256["cpu.go"] = digest(r.Source["cpu.go"])
		},
		"pointer or padding bytes": func(r *Report) {
			for i := range r.Variables {
				if r.Variables[i].Name == "X86" {
					r.Variables[i].Numerical = []Span{{0, r.Variables[i].Size}}
				}
			}
		},
		"self linkname flag removed": func(r *Report) {
			a := r.Archives["internal/cpu"]
			obj := objectBytes(t, a)
			pos := blockOffset(obj, 3) + 21*symbolIndex(t, obj, "internal/cpu.X86")
			obj[pos+12] = 0
			r.ArchiveSHA256["internal/cpu"] = digest(a)
		},
		"self linkname flag extended": func(r *Report) {
			a := r.Archives["internal/cpu"]
			obj := objectBytes(t, a)
			pos := blockOffset(obj, 3) + 21*symbolIndex(t, obj, "internal/cpu.X86")
			obj[pos+12] |= 32
			r.ArchiveSHA256["internal/cpu"] = digest(a)
		},
		"extent disagreement": func(r *Report) {
			a := r.Archives["internal/cpu"]
			obj := objectBytes(t, a)
			pos := blockOffset(obj, 3) + 21*symbolIndex(t, obj, "internal/cpu.X86")
			encodingbinary.LittleEndian.PutUint32(obj[pos+13:], 165)
			r.ArchiveSHA256["internal/cpu"] = digest(a)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneReport(t, report)
			mutate(&changed)
			if !errors.Is(ValidateReport(changed), ErrContext) || !errors.Is(o.CheckReport(context.Background(), changed), ErrContext) {
				t.Fatal("unbound SDK role acquired producer")
			}
		})
	}
	for _, kind := range []string{"lookalike owner", "arbitrary module nil", "unknown target", "function not Var", "missing Var"} {
		t.Run(kind, func(t *testing.T) {
			req := sdkRequest(t, binary, "linux/amd64")
			switch kind {
			case "lookalike owner":
				req.Directory = dir
			case "arbitrary module nil":
				req.PackagePath = "unsafe"
			case "unknown target":
				req.Target = "freebsd/amd64"
			case "function not Var":
				req.Variables = []Reference{{"internal/cpu", "Initialize"}}
			case "missing Var":
				req.Variables = []Reference{{"internal/cpu", "NoSuchVar"}}
			}
			if got, err := CaptureSDKCPU(context.Background(), req); !errors.Is(err, ErrContext) {
				if got != nil {
					got.Close()
				}
				t.Fatal("unbound original SDK request accepted", err)
			}
		})
	}
	if got, err := Capture(context.Background(), sdkRequest(t, binary, "linux/amd64")); !errors.Is(err, ErrContext) {
		if got != nil {
			got.Close()
		}
		t.Fatal("ordinary module producer widened")
	}
	if _, err := CaptureSDKCPU(nil, sdkRequest(t, binary, "linux/amd64")); !errors.Is(err, ErrContext) {
		t.Fatal("nil SDK context accepted")
	}
}

func sdkMemberBody(t *testing.T, archive []byte, name string) []byte {
	t.Helper()
	members, err := archiveMembers(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		if member.name == name {
			body, err := objectBody(member.data, "linux/amd64")
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatal("missing actual SDK member", name)
	return nil
}

func TestGoSDKStaticStorageAllMemberBinaryGuards(t *testing.T) {
	_, binary, _ := fixture(t)
	_, report := sdkCaptured(t, sdkRequest(t, binary, "linux/amd64"))
	original := report.Archives["internal/cpu"]
	for name, mutate := range map[string]func([]byte){
		"compiler nonstd":               func(a []byte) { encodingbinary.LittleEndian.PutUint32(objectBytes(t, a)[16:], 0) },
		"empty member nonstd":           func(a []byte) { encodingbinary.LittleEndian.PutUint32(sdkMemberBody(t, a, "cpu.o")[16:], 4) },
		"assembly missing assembly bit": func(a []byte) { encodingbinary.LittleEndian.PutUint32(sdkMemberBody(t, a, "cpu_x86.o")[16:], 16) },
		"assembly extra flags":          func(a []byte) { encodingbinary.LittleEndian.PutUint32(sdkMemberBody(t, a, "cpu_x86.o")[16:], 21) },
		"assembly block overflow": func(a []byte) {
			encodingbinary.LittleEndian.PutUint32(sdkMemberBody(t, a, "cpu_x86.o")[20+4*14:], ^uint32(0))
		},
		"assembly same ABI wrapper": func(a []byte) {
			obj := sdkMemberBody(t, a, "cpu_x86.o")
			pos := blockOffset(obj, 3) + 21*symbolIndex(t, obj, "internal/cpu.cpuid")
			encodingbinary.LittleEndian.PutUint16(obj[pos+8:], 1)
		},
		"assembly storage collision": func(a []byte) {
			obj := sdkMemberBody(t, a, "cpu_x86.o")
			pos := blockOffset(obj, 3) + 21*symbolIndex(t, obj, "internal/cpu.cpuid")
			off := encodingbinary.LittleEndian.Uint32(obj[pos+4:])
			name := "internal/cpu.X86"
			copy(obj[int(off):], name)
			encodingbinary.LittleEndian.PutUint32(obj[pos:], uint32(len(name)))
			obj[pos+10] = 10
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(nil), original...)
			mutate(changed)
			if _, err := readSDKCPUArchive(changed, "linux/amd64", []string{"cpu.s", "cpu_x86.s"}); !errors.Is(err, ErrContext) {
				t.Fatal("malformed or unbound SDK member accepted", err)
			}
		})
	}
	for _, sources := range [][]string{nil, {"cpu.s"}, {"cpu_x86.s", "cpu.s"}, {"cpu.s", "../cpu_x86.s"}} {
		if _, err := readSDKCPUArchive(original, "linux/amd64", sources); !errors.Is(err, ErrContext) {
			t.Fatal("unbound selected SFile roles accepted")
		}
	}
	if _, err := readArchive(original, "linux/amd64"); !errors.Is(err, ErrContext) {
		t.Fatal("ordinary archive member grammar broadened")
	}
	empty := append([]byte(nil), sdkMemberBody(t, original, "cpu.o")...)
	for _, flags := range []uint32{0, 16} {
		encodingbinary.LittleEndian.PutUint32(empty[16:], flags)
		if _, err := readObjectRole(empty, flags, false); !errors.Is(err, ErrContext) {
			t.Fatal("empty compiler object broadened")
		}
	}
}
