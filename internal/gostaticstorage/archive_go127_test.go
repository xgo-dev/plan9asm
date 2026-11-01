//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

const fixtureModule = "example.invalid/staticstorage"

func fixture(t *testing.T) (string, string, []string) {
	t.Helper()
	dir := t.TempDir()
	var err error
	dir, err = filepath.EvalSymlinks(dir) // This fixture owns the fresh directory.
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod": "module " + fixtureModule + "\n\ngo 1.27.1\n",
		"storage.go": `package staticstorage
import "example.invalid/staticstorage/dep"
var Keys [48]byte
var Data = [4]byte{1, 2, 3, 4}
var Mixed struct { Flag bool; Word uint32; Pointer *byte; Tail [3]byte }
var Relocated = struct { Number uint32; Pointer *byte }{7, &Keys[0]}
var TwiceRelocated = struct { Number uint32; First, Second *byte }{7, &Keys[0], &Keys[1]}
var Address uintptr
var PointerOnly *byte
var StringOnly string
var SliceOnly []byte
var MapOnly map[byte]byte
var ComplexOnly complex128
var BlankOnly struct { _ [8]byte }
var ZeroSize [0]byte
func Read() byte { return Keys[0] + Data[0] + dep.Keys[0] }
`,
		"dep/dep.go": `package dep
var Flags struct { _ [64]byte; Enabled bool; Tail [3]byte }
var Keys [16]byte
func Set(v byte) { Keys[0] = v; Flags.Enabled = v != 0 }
`,
	}
	for name, data := range files {
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	env := fixtureEnv(t, "linux/amd64")
	return dir, binary, env
}

func fixtureEnv(t *testing.T, target string) []string {
	t.Helper()
	values := make(map[string]string)
	for _, pair := range os.Environ() {
		key, value, _ := strings.Cut(pair, "=")
		values[key] = value
	}
	for _, key := range []string{"GOCACHE", "GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		canonical, err := filepath.EvalSymlinks(values[key])
		if !filepath.IsAbs(values[key]) || err != nil || canonical != values[key] {
			// Only a fresh factory-owned artifact may be canonicalized. Do
			// not rewrite a redirected caller input into an accepted role.
			values[key] = t.TempDir()
			canonical, err = filepath.EvalSymlinks(values[key])
			if err != nil {
				t.Fatal(err)
			}
			values[key] = canonical
		}
	}
	goos, goarch, _ := strings.Cut(target, "/")
	for key, value := range map[string]string{
		"GOOS": goos, "GOARCH": goarch, "GOTOOLCHAIN": "local", "GOENV": "off",
		"GOWORK": "off", "CGO_ENABLED": "0", "GOFLAGS": "", "GOEXPERIMENT": "",
		"GOAMD64": "v1", "GOPROXY": "off", "GOSUMDB": "off",
	} {
		values[key] = value
	}
	var env []string
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func run(t *testing.T, binary, dir string, env []string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, err := goasmcmd.Run(ctx, dir, env, binary, args...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

// The independent reader uses actual SDK exports and an explicit importcfg at
// the compiler boundary. No fake SDK source membership or SDK file mutation is
// involved. It reads binary objects through Go's archive/goobj implementation,
// not nm text or this package's parser.
const officialReaderSource = `package main
import (
 "cmd/internal/archive"
 "cmd/internal/goobj"
 "encoding/json"
 "fmt"
 "os"
)
type Reloc struct { Offset, Size int64; Type uint16 }
type Record struct {
 Name string; Kind uint8; ABI uint16; Flags, Flags2 uint8
 Size, Align int64; Data []byte; Relocations []Reloc
}
func main() {
 f, err := os.Open(os.Args[1]); if err != nil { panic(err) }; defer f.Close()
 a, err := archive.Parse(f, false); if err != nil { panic(err) }
 result := map[string]Record{}
 for _, entry := range a.Entries {
  if entry.Type != archive.EntryGoObj { continue }
  data := make([]byte, entry.Obj.Size)
  n, err := f.ReadAt(data, entry.Obj.Offset)
  if err != nil || n != len(data) { panic(fmt.Sprint(n, err)) }
  r := goobj.NewReaderFromBytes(data, false); if r == nil { panic("goobj") }
  count := r.NSym()+r.NHashed64def()+r.NHasheddef()+r.NNonpkgdef()
  for i:=0; i<count; i++ {
   s := r.Sym(uint32(i))
   name := s.Name(r)
   v := Record{Name:name, Kind:s.Type(), ABI:s.ABI(), Flags:s.Flag(), Flags2:s.Flag2(), Size:int64(s.Siz()), Align:int64(s.Align()), Data:r.Data(uint32(i))}
   for j:=0; j<r.NReloc(uint32(i)); j++ {
    q:=r.Reloc(uint32(i),j)
    v.Relocations=append(v.Relocations,Reloc{int64(q.Off()),int64(q.Siz()),q.Type()})
   }
   result[name]=v
  }
 }
 if err:=json.NewEncoder(os.Stdout).Encode(result); err!=nil { panic(err) }
}
`

func officialReader(t *testing.T, binary string) string {
	return officialReaderForSource(t, binary, officialReaderSource)
}

func officialReaderForSource(t *testing.T, binary, source string) string {
	t.Helper()
	dir := t.TempDir()
	var err error
	dir, err = filepath.EvalSymlinks(dir) // Fresh fixture-owned output, not an input redirect.
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"main.go": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := fixtureEnv(t, runtime.GOOS+"/"+runtime.GOARCH)
	arguments := []string{"list", "-deps", "-export", "-f",
		"{{if .Export}}packagefile {{.ImportPath}}={{.Export}}{{end}}",
		"cmd/internal/archive", "cmd/internal/goobj", "encoding/json", "fmt", "os"}
	if source == sdkTextReaderSource {
		arguments = append(arguments, "cmd/internal/objfile")
	}
	config := run(t, binary, dir, env, arguments...)
	if err := os.WriteFile(filepath.Join(dir, "importcfg"), config, 0600); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(dir, gotoolchain.HostExecutable("official-reader"))
	run(t, binary, dir, env, "tool", "compile", "-p", "main", "-importcfg", "importcfg", "-o", "main.o", "main.go")
	run(t, binary, dir, env, "tool", "link", "-importcfg", "importcfg", "-o", tool, "main.o")
	if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
		if source == sdkTextReaderSource {
			artifact = filepath.Join(artifact, "text-sdk-oracle")
		} else if source == sdkNamespaceReaderSource {
			artifact = filepath.Join(artifact, "namespace-sdk-oracle")
		} else if source == sdkIndexedAuxReaderSource {
			artifact = filepath.Join(artifact, "aux-sdk-oracle")
		} else if source == sdkIndexedCountsReaderSource {
			artifact = filepath.Join(artifact, "indexed-counts-sdk-oracle")
		} else if source == sdkASMDataReaderSource {
			artifact = filepath.Join(artifact, "asm-data-sdk-oracle")
		} else if source != officialReaderSource {
			artifact = filepath.Join(artifact, "cpu-sdk-oracle")
		}
		if err := os.MkdirAll(artifact, 0700); err != nil {
			t.Fatal(err)
		}
		goenv := run(t, binary, dir, env, "env", "-json", "GOROOT", "GOTOOLDIR", "GOVERSION", "GOOS", "GOARCH")
		var actual map[string]string
		if err := json.Unmarshal(goenv, &actual); err != nil {
			t.Fatal(err)
		}
		inputs := map[string]string{}
		for role, file := range map[string]string{
			"go":      binary,
			"compile": filepath.Join(actual["GOTOOLDIR"], gotoolchain.HostExecutable("compile")),
			"link":    filepath.Join(actual["GOTOOLDIR"], gotoolchain.HostExecutable("link")),
		} {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			inputs[role] = digest(data)
		}
		for name := range formatSources {
			data, err := os.ReadFile(filepath.Join(actual["GOROOT"], filepath.FromSlash(name)))
			if err != nil || digest(data) != formatSources[name] {
				t.Fatal("independent reader SDK format source changed", name, err)
			}
			inputs[name] = digest(data)
		}
		readerBytes, err := os.ReadFile(tool)
		if err != nil {
			t.Fatal(err)
		}
		inputs["reader"] = digest(readerBytes)
		metadata, _ := json.MarshalIndent(struct {
			Directory, Binary string
			Environment       []string
			Tools             map[string]string
			SourceSHA256      string
			Commands          [][]string
		}{dir, binary, env, inputs, digest([]byte(source)), [][]string{
			arguments,
			{"tool", "compile", "-p", "main", "-importcfg", "importcfg", "-o", "main.o", "main.go"},
			{"tool", "link", "-importcfg", "importcfg", "-o", tool, "main.o"},
		}}, "", "  ")
		for name, data := range map[string][]byte{"sdk-reader-source.go": []byte(source), "sdk-reader-importcfg": config, "sdk-reader-input.json": metadata, "sdk-reader-env.json": goenv, "sdk-reader": readerBytes} {
			if err := os.WriteFile(filepath.Join(artifact, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return tool
}

func TestGoStaticStorageActualBinaryDataRecords(t *testing.T) {
	dir, binary, _ := fixture(t)
	oracle := officialReader(t, binary)
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			output := run(t, binary, dir, fixtureEnv(t, target), selectionArguments()...)
			packages := make(map[string]Package)
			decoder := json.NewDecoder(bytes.NewReader(output))
			for {
				var pkg Package
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				packages[pkg.ImportPath] = pkg
			}
			selected := packages[fixtureModule]
			if selected.Export == "" || packages[fixtureModule+"/dep"].Export == "" {
				t.Fatalf("actual owned/imported exports missing: %s", output)
			}
			data, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			var expected map[string]dataRecord
			oracleRaw := run(t, oracle, dir, fixtureEnv(t, target), selected.Export)
			if err := json.Unmarshal(oracleRaw, &expected); err != nil {
				t.Fatal(err)
			}
			depData, err := os.ReadFile(packages[fixtureModule+"/dep"].Export)
			if err != nil {
				t.Fatal(err)
			}
			depRaw := run(t, oracle, dir, fixtureEnv(t, target), packages[fixtureModule+"/dep"].Export)
			var depExpected map[string]dataRecord
			if err := json.Unmarshal(depRaw, &depExpected); err != nil {
				t.Fatal(err)
			}
			depActual, err := readArchive(depData, target)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Flags", "Keys"} {
				name = fixtureModule + "/dep." + name
				if depExpected[name].Size == 0 || !reflect.DeepEqual(depActual[name], depExpected[name]) {
					t.Fatal("independent imported data record differs", name)
				}
			}
			if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
				if !filepath.IsAbs(artifact) {
					t.Fatal("artifact root must be explicit and absolute")
				}
				folder := filepath.Join(artifact, strings.ReplaceAll(target, "/", "-"))
				if err := os.MkdirAll(folder, 0700); err != nil {
					t.Fatal(err)
				}
				for name, contents := range map[string][]byte{"actual.a": data, "sdk-reader.json": oracleRaw, "selected.json": output, "dep.a": depData, "dep-sdk-reader.json": depRaw} {
					if err := os.WriteFile(filepath.Join(folder, name), contents, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Logf("ACTUAL_ARCHIVE_SHA256 %s %x SDK_READER_SHA256 %x", target, sha256.Sum256(data), sha256.Sum256(oracleRaw))
			for _, name := range []string{"Keys", "Data", "Mixed", "Relocated"} {
				if expected[fixtureModule+"."+name].Size == 0 {
					t.Fatal("independent actual compiler object omitted", name)
				}
			}
			t.Logf("ACTUAL_GO_BINARY_STORAGE %s Keys=%+v Data=%+v Mixed=%+v", target,
				expected[fixtureModule+".Keys"], expected[fixtureModule+".Data"], expected[fixtureModule+".Mixed"])
			actual, err := readArchive(data, target)
			if err != nil {
				t.Fatalf("compiled initialized storage lacks binary producer: %v", err)
			}
			for _, name := range []string{"Keys", "Data", "Mixed", "Relocated"} {
				name = fixtureModule + "." + name
				if !reflect.DeepEqual(actual[name], expected[name]) {
					t.Fatalf("independent SDK binary record differs for %s: got %+v want %+v", name, actual[name], expected[name])
				}
			}
		})
	}
}
