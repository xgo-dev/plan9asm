//go:build go1.23

package gostaticstorage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// This reader is compiled against the selected SDK's actual goobj/objabi
// exports. It does not copy our enum numbers, offsets or SEH decoder.
const windowsUnwindSDKReader = `package main
import (
 "bytes"
 "cmd/internal/goobj"
 "cmd/internal/objabi"
 "encoding/json"
 "os"
)
func main() {
 data, err := os.ReadFile(os.Args[1])
 if err != nil { panic(err) }
 reader := goobj.NewReaderFromBytes(data[bytes.Index(data, []byte("\n!\n"))+3:], true)
 type record struct {
  Name string
  Kind, Flags, Flags2 uint8
  Align uint32
  Data []byte
 }
 result := struct {
  Kind, Aux uint8
  TextFlags2 uint8
  Records []record
  Links map[string]string
 }{Kind: uint8(objabi.SSEHUNWINDINFO), Aux: goobj.AuxSehUnwindInfo, Links: map[string]string{}}
 count := reader.NSym()+reader.NHashed64def()+reader.NHasheddef()+reader.NNonpkgdef()
 for index := uint32(0); index < uint32(count); index++ {
  symbol := reader.Sym(index)
  switch objabi.SymKind(symbol.Type()) {
  case objabi.SSEHUNWINDINFO:
   result.Records = append(result.Records, record{symbol.Name(reader), symbol.Type(), symbol.Flag(), symbol.Flag2(), symbol.Align(), reader.Data(index)})
  case objabi.STEXT:
   result.TextFlags2 = symbol.Flag2()
   for _, aux := range reader.Auxs(index) {
    if aux.Type() != goobj.AuxSehUnwindInfo { continue }
    ref := aux.Sym()
    if ref.PkgIdx != goobj.PkgIdxHashed { panic("SEH reference is not hashed") }
    target := reader.Sym(uint32(reader.NSym()+reader.NHashed64def())+ref.SymIdx)
    if _, duplicate := result.Links[symbol.Name(reader)]; duplicate { panic("duplicate SEH link") }
    result.Links[symbol.Name(reader)] = target.Name(reader)
   }
  }
 }
 if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
}
`

func TestWindowsUnwindHistoricalSchemaActualSDK(t *testing.T) {
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	environment := append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOFLAGS=",
		"GOEXPERIMENT=", "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off", "GOAMD64=v1",
		"GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	run := func(env []string, binary string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		output, err := goasmcmd.Run(ctx, directory, env, binary, args...)
		if err != nil {
			t.Fatal(err)
		}
		return output
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.invalid/sehschema\n\ngo 1.20\n")
	write("original.s", "TEXT ·Value(SB),4,$160-16\nMOVQ a+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n"+
		"TEXT ·Void(SB),4,$160-8\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nRET\n")
	version := strings.TrimSpace(string(run(environment, driver, "env", "GOVERSION")))
	root := strings.TrimSpace(string(run(environment, driver, "env", "GOROOT")))
	read := func(role string) ([]byte, error) { return os.ReadFile(filepath.Join(root, filepath.FromSlash(role))) }
	builtin, err := WindowsAMD64UnwindSources(version, read)
	if err != nil {
		t.Fatal("actual SDK needs its independently audited schema", err)
	}
	target := append(append([]string(nil), environment...), "GOOS=windows", "GOARCH=amd64")
	run(target, driver, "tool", "asm", "-p", "example.invalid/sehschema", "-o", "original.o", "original.s")
	data, err := os.ReadFile(filepath.Join(directory, "original.o"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := ObserveWindowsAMD64AssemblyUnwind(data, builtin)
	if err != nil || len(observed.Texts) != 2 || len(observed.Unwind) != 1 || observed.Version != version {
		t.Fatal("complete original Windows object observation failed", err)
	}

	write("reader.go", windowsUnwindSDKReader)
	config := run(environment, driver, "list", "-deps", "-export", "-f",
		"{{if .Export}}packagefile {{.ImportPath}}={{.Export}}{{end}}",
		"cmd/internal/goobj", "cmd/internal/objabi", "bytes", "encoding/json", "os")
	write("importcfg", string(config))
	reader := filepath.Join(directory, gotoolchain.HostExecutable("reader"))
	run(environment, driver, "tool", "compile", "-p", "main", "-importcfg", "importcfg", "-o", "reader.o", "reader.go")
	run(environment, driver, "tool", "link", "-importcfg", "importcfg", "-o", reader, "reader.o")
	var actual struct {
		Kind, Aux, TextFlags2 uint8
		Records               []struct {
			Name                string
			Kind, Flags, Flags2 uint8
			Align               uint32
			Data                []byte
		}
		Links map[string]string
	}
	if err := json.Unmarshal(run(environment, reader, "original.o"), &actual); err != nil {
		t.Fatal(err)
	}
	if len(actual.Records) != len(observed.Unwind) || len(actual.Links) != len(observed.Texts) ||
		actual.Aux != observed.AuxType || actual.TextFlags2 != observed.TextFlags2 {
		t.Fatal("actual SDK complete enum/inventory differs", actual, observed)
	}
	for index, record := range actual.Records {
		value := observed.Unwind[index]
		if record.Name != value.Name || record.Kind != actual.Kind || record.Flags != 3 ||
			record.Flags2 != observed.TextFlags2 || record.Align != 4 || !bytes.Equal(record.Data, value.Data) {
			t.Fatal("actual SDK complete SEH record differs", record, value)
		}
	}
	for _, text := range observed.Texts {
		if actual.Links[text.Name] != observed.Unwind[0].Name {
			t.Fatal("actual SDK TEXT/SEH ownership differs", text.Name)
		}
	}

	start := bytes.Index(data, []byte("\n!\n")) + 3
	block := func(index int) int { return start + int(binary.LittleEndian.Uint32(data[start+20+index*4:])) }
	symbol := block(3) + int(observed.Unwind[0].Index)*21
	textSymbol := block(3) + int(observed.Texts[0].Index)*21
	changes := map[string]func([]byte){
		"other symbol enum":      func(v []byte) { v[symbol+10] = actual.Kind - 1 },
		"unknown symbol enum":    func(v []byte) { v[symbol+10] = actual.Kind + 1 },
		"other metadata flag2":   func(v []byte) { v[symbol+12] ^= 16 },
		"other TEXT flag2":       func(v []byte) { v[textSymbol+12] ^= 16 },
		"wrong binary alignment": func(v []byte) { v[symbol+17] = 0 },
		"unknown auxiliary enum": func(v []byte) { v[block(15)] = actual.Aux + 1 },
		"other auxiliary enum": func(v []byte) {
			for pos := block(15); pos < block(16); pos += 9 {
				if v[pos] == actual.Aux {
					v[pos]--
					return
				}
			}
			t.Fatal("actual object omitted SEH link")
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(nil), data...)
			change(changed)
			if _, err := ObserveWindowsAMD64AssemblyUnwind(changed, builtin); !errors.Is(err, ErrContext) {
				t.Fatal("changed producer-specific object accepted", err)
			}
		})
	}
	for _, role := range windowsUnwindSourceRoles {
		t.Run("source/"+role, func(t *testing.T) {
			_, err := WindowsAMD64UnwindSources(version, func(name string) ([]byte, error) {
				value, err := read(name)
				if name == role {
					value = append(value, '\n')
				}
				return value, err
			})
			if !errors.Is(err, ErrContext) {
				t.Fatal("changed SDK source accepted", err)
			}
		})
	}
	if _, err := WindowsAMD64UnwindSources("go1.99.1", read); !errors.Is(err, ErrContext) {
		t.Fatal("unregistered producer accepted", err)
	}
	if _, err := ObserveWindowsAMD64AssemblyUnwind(data, append(append([]byte(nil), builtin...), '\n')); !errors.Is(err, ErrContext) {
		t.Fatal("changed builtin source accepted", err)
	}
	if version != "go1.27.1" && version != "go1.27.2" && version != "go1.27.3" {
		if _, err := objectBody(data, "windows/amd64"); !errors.Is(err, ErrContext) {
			t.Fatal("Windows role widened generic compiler object admission", err)
		}
	}
	t.Logf("actual SDK %s: kind=%d aux=%d flags2=%d; %d TEXTs, %d shared unwind record",
		version, actual.Kind, actual.Aux, actual.TextFlags2, len(observed.Texts), len(observed.Unwind))
}
