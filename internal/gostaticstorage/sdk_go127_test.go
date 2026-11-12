//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type sdkDefinition struct {
	Name                   string
	Kind                   uint8
	ABI                    uint16
	Flags, Flags2          uint8
	Size, Align            int64
	DataBytes, Relocations int
}

type sdkMember struct {
	Name         string
	Type         int
	Offset, Size int64
	TextHeader   []byte
	ObjectFlags  uint32
	Definitions  []sdkDefinition
	Variables    map[string]dataRecord
}

// All member/definition metadata comes from the original SDK implementation.
// Variables retain full bytes/relocations; unrelated TEXT data is not treated
// as storage and receives no translation or native-entry permission.
const sdkMemberReaderSource = `package main
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
 Member string; Index uint32
}
type Definition struct {
 Name string; Kind uint8; ABI uint16; Flags, Flags2 uint8
 Size, Align int64; DataBytes, Relocations int
}
type Member struct {
 Name string; Type int; Offset, Size int64
 TextHeader []byte; ObjectFlags uint32; Definitions []Definition
 Variables map[string]Record
}
func main() {
 f,err:=os.Open(os.Args[1]); if err!=nil { panic(err) }; defer f.Close()
 a,err:=archive.Parse(f,false); if err!=nil { panic(err) }
 members:=[]Member{}
 for _,entry:=range a.Entries {
  m:=Member{Name:entry.Name,Type:int(entry.Type),Offset:entry.Offset,Size:entry.Size}
  if entry.Type==archive.EntryGoObj {
   m.TextHeader=entry.Obj.TextHeader
   data:=make([]byte,entry.Obj.Size)
   n,err:=f.ReadAt(data,entry.Obj.Offset); if err!=nil||n!=len(data) { panic(fmt.Sprint(n,err)) }
   r:=goobj.NewReaderFromBytes(data,false); if r==nil { panic("goobj") }
   m.ObjectFlags=r.Flags(); m.Variables=map[string]Record{}
   count:=r.NSym()+r.NHashed64def()+r.NHasheddef()+r.NNonpkgdef()
   for i:=0;i<count;i++ {
    s:=r.Sym(uint32(i)); name:=s.Name(r)
    m.Definitions=append(m.Definitions,Definition{Name:name,Kind:s.Type(),ABI:s.ABI(),Flags:s.Flag(),Flags2:s.Flag2(),Size:int64(s.Siz()),Align:int64(s.Align()),DataBytes:len(r.Data(uint32(i))),Relocations:r.NReloc(uint32(i))})
    if name!="internal/cpu.X86"&&name!="internal/cpu.CacheLineSize" { continue }
    v:=Record{
     Name:name, Kind:s.Type(), ABI:s.ABI(), Flags:s.Flag(), Flags2:s.Flag2(),
     Size:int64(s.Siz()), Align:int64(s.Align()), Data:r.Data(uint32(i)),
     Member:entry.Name, Index:uint32(i),
    }
    for j:=0;j<r.NReloc(uint32(i));j++ { q:=r.Reloc(uint32(i),j); v.Relocations=append(v.Relocations,Reloc{int64(q.Off()),int64(q.Siz()),q.Type()}) }
    m.Variables[name]=v
   }
  }
  members=append(members,m)
 }
 if err:=json.NewEncoder(os.Stdout).Encode(members);err!=nil { panic(err) }
}
`

func TestGoSDKStaticStorageOriginalCPUArchiveMembers(t *testing.T) {
	_, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkMemberReaderSource)
	root := filepath.Dir(filepath.Dir(binary))
	dir := filepath.Join(root, "src", "internal", "cpu")
	for _, target := range []string{
		"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm",
		"darwin/amd64", "windows/386", "windows/amd64",
	} {
		t.Run(target, func(t *testing.T) {
			selected := run(t, binary, dir, fixtureEnv(t, target), "list", "-deps", "-json", "-compiled", "-export", "-a", "-p=1", "internal/cpu")
			decoder := json.NewDecoder(bytes.NewReader(selected))
			var actual Package
			for {
				var pkg Package
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if pkg.ImportPath == "internal/cpu" {
					actual = pkg
				}
			}
			if !actual.Standard || actual.Dir != dir || actual.Module != nil || actual.Export == "" {
				t.Fatalf("original SDK owner selection differs: %+v", actual)
			}
			archive, err := os.ReadFile(actual.Export)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, dir, fixtureEnv(t, target), actual.Export)
			var members []sdkMember
			if err := json.Unmarshal(raw, &members); err != nil {
				t.Fatal(err)
			}
			var variable dataRecord
			matches := 0
			for _, member := range members {
				if value, exists := member.Variables["internal/cpu.X86"]; exists {
					variable = value
					matches++
				}
			}
			if matches != 1 || variable.Kind != 10 || variable.Size <= 0 || len(variable.Data) != 0 || len(variable.Relocations) != 0 {
				t.Fatalf("actual SDK native BSS identity is not unique/initialized: %+v", members)
			}
			artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR")
			if artifact != "" {
				folder := filepath.Join(artifact, strings.ReplaceAll(target, "/", "-"))
				if err := os.MkdirAll(folder, 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string][]byte{"actual.a": archive, "selected.json": selected, "sdk-members.json": raw} {
					if err := os.WriteFile(filepath.Join(folder, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Logf("SDK_ORIGINAL_CPU %s archiveSHA256=%s members=%d X86=%+v", target, digest(archive), len(members), variable)
			for _, member := range members {
				t.Logf("SDK_ORIGINAL_MEMBER %s %s type=%d flags=%#x definitions=%d", target, member.Name, member.Type, member.ObjectFlags, len(member.Definitions))
			}
			data, err := readSDKCPUArchive(archive, target, actual.SFiles)
			if err != nil {
				t.Fatalf("original SDK initialized numerical storage lacks binary producer: %v", err)
			}
			if !reflect.DeepEqual(data[variable.Name], variable) {
				t.Fatal("original SDK BSS record differs from actual Go archive reader")
			}
		})
	}
}
