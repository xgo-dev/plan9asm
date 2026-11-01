package plan9asm

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func x86PanicTerminalCompilerFixture(t *testing.T) (GoPackage, []byte, *gostaticstorage.SDKASMDataObservation) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "body.go")
	pkg := x86PanicTerminalDeclarationFixture(t, map[string]string{filename: "func arbitraryName(){ panic(\"failure\") }\n"})
	body := gostaticstorage.TextRecord{Name: "terminal.arbitraryName", Namespace: gostaticstorage.TextSymbolSelf, ABI: 1, Kind: 1,
		Size: 5, Code: []byte{0xe8, 0, 0, 0, 0}, Positions: []gostaticstorage.TextPosition{{Start: 0, End: 5, File: filename, Line: 2}}}
	objects := &gostaticstorage.SDKASMDataObservation{Protocol: gostaticstorage.ASMDataCPPProtocol, PackagePath: "terminal", Target: "linux/386",
		Members: []gostaticstorage.ASMDataMember{{Name: "__.PKGDEF"}, {Name: "_go_.o", Flags: 16, Texts: []gostaticstorage.TextRecord{body}}, {Name: "terminal.o", Flags: 20}},
		Sources: []gostaticstorage.ASMDataSourceObservation{{Name: "terminal.s"}}}
	return pkg, []byte("ref terminal.arbitraryName ABI0\ndef terminal.entry ABI0\n"), objects
}

func TestX86GoPanicTerminalCompilerKeepsActualABIAndOriginalBody(t *testing.T) {
	pkg, symABI, objects := x86PanicTerminalCompilerFixture(t)
	bodies, err := x86GoPanicTerminalCompilerBodies(pkg, symABI, objects, "")
	if err != nil || len(bodies) != 1 || bodies[0].declaration.nativeName != "terminal.arbitraryName" ||
		!reflect.DeepEqual(bodies[0].text, objects.Members[1].Texts[0]) || bodies[0].text.ABI != 1 {
		t.Fatal("an ABI0 assembler reference did not retain the actual non-regabi386 compiler ABIInternal body", bodies, err)
	}
}

func TestX86GoPanicTerminalCompilerRejectsDifferentIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*gostaticstorage.SDKASMDataObservation){
		"target":    func(o *gostaticstorage.SDKASMDataObservation) { o.Target = "linux/amd64" },
		"package":   func(o *gostaticstorage.SDKASMDataObservation) { o.PackagePath = "other" },
		"protocol":  func(o *gostaticstorage.SDKASMDataObservation) { o.Protocol = gostaticstorage.ASMDataProtocol },
		"inventory": func(o *gostaticstorage.SDKASMDataObservation) { o.Members = o.Members[:2] },
		"compiler-member": func(o *gostaticstorage.SDKASMDataObservation) {
			o.Members[1].Name = "other.o"
		},
		"fake-ABI0": func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].ABI = 0 },
		"name":      func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Name = "terminal.other" },
		"namespace": func(o *gostaticstorage.SDKASMDataObservation) {
			o.Members[1].Texts[0].Namespace = gostaticstorage.TextSymbolHashed
		},
		"kind":      func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Kind = 3 },
		"dupe-weak": func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Flags |= 1 },
		"linkname":  func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Flags2 |= 16 },
		"wrapper":   func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Flags2 |= 64 },
		"empty":     func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Code = nil },
		"extent":    func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Size++ },
		"source-file": func(o *gostaticstorage.SDKASMDataObservation) {
			o.Members[1].Texts[0].Positions[0].File += ".other"
		},
		"source-line": func(o *gostaticstorage.SDKASMDataObservation) { o.Members[1].Texts[0].Positions[0].Line++ },
		"compiler-duplicate": func(o *gostaticstorage.SDKASMDataObservation) {
			o.Members[1].Texts = append(o.Members[1].Texts, o.Members[1].Texts[0])
		},
		"alternative-ASM": func(o *gostaticstorage.SDKASMDataObservation) {
			o.Members[2].Texts = append(o.Members[2].Texts, o.Members[1].Texts[0])
		},
		"DATA-alias": func(o *gostaticstorage.SDKASMDataObservation) {
			o.Members[2].Definitions = []gostaticstorage.ASMDataDefinition{{Name: "terminal.arbitraryName", Kind: 3}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			pkg, symABI, objects := x86PanicTerminalCompilerFixture(t)
			mutate(objects)
			if bodies, err := x86GoPanicTerminalCompilerBodies(pkg, symABI, objects, ""); !errors.Is(err, ErrProbeNeedsContext) || len(bodies) != 0 {
				t.Fatal("changed compiler/source/object association was accepted", bodies, err)
			}
		})
	}
	for name, symABI := range map[string]string{
		"missing": "", "wrong-ABI": "ref terminal.arbitraryName ABIInternal\n", "wrong-name": "ref terminal.other ABI0\n",
		"ASM-definition": "ref terminal.arbitraryName ABI0\ndef terminal.arbitraryName ABI0\n",
		"unknown-schema": "permission terminal.arbitraryName noreturn\n",
	} {
		t.Run(name, func(t *testing.T) {
			pkg, _, objects := x86PanicTerminalCompilerFixture(t)
			if bodies, err := x86GoPanicTerminalCompilerBodies(pkg, []byte(symABI), objects, ""); !errors.Is(err, ErrProbeNeedsContext) || len(bodies) != 0 {
				t.Fatal("missing/different/handwritten symbol role acquired compiler association", bodies, err)
			}
		})
	}
}
