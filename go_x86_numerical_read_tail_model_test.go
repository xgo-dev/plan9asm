package plan9asm

import (
	"errors"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoX86NumericalDirectTailTypedInventoryKeepsHelperSeparate(t *testing.T) {
	const source = "TEXT ·entry(SB),4,$0-0\nJMP helper<>(SB)\nTEXT helper<>(SB),4,$0\nJMP ·ordinary(SB)\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		entries, terminals, err := numericalTypedSourceEntries(file, "example", arch, numericalSBSDKSource)
		if err != nil || !reflect.DeepEqual(entries, map[string]bool{"entry": true, "ordinary": true}) ||
			!reflect.DeepEqual(terminals, map[string]bool{"ordinary": true}) {
			t.Fatal("helper became a declared entry or ordinary terminal lost its own role", arch, entries, terminals, err)
		}
		for _, changed := range []string{
			strings.Replace(source, "JMP helper<>(SB)", "JMP missing<>(SB)", 1),
			strings.Replace(source, "JMP helper<>(SB)", "JMP helper<>+1(SB)", 1),
			strings.Replace(source, "JMP ·ordinary(SB)", "JMP ·ordinary+1(SB)", 1),
			strings.Replace(source, "JMP ·ordinary(SB)", "CALL helper<>+1(SB)\nRET", 1),
			strings.Replace(source, "JMP ·ordinary(SB)", "MOVQ $helper<>(SB),AX\nRET", 1),
			source + "TEXT helper<>(SB),4,$0\nRET\n",
			source + "DATA escape<>+0(SB)/8,$helper<>(SB)\nGLOBL escape<>(SB),8,$8\n",
		} {
			parsed, err := Parse(ArchAMD64, changed)
			if err != nil {
				t.Fatal("independent whole-source role fixture", err)
			}
			if entries, terminals, err := numericalTypedSourceEntries(parsed, "example", arch, numericalSBSDKSource); entries != nil || terminals != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unknown/escaped/duplicate original helper acquired a source entry", arch, changed, entries, terminals, err)
			}
		}
	}
}

func TestGoX86NumericalPrivateCallSourceRolesRemainObservationOnly(t *testing.T) {
	// Retain the earlier self-CALL source: its original control relocation can
	// now be associated, but neither a helper declaration nor a recursive
	// continuation is thereby authorized.
	const source = "TEXT ·entry(SB),4,$0-0\nJMP helper<>(SB)\nTEXT helper<>(SB),4,$0\nCALL helper<>(SB)\nRET\n"
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			entries, terminals, err := numericalTypedSourceEntries(file, "example", arch, numericalSBSDKSource)
			if err != nil || !reflect.DeepEqual(entries, map[string]bool{"entry": true}) || len(terminals) != 0 {
				t.Fatal("CALL source association invented a private helper declaration", entries, terminals, err)
			}
			roles, err := numericalDirectTailRoles(file)
			if err != nil || len(roles) != 2 || roles[x86DirectTailPoint{1, 1}] != "helper<>" {
				t.Fatal("CALL did not retain its actual original TEXT/ordinal association", roles, err)
			}
			resolve := testResolveSym("example")
			pkg := mustGoPackage(t, "example", "package p\nfunc entry()")
			sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if prepared, err := PrepareX86DirectTailSource(file, Options{Goarch: arch, ResolveSym: resolve, Sigs: sigs}); prepared != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "recursive") {
				t.Fatal("observed private CALL supplied recursive execution authority", err)
			}
		})
	}
}

func TestGoX86NumericalDirectTailStaticTupleMatchesOriginalNode(t *testing.T) {
	// This is only an independent association model, never a live source token.
	for _, arch := range []string{"386", "amd64"} {
		makeSource := func() *GoX86NumericalReadSource {
			program, observed := numericalNativeOrderFixture(t)
			program = strings.Replace(program, "RET", "JMP helper<>(SB)", 1)
			file, err := Parse(ArchAMD64, program)
			if err != nil {
				t.Fatal(err)
			}
			return &GoX86NumericalReadSource{file: file, role: numericalSBSDKSource,
				request: GoX86NumericalReadCaptureRequest{PackagePath: "example"},
				assembly: &numericalSDKAssemblyJoin{Observation: sdkASMDataLiveObservation{
					Objects: &gostaticstorage.SDKASMDataObservation{Sources: []gostaticstorage.ASMDataSourceObservation{observed}}}}}
		}
		original := makeSource()
		if name, abi, valid := original.numericalSourceTextIdentity(2, original.file.Funcs[2], arch); !valid || name != "helper" || abi != 65535 {
			t.Fatal("exact original source ordinal lost its physical static tuple", arch, name, abi, valid)
		}
		for name, mutate := range map[string]func(*GoX86NumericalReadSource){
			"ordinary role": func(s *GoX86NumericalReadSource) { s.role = numericalSBOwnedSource },
			"no metadata":   func(s *GoX86NumericalReadSource) { s.assembly = nil },
			"no tail":       func(s *GoX86NumericalReadSource) { s.file.Funcs[0].Instrs = s.file.Funcs[0].Instrs[:1] },
			"source ordinal": func(s *GoX86NumericalReadSource) {
				s.assembly.Observation.Objects.Sources[0].TextOrder[2].SourceOrdinal--
			},
			"object ordinal": func(s *GoX86NumericalReadSource) {
				s.assembly.Observation.Objects.Sources[0].TextOrder[2].ObjectOrdinal++
			},
			"source name": func(s *GoX86NumericalReadSource) {
				s.assembly.Observation.Objects.Sources[0].TextOrder[2].Name = "other"
			},
			"source ABI": func(s *GoX86NumericalReadSource) { s.assembly.Observation.Objects.Sources[0].TextOrder[2].ABI = 0 },
			"source bank": func(s *GoX86NumericalReadSource) {
				s.assembly.Observation.Objects.Sources[0].TextOrder[2].Namespace = gostaticstorage.TextSymbolNonpkgDefinition
			},
			"relative index": func(s *GoX86NumericalReadSource) { s.assembly.Observation.Objects.Sources[0].TextOrder[2].Relative++ },
			"physical index": func(s *GoX86NumericalReadSource) { s.assembly.Observation.Objects.Sources[0].TextOrder[2].Index++ },
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				changed := makeSource()
				mutate(changed)
				if name, abi, valid := changed.numericalSourceTextIdentity(2, changed.file.Funcs[2], arch); valid {
					t.Fatal("changed original static tuple retained an instruction association", name, abi)
				}
			})
		}
	}
}

func TestGoX86NumericalTailStringLanguageKeepsActualABI0Identity(t *testing.T) {
	pkg := mustGoPackage(t, "example.invalid/stringrole", `package stringrole
type Named string
type Other string
type Fake struct { Data *byte; Length int }
func String(x string) uintptr
func NamedString(x Named) uintptr
func OtherString(x Other) uintptr
func Slice(x []byte) uintptr
func Struct(x Fake) uintptr
`)
	for _, arch := range []string{"386", "amd64"} {
		sizes := types.SizesFor("gc", arch)
		word, numerical := int64(8), I64
		if arch == "386" {
			word, numerical = 4, I32
		}
		identities := make(map[string]string)
		for _, name := range []string{"String", "NamedString", "OtherString", "Slice", "Struct"} {
			fn := pkg.Types.Scope().Lookup(name).(*types.Func)
			typ := fn.Type().(*types.Signature).Params().At(0).Type()
			identity, err := numericalTailLanguageType(typ, sizes)
			if err != nil || identities[identity] != "" {
				t.Fatal("same-sized string/named/slice/struct language identities were conflated", arch, name, identity, err)
			}
			identities[identity] = name
			if !strings.Contains(name, "String") {
				continue
			}
			if _, err := goAMD64FrameLanguageTypeRole(typ, sizes, true); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("source-only string role widened generic frame observation", err)
			}
			sig, err := DeriveGoFuncABI0Signature(name, fn, arch, sizes)
			if err != nil || len(sig.Frame.Params) != 2 || sig.Frame.Params[0].Type != Ptr ||
				sig.Frame.Params[0].Offset != 0 || sig.Frame.Params[1].Type != numerical || sig.Frame.Params[1].Offset != word {
				t.Fatal("actual string transport lost separate opaque data and numerical length", arch, name, sig, err)
			}
		}
	}
}
