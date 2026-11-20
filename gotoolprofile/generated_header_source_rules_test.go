package gotoolprofile

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// These are native compiler observations, not a source-derived header proof or
// permission to omit a CPU scope. The complete source replay is a later stage.
const nativeHeaderRulesSource = `package header

const (
	First = iota + 1
	Second
)
const Text = "x y\n世界"
const Truth = true
const Rune = '世'
const Negative = -7
const Huge = 1 << 80
const Fraction = 1.25
const Complex = 1 + 2i
const IntegerFromFloat int16 = 2.0
const TypedFloat float32 = 2
const _ = 17

type NonStruct int
type Word = uintptr
type Packet struct { First uint64; Last byte }
type Alias = Packet
type Defined Packet
type Nested struct { Prefix byte; Body Packet; Tail uint16 }
type ArrayRecord struct { Items [2]Packet; Last byte }
type Blank struct { First byte; _ [3]byte; Word uintptr }
type Empty struct {}
type EmptyTail struct { Word uint64; Tail [0]byte }
type ZeroArray struct { Values [0]uint64; Last byte }
type Embedded struct { Packet }
type LiteralAlias = struct { Value uint32 }
type Lanes struct { First float64; Middle complex128; Last float32 }
type Generic[T any] struct { Value T }

var Variable = 11

func Holder() {
	type Local struct { Value uint64 }
	const LocalConstant = 9
	var value Local
	_ = value
	_ = LocalConstant
}
`

func TestGeneratedHeaderNativeSourceDeclarationAndLayoutRules(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRules(t, target, nativeHeaderRulesSource)
			wanted := map[string]string{
				"const_First": "1", "const_Second": "2", "const_Text": `"x y\n世界"`,
				"const_Truth": "true", "const_Rune": "19990", "const_Negative": "-7",
				"const_Huge": "1208925819614629174706176", "Empty__size": "0",
				"const_IntegerFromFloat": "2",
				"LiteralAlias__size":     "4", "LiteralAlias_Value": "0",
			}
			packetSize, nestedSize, bodyOffset, tailOffset := "16", "32", "8", "24"
			arraySize, arrayLast, blankSize, wordOffset := "40", "32", "16", "8"
			zeroTailSize, zeroArraySize := "16", "8"
			lanesSize := "32"
			if strings.HasSuffix(target, "/386") || strings.HasSuffix(target, "/arm") {
				packetSize, nestedSize, bodyOffset, tailOffset = "12", "20", "4", "16"
				arraySize, arrayLast, blankSize, wordOffset = "28", "24", "8", "4"
				zeroTailSize, zeroArraySize = "12", "4"
				lanesSize = "28"
			}
			for _, name := range []string{"Packet", "Alias", "Defined"} {
				wanted[name+"__size"], wanted[name+"_First"], wanted[name+"_Last"] = packetSize, "0", "8"
			}
			wanted["Nested__size"], wanted["Nested_Prefix"] = nestedSize, "0"
			wanted["Nested_Body"], wanted["Nested_Tail"] = bodyOffset, tailOffset
			wanted["ArrayRecord__size"], wanted["ArrayRecord_Items"], wanted["ArrayRecord_Last"] = arraySize, "0", arrayLast
			wanted["Blank__size"], wanted["Blank_First"], wanted["Blank_Word"] = blankSize, "0", wordOffset
			wanted["EmptyTail__size"], wanted["EmptyTail_Word"], wanted["EmptyTail_Tail"] = zeroTailSize, "0", "8"
			wanted["ZeroArray__size"], wanted["ZeroArray_Values"], wanted["ZeroArray_Last"] = zeroArraySize, "0", "0"
			wanted["Embedded__size"], wanted["Embedded_Packet"] = packetSize, "0"
			wanted["Lanes__size"], wanted["Lanes_First"], wanted["Lanes_Middle"], wanted["Lanes_Last"] = lanesSize, "0", "8", "24"
			if !reflect.DeepEqual(actual, wanted) {
				t.Fatalf("native compiler declaration/layout contract changed:\nactual=%v\nwanted=%v", actual, wanted)
			}
		})
	}
}

func TestGeneratedHeaderNativeLayoutIsNotPublicTypeModelAuthority(t *testing.T) {
	const source = "package header\ntype Packet struct { First uint64; Last byte }\ntype EmptyTail struct { Word uint64; Tail [0]byte }\n"
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRules(t, target, source)
			files := token.NewFileSet()
			file, err := parser.ParseFile(files, "header.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, arch, _ := strings.Cut(target, "/")
			sizes := types.SizesFor("gc", arch)
			if sizes == nil {
				t.Fatalf("missing actual framework size model for %s", arch)
			}
			pkg, err := (&types.Config{Sizes: sizes, GoVersion: "go1.20"}).Check("example.invalid/header", files, []*ast.File{file}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Packet", "EmptyTail"} {
				model := sizes.Sizeof(pkg.Scope().Lookup(name).Type())
				t.Logf("NATIVE_HEADER_PUBLIC_MODEL target=%s type=%s compiler=%s public_model=%d equal=%t",
					target, name, actual[name+"__size"], model, actual[name+"__size"] == fmt.Sprint(model))
			}
			// Native expectations are independent of the SDK running this test.
			// Go 1.20 StdSizes returns 9/8 on both target widths, unlike gc.
			wanted := "16"
			if arch == "386" || arch == "arm" {
				wanted = "12"
			}
			if actual["Packet__size"] != wanted || actual["EmptyTail__size"] != wanted {
				t.Fatalf("native trailing/zero-tail padding changed: %v", actual)
			}
		})
	}
}

func TestGeneratedHeaderNativeBuiltinImportPropertiesMatchSourceReplay(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		want64 map[string]string
		want32 map[string]string
	}{
		{
			name:   "unsafe_import_constant",
			source: "package header\nimport \"unsafe\"\nconst Word = unsafe.Sizeof(uintptr(0))\n",
			want64: map[string]string{"const_Word": "8"},
			want32: map[string]string{"const_Word": "4"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
				t.Run(target, func(t *testing.T) {
					wanted := test.want64
					if strings.HasSuffix(target, "/386") || strings.HasSuffix(target, "/arm") {
						wanted = test.want32
					}
					actual := compileNativeHeaderRules(t, target, test.source)
					if !reflect.DeepEqual(actual, wanted) {
						t.Fatalf("unclosed-source native observation changed: actual=%v wanted=%v", actual, wanted)
					}
					replayed, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", target, "go1.20",
						map[string]string{"header.go": test.source}, map[string]string{"unsafe": "unsafe"})
					if err != nil || !reflect.DeepEqual(actual, replayed) {
						t.Fatalf("actual builtin-import header differs from original property replay: actual=%v replay=%v error=%v",
							actual, replayed, err)
					}
				})
			}
		})
	}
}

func TestGeneratedHeaderNativeDefinitionsFollowOriginalSourceChanges(t *testing.T) {
	const original = "package header\nconst Value = 7\ntype Record struct { Value uint64 }\n"
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			before := compileNativeHeaderRules(t, target, original)
			for _, test := range []struct {
				name   string
				source string
			}{
				{"constant_value", strings.Replace(original, "Value = 7", "Value = 8", 1)},
				{"field_offset", strings.Replace(original, "{ Value uint64 }", "{ Prefix uint64; Value uint64 }", 1)},
				{"definition_presence", "package header\nconst Value = 7\n"},
			} {
				t.Run(test.name, func(t *testing.T) {
					after := compileNativeHeaderRules(t, target, test.source)
					if reflect.DeepEqual(before, after) || HeaderDefinitionSHA256(before) == HeaderDefinitionSHA256(after) {
						t.Fatal("actual native header did not retain changed complete original declarations")
					}
				})
			}
		})
	}
}

func compileNativeHeaderRules(t *testing.T, target, source string) map[string]string {
	t.Helper()
	return compileNativeHeaderRulesWithImports(t, target, source, nil)
}

func compileNativeHeaderRulesWithImports(t *testing.T, target, source string, dependencies map[string]string) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	goos, goarch, ok := strings.Cut(target, "/")
	if !ok {
		t.Fatal("invalid native compiler target")
	}
	env := replaceEnv(os.Environ(), map[string]string{
		"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
		"GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": "",
	})
	directory := t.TempDir()
	stdout, stderr, err := RunBounded(ctx, directory, env, goBinary, "env", "-json", "GOROOT", "GOVERSION", "GOTOOLDIR", "GOHOSTOS", "GOENV")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual SDK env: %v\n%s\n%s", err, stdout, stderr)
	}
	var sdk struct{ GOROOT, GOVERSION, GOTOOLDIR, GOHOSTOS, GOENV string }
	if err := json.Unmarshal(stdout, &sdk); err != nil || sdk.GOROOT == "" || sdk.GOTOOLDIR == "" || sdk.GOENV != "" {
		t.Fatalf("incomplete selected SDK identity: %+v %v", sdk, err)
	}
	extension := ""
	if sdk.GOHOSTOS == "windows" {
		extension = ".exe"
	}
	actualDriver, err := filepath.EvalSymlinks(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	expectedDriver, err := filepath.EvalSymlinks(filepath.Join(sdk.GOROOT, "bin", "go"+extension))
	if err != nil || actualDriver != expectedDriver {
		t.Fatalf("selected driver differs from its actual SDK: %s %s %v", actualDriver, expectedDriver, err)
	}
	compiler := filepath.Join(sdk.GOTOOLDIR, "compile"+extension)
	inputs := []string{actualDriver, compiler}
	digests := make(map[string][32]byte)
	for _, input := range inputs {
		data, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		digests[input] = sha256.Sum256(data)
	}
	goFile, header, object := filepath.Join(directory, "header.go"), filepath.Join(directory, "go_asm.h"), filepath.Join(directory, "go.o")
	if err := os.WriteFile(goFile, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"tool", "compile", "-p", "example.invalid/header", "-lang", "go1.20", "-asmhdr", header, "-o", object, goFile}
	if len(dependencies) != 0 {
		var names []string
		for name := range dependencies {
			names = append(names, name)
		}
		sort.Strings(names)
		var importConfig strings.Builder
		for index, name := range names {
			original := []byte(dependencies[name])
			file := filepath.Join(directory, fmt.Sprintf("dependency-%d.go", index))
			export := filepath.Join(directory, fmt.Sprintf("dependency-%d.a", index))
			if err := os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := RunBounded(ctx, directory, env, goBinary,
				"tool", "compile", "-p", name, "-lang", "go1.20", "-o", export, file)
			if err != nil || len(stdout) != 0 || len(stderr) != 0 {
				t.Fatalf("actual original dependency compiler %s: %v\n%s\n%s", target, err, stdout, stderr)
			}
			bytes, err := os.ReadFile(export)
			if err != nil || len(bytes) == 0 {
				t.Fatalf("actual original dependency emitted no export: %v", err)
			}
			digests[file], digests[export] = sha256.Sum256(original), sha256.Sum256(bytes)
			inputs = append(inputs, file, export)
			fmt.Fprintf(&importConfig, "packagefile %s=%s\n", name, export)
		}
		config := filepath.Join(directory, "importcfg")
		bytes := []byte(importConfig.String())
		if err := os.WriteFile(config, bytes, 0600); err != nil {
			t.Fatal(err)
		}
		digests[config] = sha256.Sum256(bytes)
		inputs = append(inputs, config)
		args = append(args[:len(args)-1], "-importcfg", config, goFile)
	}
	stdout, stderr, err = RunBounded(ctx, directory, env, goBinary, args...)
	if err != nil || len(stdout) != 0 || len(stderr) != 0 {
		t.Fatalf("actual native compiler %s: %v\n%s\n%s", target, err, stdout, stderr)
	}
	for _, input := range append(inputs, goFile) {
		data, err := os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		wanted := digests[input]
		if input == goFile {
			wanted = sha256.Sum256([]byte(source))
		}
		if sha256.Sum256(data) != wanted {
			t.Fatalf("actual compiler input changed: %s", input)
		}
	}
	headerBytes, err := os.ReadFile(header)
	if err != nil {
		t.Fatal(err)
	}
	objectBytes, err := os.ReadFile(object)
	if err != nil || len(objectBytes) == 0 {
		t.Fatalf("actual native compiler emitted no object: %v", err)
	}
	definitions, err := HeaderDefinitions(headerBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NATIVE_HEADER_RULE_OBJECT sdk=%s target=%s source_sha=%x compile_sha=%x header_sha=%x object_sha=%x definitions=%d",
		sdk.GOVERSION, target, sha256.Sum256([]byte(source)), digests[compiler], sha256.Sum256(headerBytes), sha256.Sum256(objectBytes), len(definitions))
	return definitions
}
