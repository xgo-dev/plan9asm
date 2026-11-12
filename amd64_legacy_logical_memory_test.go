package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86LegacyLogicalOriginalBytes(t *testing.T, arch, name string) []byte {
	t.Helper()
	listing := x86InsertExtractGoListing(t, arch, "TEXT original(SB),4,$0-0\n"+name+" (AX),X0\nRET\n")
	var code []byte
	for _, line := range strings.Split(string(listing), "\n") {
		code = append(code, x86InsertExtractListedBytes(line)...)
	}
	// Independent Intel encoding, not obtained from the translator's spec.
	opcode := map[string]byte{
		"ANDPS": 0x54, "ANDPD": 0x54, "ANDNPS": 0x55, "ANDNPD": 0x55,
		"ORPS": 0x56, "ORPD": 0x56, "XORPS": 0x57, "XORPD": 0x57,
		"PAND": 0xdb, "PANDN": 0xdf, "POR": 0xeb, "PXOR": 0xef,
	}[name]
	want := []byte{0x0f, opcode, 0x00, 0xc3}
	if strings.HasSuffix(name, "PD") || strings.HasPrefix(name, "P") {
		want = append([]byte{0x66}, want...)
	}
	if !bytes.Equal(code, want) {
		t.Fatalf("%s/%s actual Go memory opcode=%x independent encoding=%x", arch, name, code, want)
	}
	t.Logf("%s/%s original complete opcode+RET=%x", arch, name, code)
	return append([]byte(nil), code[:len(code)-1]...)
}

func TestX86LegacyLogicalMemoryOriginalGoBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range x86LegacyLogicalMemoryNames {
			t.Run(arch+"/"+name, func(t *testing.T) { x86LegacyLogicalOriginalBytes(t, arch, name) })
		}
	}
}

func TestX86LegacyLogicalMemoryRequiredNativeSelection(t *testing.T) {
	const file = "amd64_legacy_logical_memory_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"linux", "386"},
		{"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", file)
		if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
			t.Fatalf("stock Go required native selection %s/%s: %t/%v", target.os, target.arch, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(syntax.Decls) != 2 {
		t.Fatal("native wrapper must contain only its import and required root")
	}
	function, ok := syntax.Decls[1].(*ast.FuncDecl)
	if !ok || function.Name.Name != "TestCrossLinuxRuntimeMatrixX86LegacyLogicalMemoryNativeFaults" || len(function.Body.List) != 1 {
		t.Fatal("native root registration changed or became optional")
	}
	statement, ok := function.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("native root bypassed its mandatory helper")
	}
	call, ok := statement.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		t.Fatal("native root must call the full fault helper")
	}
	callee, ok := call.Fun.(*ast.Ident)
	if !ok || callee.Name != "x86LegacyLogicalMemoryRuntime" {
		t.Fatal("native root changed helper")
	}
	argument, ok := call.Args[1].(*ast.Ident)
	if !ok || argument.Name != "true" {
		t.Fatal("native root omitted its alignment axis")
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") {
		t.Fatalf("required cross-runtime prefix missing: %v", err)
	}
}

func TestX86LegacyLogicalMemoryUnboundAddressSizeBeforeEmission(t *testing.T) {
	for _, name := range x86LegacyLogicalMemoryNames {
		file, err := Parse(ArchAMD64, "TEXT view(SB),4,$0-0\n"+name+" (AX),X0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, bits := range []int{32, 64} {
			ins := file.Funcs[0].Instrs[1]
			ins.x86AddressBits = bits
			var output strings.Builder
			context := &amd64Ctx{goarch: "amd64", b: &output}
			known, terminal, err := context.lowerPackedLogicalFamily(ins.Op, ins)
			if !known || terminal || !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
				t.Fatalf("%s unbound address-size%d emitted IR: %t/%t/%v", name, bits, known, terminal, err)
			}
		}
	}
}

// Independent legacy namespace: these twelve Go names all have an m128
// source whose original SSE instruction requires aligned native storage.
var x86LegacyLogicalMemoryNames = []string{
	"ANDPS", "ANDPD", "ANDNPS", "ANDNPD", "ORPS", "ORPD",
	"XORPS", "XORPD", "PAND", "PANDN", "POR", "PXOR",
}

var x86LegacyLogicalMemoryTargets = []struct{ arch, triple string }{
	{"amd64", "x86_64-apple-darwin"},
	{"amd64", "x86_64-unknown-linux-gnu"},
	{"amd64", "x86_64-pc-windows-msvc"},
	{"386", "i386-unknown-linux-gnu"},
	{"386", "i686-pc-windows-msvc"},
}

func TestX86LegacyLogicalMemoryFPNeedsNativeBacking(t *testing.T) {
	for _, target := range x86LegacyLogicalMemoryTargets {
		for _, name := range x86LegacyLogicalMemoryNames {
			source := "TEXT ·view(SB),4,$0-16\nMOVOU a+0(FP),X0\n" + name + " a+0(FP),X0\nRET\n"
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+name+"/"+api, func(t *testing.T) {
					_, err := x86ScalarFPBitViewAPI(t, source, "func view(a,b uint64)", target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "original native storage") {
						t.Fatalf("independent FP bytes fabricated native m128 backing/alignment: %v", err)
					}
				})
			}
		}
	}
}

func TestX86LegacyLogicalMemoryVirtualStackNeedsCertificate(t *testing.T) {
	for _, target := range x86LegacyLogicalMemoryTargets {
		for _, name := range x86LegacyLogicalMemoryNames {
			for _, address := range []string{"16(SP)", "16(BP)", "16(AX)(BP*1)"} {
				source := x86OrdinaryBPNativeSource(target.arch, "view", name+" "+address+",X0", address, 0)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+name+"/"+address+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *byte)", target.arch, target.triple, api)
						x86RequireOrdinaryBPNativeOutcome(t, target.arch, address, ir, err)
					})
				}
			}
		}
	}
}

func TestX86LegacyLogicalMemoryNativeOpcodeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86LegacyLogicalMemoryTargets {
		var source, ordinary, declaration strings.Builder
		source.WriteString("GLOBL ·data(SB),8,$16\n")
		ordinary.WriteString("GLOBL ·data(SB),8,$16\n")
		declaration.WriteString("var data [16]byte\n")
		for _, name := range x86LegacyLogicalMemoryNames {
			move, size := "MOVQ", 8
			if target.arch == "386" {
				move, size = "MOVL", 4
			}
			for i, address := range []string{"(AX)", "16(AX)(CX*2)", "·data(SB)", "(FS)", "(GS)"} {
				fn := fmt.Sprintf("%s%d", strings.ToLower(name), i)
				body := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n"+
					"%s p+0(FP),AX\n%s index+%d(FP),CX\nPXOR X0,X0\n%s %s,X0\nRET\n",
					fn, size*2, move, move, size, name, address)
				source.WriteString(body)
				if i < 3 {
					ordinary.WriteString(body)
				}
				fmt.Fprintf(&declaration, "func %s(p *byte,index uintptr)\n", fn)
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		pkg := mustGoPackage(t, "logical", "package logical\n"+declaration.String())
		resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
		signatures, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
		if err != nil || len(file.Funcs) != 60 {
			t.Fatal("original logical-memory format inventory changed", err)
		}
		// Original FS/GS operands have no Go TLS/segment contract. Keep all
		// sixty formats as emitter objects and public Context, not public success.
		formatIR := x86ScalarFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0)
		for _, name := range x86LegacyLogicalMemoryNames {
			for _, segment := range []string{"fs", "gs"} {
				want := "asm sideeffect \"" + strings.ToLower(name) + " %" + segment + ":($2), $0\""
				if !strings.Contains(formatIR, want) {
					t.Fatal("original native segment format lost its prefix", name, segment)
				}
			}
		}
		for _, level := range []string{"-O0", "-O2"} {
			x86PackedStringCompileObject(t, llc, target.triple, formatIR, level)
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, ordinary.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declaration.String(), target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original segmented source acquired an unbound TLS contract", api, err)
				}
				ir, err = x86ScalarFPBitViewAPI(t, ordinary.String(), declaration.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range x86LegacyLogicalMemoryNames {
					want := "asm sideeffect \"" + strings.ToLower(name) + " ($2), $0\", \"=x,0,r,~{memory}\""
					if !strings.Contains(ir, want) {
						t.Fatalf("dead result lost original single native %s memory effect", name)
					}
				}
				compileLLVMToObject(t, llc, target.triple, "logical-native.ll", "logical-native.o", ir)
			})
		}
	}
}

func TestX86LegacyLogicalMemoryPSRetainsSSE1Carrier(t *testing.T) {
	var source strings.Builder
	for _, name := range []string{"ANDPS", "ANDNPS", "ORPS", "XORPS"} {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nMOVUPS (AX),X0\n%s (AX),X0\nMOVUPS X0,(BX)\nRET\n", strings.ToLower(name), name)
	}
	file, signatures := x86UnboundVoidFormatSources(t, source.String(), "386", "i386-unknown-linux-gnu")
	ir := x86ScalarFormatObjectUnit(t, file, signatures, "386", "i386-unknown-linux-gnu", 0)
	x86LegacyLogicalSSE1Objects(t, ir)
}

func TestX86LegacyLogicalMemoryPSInitializedSSE1Objects(t *testing.T) {
	var source, declaration strings.Builder
	for _, name := range []string{"ANDPS", "ANDNPS", "ORPS", "XORPS"} {
		fn := strings.ToLower(name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\n"+
			"MOVL p+0(FP),AX\nMOVL out+4(FP),BX\nMOVUPS (AX),X0\n"+
			"%s (AX),X0\nMOVUPS X0,(BX)\nRET\n", fn, name)
		fmt.Fprintf(&declaration, "func %s(p,out *byte)\n", fn)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		x86LEAActualTargetGoObject(t, "386", triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declaration.String(), "386", triple, api)
				if err != nil {
					t.Fatal("initialized SSE1 native-memory program", err)
				}
				x86LegacyLogicalSSE1Objects(t, ir)
			})
		}
	}
}

func x86LegacyLogicalSSE1Objects(t *testing.T, ir string) {
	t.Helper()
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and objdump required")
	}
	if !strings.Contains(ir, "call <4 x float> asm sideeffect") || strings.Contains(ir, "+sse2") {
		t.Fatal("PS native carrier silently requires SSE2")
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			directory := t.TempDir()
			input, object := filepath.Join(directory, "sse1.ll"), filepath.Join(directory, "sse1.o")
			if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, llc, level, "-filetype=obj", input, "-o", object))
			cancel()
			if err != nil {
				t.Fatalf("SSE1 object: %v\n%s", err, output)
			}
			ctx, cancel = runtimeOracleStageContext(t)
			output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, objdump, "-d", object))
			cancel()
			if err != nil {
				t.Fatalf("SSE1 disassembly: %v\n%s", err, output)
			}
			for _, name := range []string{"andps", "andnps", "orps", "xorps"} {
				if !strings.Contains(string(output), name) {
					t.Fatalf("SSE1 object lost %s", name)
				}
			}
			for _, forbidden := range []string{"movdqa", "movdqu", "pand", "pxor", "por", "movapsd", "movq\t%xmm"} {
				if strings.Contains(string(output), forbidden) {
					t.Fatalf("SSE1 source introduced %s:\n%s", forbidden, output)
				}
			}
		})
	}
}
