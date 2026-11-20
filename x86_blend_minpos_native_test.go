package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func x86BlendMinposMemoryRows() []x86BlendMinposCase {
	var rows []x86BlendMinposCase
	for _, row := range x86BlendMinposCanonicalRows() {
		if row.operand == "(BX)" {
			rows = append(rows, row)
		}
	}
	return rows
}

// A minimum-ISA counterpart, separate from the original 78 programs which
// deliberately observe Z/Y/X aliases. Actual bytes supply mode32's valid VEX
// forms without borrowing Go's different four-operand named frontend.
func x86BlendMinposNativeProgram(t *testing.T, arch string) (string, string, [][]byte) {
	t.Helper()
	rows := x86BlendMinposMemoryRows()
	codes := x86BlendMinposOriginalCodes(t, rows)
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source, declarations strings.Builder
	for index, row := range rows {
		for _, role := range []string{"live", "dead"} {
			name := fmt.Sprintf("BlendMinposNative%d_%s", index, role)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),BX\n%s old+%d(FP),CX\n%s mask+%d(FP),DX\n",
				name, 4*word, move, move, word, move, 2*word, move, 3*word)
			fmt.Fprintf(&source, "VMOVUPS (CX),%s2\nVMOVUPS (DX),%s0\nSTC\n", row.bank, row.bank)
			source.WriteString(x86RawDisplacementDirectives(codes[index]))
			if role == "live" {
				fmt.Fprintf(&source, "VMOVUPS %s%d,(DI)\n", row.bank, row.dst)
			}
			source.WriteString("SETCS 64(DI)\nRET\n")
			fmt.Fprintf(&declarations, "func %s(out *[80]byte,input,old,mask *[32]byte)\n", name)
		}
	}
	return source.String(), declarations.String(), codes
}

// These actual Go byte wrappers share the native driver's generator. They
// use only SSE4.1/AVX2, never an incidental AVX512 producer or emulator.
func x86BlendMinposNativeReferences(t *testing.T, codes [][]byte) (string, string) {
	t.Helper()
	rows := x86BlendMinposMemoryRows()
	if len(codes) != len(rows) || len(rows) != 11 {
		t.Fatal("incomplete independent native blend/minimum byte directory")
	}
	var references, cases strings.Builder
	for index, row := range rows {
		literal := make([]string, len(codes[index]))
		for at, value := range codes[index] {
			literal[at] = fmt.Sprintf("0x%02x", value)
		}
		for _, role := range []string{"live", "dead"} {
			name := fmt.Sprintf("BlendMinposNative%d_%s", index, role)
			bank := "xmm"
			if row.width == 32 {
				bank = "ymm"
			}
			assembly := fmt.Sprintf("vmovups (%%1),%%%%%s2\n\tvmovups (%%3),%%%%%s0\n\tstc\n\t.byte %s\n\t", bank, bank, strings.Join(literal, ","))
			live := 0
			if role == "live" {
				assembly += fmt.Sprintf("vmovups %%%%%s%d,(%%2)\n\t", bank, row.dst)
				live = 1
			}
			assembly += "setc 64(%2)"
			fmt.Fprintf(&references, `extern void %[1]s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*);
static __attribute__((noinline,used)) void original_%[1]s(uint8_t *out,const uint8_t *input,const uint8_t *old,const uint8_t *mask) {
    __asm__ volatile(%[2]s : : "b"(input),"r"(old),"r"(out),"r"(mask) : "xmm0","xmm2","xmm3","memory","cc");
}
`, name, strconv.Quote(assembly))
			flag := func(value bool) int {
				if value {
					return 1
				}
				return 0
			}
			width := row.width
			if row.legacy {
				width = 16
			}
			for zero := 0; zero < 2; zero++ {
				fmt.Fprintf(&cases, "{%s,original_%s,%d,%d,%d,%d,%d,%d},\n", name, name, width, row.bits/8, flag(row.minimum), flag(row.legacy), live, zero)
			}
		}
	}
	return references.String(), cases.String()
}

func TestX86BlendMinposOriginalNativeWrappersCompile(t *testing.T) {
	clang, objdump := findLLVM22Tool("clang"), findLLVM22Tool("llvm-objdump")
	if clang == "" || objdump == "" {
		t.Fatal("original native wrappers require LLVM22 clang and llvm-objdump")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, _, codes := x86BlendMinposNativeProgram(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			references, _ := x86BlendMinposNativeReferences(t, codes)
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					directory := t.TempDir()
					input, object := filepath.Join(directory, "reference.c"), filepath.Join(directory, "reference.o")
					if err := os.WriteFile(input, []byte("typedef unsigned char uint8_t;\n"+references), 0600); err != nil {
						t.Fatal(err)
					}
					stage, cancel := runtimeOracleStageContext(t)
					output, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, clang, "--no-default-config",
						"-target", target.triple, "-nostdinc", "-ffreestanding", "-mavx2", level, "-c", input, "-o", object))
					cancel()
					if err != nil {
						t.Fatalf("original wrapper C/assembly failed: %v\n%s", err, output)
					}
					stage, cancel = runtimeOracleStageContext(t)
					listing, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, objdump, "-d", object))
					cancel()
					if err != nil {
						t.Fatal("independent original wrapper disassembly", err, string(listing))
					}
					if count := len(regexp.MustCompile(`(?m)^[0-9a-f]+ <_?original_BlendMinposNative[0-9]+_(?:live|dead)>:\r?\n`).FindAll(listing, -1)); count != 22 {
						t.Fatal("actual object lost an original live/dead wrapper", count)
					}
				})
			}
		})
	}
}

func TestX86BlendMinposNativeBackingAndTargetRemainIndependent(t *testing.T) {
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			source, declarations, _ := x86BlendMinposNativeProgram(t, "amd64")
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("nonmatching target acquired original legacy alignment/fault behavior", err)
			}
		})
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range x86BlendMinposMemoryRows() {
			if !row.legacy {
				continue
			}
			t.Run(target.triple+"/"+row.op, func(t *testing.T) {
				instruction := strings.Replace(row.instruction(), "(BX)", "input+0(FP)", 1)
				source := "TEXT ·Value(SB),4,$0-16\nPXOR X0,X0\nPXOR X2,X2\n" + instruction + "\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(input,other uint64)", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("logical FP bytes acquired actual native m128 storage", api, err)
					}
				}
			})
		}
	}
}

func TestX86BlendMinposActualNativeObjectsRetainLegacyDeadReads(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("actual native objects require exact LLVM22 llc and llvm-objdump")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _ := x86BlendMinposNativeProgram(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("actual initialized original native program rejected", err)
					}
					if strings.Contains(ir, "+avx512") {
						t.Fatal("minimum-ISA original family borrowed AVX512")
					}
					for _, pipeline := range []struct{ name, body, level string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
						{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							directory := t.TempDir()
							input, object := filepath.Join(directory, "native.ll"), filepath.Join(directory, "native.o")
							if err := os.WriteFile(input, []byte(pipeline.body), 0600); err != nil {
								t.Fatal(err)
							}
							stage, cancel := runtimeOracleStageContext(t)
							output, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, llc,
								pipeline.level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
							cancel()
							if err != nil {
								t.Fatalf("actual native object failed: %v\n%s", err, output)
							}
							stage, cancel = runtimeOracleStageContext(t)
							listing, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, objdump, "-d", object))
							cancel()
							if err != nil {
								t.Fatal("native object disassembly", err, string(listing))
							}
							sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <_?(BlendMinposNative[0-9]+_(?:live|dead))>:\r?\n`).FindAllSubmatchIndex(listing, -1)
							if len(sections) != 22 {
								t.Fatal("native object lost an original live/dead function", len(sections))
							}
							for index, section := range sections {
								name := string(listing[section[2]:section[3]])
								end := len(listing)
								if index+1 < len(sections) {
									end = sections[index+1][0]
								}
								var ordinal int
								if _, err := fmt.Sscanf(name, "BlendMinposNative%d_", &ordinal); err != nil || ordinal < 0 || ordinal >= 11 {
									t.Fatal("unrecognized original function identity", name, err)
								}
								row := x86BlendMinposMemoryRows()[ordinal]
								if row.legacy {
									pattern := `(?m)\b` + strings.ToLower(row.op) + `[ \t]+[^\r\n]*\([^\r\n]+\),[ \t]*%xmm[0-9]+`
									if count := len(regexp.MustCompile(pattern).FindAll(listing[section[1]:end], -1)); count != 1 {
										t.Fatalf("%s lost its sole original legacy faulting read: count=%d\n%s", name, count, listing[section[1]:end])
									}
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestX86BlendMinposRequiredNativeOwners(t *testing.T) {
	const file = "x86_blend_minpos_native_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", file)
		if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
			t.Fatal("required native fault owner selected on an inapplicable host", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"TestCrossLinuxRuntimeMatrixX86BlendMinposOriginalFaultsAMD64": false,
		"TestCrossLinuxRuntimeMatrixX86BlendMinposOriginalFaults386":   false,
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(function, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && strings.HasPrefix(selector.Sel.Name, "Skip") {
				t.Fatal("required actual native execution acquired an optional skip", function.Name.Name)
			}
			return true
		})
		if _, found := wanted[function.Name.Name]; !found {
			continue
		}
		host, full := 0, 0
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if callee, ok := call.Fun.(*ast.Ident); ok {
					if callee.Name == "x87IA32RequireNativeHost" {
						host++
					}
					if callee.Name == "x86BlendMinposNativeFaults" {
						full++
					}
				}
			}
			return true
		})
		if host != 2 || full != 1 || wanted[function.Name.Name] {
			t.Fatal("required owner lost host brackets or its complete fault matrix", function.Name.Name, host, full)
		}
		wanted[function.Name.Name] = true
	}
	for root, found := range wanted {
		if !found {
			t.Fatal("required actual-native owner missing", root)
		}
	}
}
