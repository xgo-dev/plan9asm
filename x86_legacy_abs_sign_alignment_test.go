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
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type x86AbsSignAlignmentRow struct {
	opcode       string
	bits         int
	sign, legacy bool
}

// Type4 has different legacy/VEX alignment rules. Do not derive either the
// opcode directory or that distinction from the implementation's form table.
func x86AbsSignAlignmentRows() []x86AbsSignAlignmentRow {
	var rows []x86AbsSignAlignmentRow
	for _, vector := range []bool{false, true} {
		for _, sign := range []bool{false, true} {
			prefix := "PABS"
			if sign {
				prefix = "PSIGN"
			}
			if vector {
				prefix = "V" + prefix
			}
			for index, width := range []string{"B", "W", "D"} {
				rows = append(rows, x86AbsSignAlignmentRow{prefix + width, 8 << index, sign, !vector})
			}
		}
	}
	return rows
}

func (row x86AbsSignAlignmentRow) instruction() string {
	if row.sign && !row.legacy {
		return row.opcode + " (BX),X0,X0"
	}
	return row.opcode + " (BX),X0"
}

func x86AbsSignAlignmentOriginalBytes(t *testing.T, arch string) [][]byte {
	t.Helper()
	rows := x86AbsSignAlignmentRows()
	var source strings.Builder
	for _, row := range rows {
		source.WriteString(row.instruction() + "\n")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, arch, source.String()+"RET")
	if len(pcs) != 13 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("incomplete original Go legacy/VEX alignment opcode inventory")
	}
	result := make([][]byte, len(rows))
	for index, row := range rows {
		opcode := byte(0x1c + index%3)
		if row.sign {
			opcode = byte(0x08 + index%3)
		}
		want := []byte{0x66, 0x0f, 0x38, opcode, 0x03}
		if !row.legacy {
			want = []byte{0xc4, 0xe2, 0x79, opcode, 0x03}
		}
		result[index] = append([]byte(nil), code[pcs[index]:pcs[index+1]]...)
		if !bytes.Equal(result[index], want) {
			t.Fatal("actual Go opcode differs from independent Intel ModRM/prefix row", arch, row.opcode, result[index], want)
		}
	}
	return result
}

func x86AbsSignAlignmentProgram(arch string, vectorControls bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	rows := x86AbsSignAlignmentRows()
	if !vectorControls {
		rows = rows[:6]
	}
	var source, declarations strings.Builder
	for index, row := range rows {
		for _, role := range []string{"live", "dead"} {
			name := fmt.Sprintf("AbsAlignment%d_%s", index, role)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),BX\n%s old+%d(FP),CX\nMOVOU (CX),X0\nSTC\n%s\n",
				name, 3*word, move, move, word, move, 2*word, row.instruction())
			if role == "live" {
				source.WriteString("MOVOU X0,(DI)\n")
			}
			source.WriteString("SETCS 16(DI)\nRET\n")
			fmt.Fprintf(&declarations, "func %s(out *[32]byte,input,old *[16]byte)\n", name)
		}
	}
	return source.String(), declarations.String()
}

// Native runtime and host-independent C-object checks consume this same
// generator. Quote actual assembly newlines once as a C string literal,
// rather than stacking raw-Go, fmt and C backslash escape conventions.
func x86AbsSignAlignmentNativeReferences(t *testing.T, code [][]byte) (string, string) {
	t.Helper()
	rows := x86AbsSignAlignmentRows()
	if len(code) != len(rows) {
		t.Fatal("native original reference lacks the complete independent byte directory")
	}
	var references, kernels strings.Builder
	for index, row := range rows {
		literal := make([]string, len(code[index]))
		for at, value := range code[index] {
			literal[at] = fmt.Sprintf("0x%02x", value)
		}
		for _, role := range []string{"live", "dead"} {
			name := fmt.Sprintf("AbsAlignment%d_%s", index, role)
			assembly := "movdqu (%1),%%xmm0\n\tstc\n\t.byte " + strings.Join(literal, ",") + "\n\t"
			live := 0
			if role == "live" {
				assembly += "movdqu %%xmm0,(%2)\n\t"
				live = 1
			}
			assembly += "setc 16(%2)"
			fmt.Fprintf(&references, `extern void %[1]s(uint8_t*,const uint8_t*,const uint8_t*);
static __attribute__((noinline,used)) void original_%[1]s(uint8_t *out,const uint8_t *input,const uint8_t *old) {
    __asm__ volatile(%[2]s : : "b"(input),"r"(old),"r"(out) : "xmm0","memory","cc");
}
`, name, strconv.Quote(assembly))
			legacy, sign := 0, 0
			if row.legacy {
				legacy = 1
			}
			if row.sign {
				sign = 1
			}
			fmt.Fprintf(&kernels, "{%s,original_%s,%d,%d,%d,%d},\n", name, name, row.bits/8, sign, legacy, live)
		}
	}
	return references.String(), kernels.String()
}

func TestX86LegacyAbsSignAlignmentIndependentOriginalBytes(t *testing.T) {
	x86PackedAbsSignOriginalProgramUnchanged(t)
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) { x86AbsSignAlignmentOriginalBytes(t, arch) })
	}
}

func TestX86LegacyAbsSignAlignmentOriginalCWrappersCompile(t *testing.T) {
	clang, objdump := findLLVM22Tool("clang"), findLLVM22Tool("llvm-objdump")
	if clang == "" || objdump == "" {
		t.Fatal("actual native original wrappers require exact LLVM22 clang and llvm-objdump")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			references, _ := x86AbsSignAlignmentNativeReferences(t, x86AbsSignAlignmentOriginalBytes(t, target.arch))
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					directory := t.TempDir()
					source, object := filepath.Join(directory, "original.c"), filepath.Join(directory, "original.o")
					if err := os.WriteFile(source, []byte("typedef unsigned char uint8_t;\n"+references), 0600); err != nil {
						t.Fatal(err)
					}
					// Object-only, freestanding C: no host headers, SDK, libc or
					// link fallback can hide a wrong 386/AMD64 register constraint.
					stage, cancel := runtimeOracleStageContext(t)
					output, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, clang, "--no-default-config",
						"-target", target.triple, "-nostdinc", "-ffreestanding", "-mssse3", level, "-c", source, "-o", object))
					cancel()
					if err != nil {
						t.Fatalf("actual original native C wrappers failed compilation: %v\n%s", err, output)
					}
					stage, cancel = runtimeOracleStageContext(t)
					listing, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, objdump, "-d", object))
					cancel()
					if err != nil {
						t.Fatalf("actual original native C objects failed independent disassembly: %v\n%s", err, listing)
					}
					pattern := `(?m)^[0-9a-f]+ <_?original_AbsAlignment[0-9]+_(?:live|dead)>:\r?\n`
					if got := len(regexp.MustCompile(pattern).FindAll(listing, -1)); got != 24 {
						t.Fatal("actual C object lost an original live/dead opcode wrapper", got)
					}
				})
			}
		})
	}
}

func TestX86LegacyAbsSignAlignmentNeedsActualNativeBackingAndTarget(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86AbsSignAlignmentRows()[:6] {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.opcode+"/"+api, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-16\nPXOR X0,X0\n" + row.opcode + " a+0(FP),X0\nRET\n"
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(a,b uint64)", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("logical FP bytes acquired original native m128 alignment and backing", err)
					}
				})
			}
		}
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			source, declarations := x86AbsSignAlignmentProgram("amd64", false)
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a nonmatching target silently erased original x86 alignment/fault behavior", err)
			}
		})
	}
}

func TestX86LegacyAbsSignAlignmentRequiredNativeOwners(t *testing.T) {
	const name = "x86_legacy_abs_sign_alignment_native_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", name)
		if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
			t.Fatal("required actual-native fault owner selected on the wrong host", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		"TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaultsAMD64": false,
		"TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaults386":   false,
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(function, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && strings.HasPrefix(selector.Sel.Name, "Skip") {
				t.Fatal("required native ABS/sign execution became an optional skip", function.Name.Name)
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
					if callee.Name == "x86LegacyAbsSignNativeAlignment" {
						full++
					}
				}
			}
			return true
		})
		if host != 2 || full != 1 || wanted[function.Name.Name] {
			t.Fatal("required native owner lost host brackets or its entire fault matrix", function.Name.Name, host, full)
		}
		wanted[function.Name.Name] = true
	}
	for root, found := range wanted {
		if !found {
			t.Fatal("required native owner is absent", root)
		}
	}
}

func TestX86LegacyAbsSignAlignmentNativeOracleFixesAndObservesMXCSRMode(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(), "x86_legacy_abs_sign_alignment_native_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	source := ""
	ast.Inspect(syntax, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "x86LegacyAbsSignAlignmentNativeMainC" {
			return true
		}
		if len(declaration.Values) != 1 || source != "" {
			t.Fatal("native MXCSR driver source ownership changed")
		}
		literal, ok := declaration.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("native MXCSR driver is not the actual compiled C source")
		}
		source, err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	load, read := strings.Index(source, "ldmxcsr"), strings.Index(source, "stmxcsr")
	witness, call := strings.Index(source, `printf("memory enter`), strings.Index(source, "(original?k.original:k.translated)")
	if !strings.Contains(source, "fixed_mxcsr=UINT32_C(0x1f80)") || load < 0 || read <= load || witness <= read || call <= witness ||
		strings.Count(source, "stmxcsr") != 2 || strings.LastIndex(source, "stmxcsr") <= call ||
		strings.Count(source, "observed_mxcsr!=fixed_mxcsr") != 2 {
		t.Fatal("oracle must fix and observe MM=0 before the exact entry witness and check successful-return MXCSR preservation")
	}
}

// Real LLVM22 machine objects, not IR spelling or align16 metadata, must
// retain each legacy m128 opcode in both live and dead-result functions.
// Original-process signal behavior is a separate required native owner.
func TestX86LegacyAbsSignAlignmentActualNativeObjects(t *testing.T) {
	llc, disassembler := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || disassembler == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required for original native alignment objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86AbsSignAlignmentProgram(target.arch, false)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original legacy source rejected before object examination", err)
					}
					for _, pipeline := range []struct{ name, body, level string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
						{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							directory := t.TempDir()
							input, object := filepath.Join(directory, "alignment.ll"), filepath.Join(directory, "alignment.o")
							if err := os.WriteFile(input, []byte(pipeline.body), 0600); err != nil {
								t.Fatal(err)
							}
							stage, cancel := runtimeOracleStageContext(t)
							output, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, llc,
								pipeline.level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
							cancel()
							if err != nil {
								t.Fatalf("actual native alignment object: %v\n%s", err, output)
							}
							stage, cancel = runtimeOracleStageContext(t)
							listing, err := runtimeOracleCombinedOutput(stage, exec.CommandContext(stage, disassembler, "-d", object))
							cancel()
							if err != nil {
								t.Fatalf("independent LLVM22 disassembly: %v\n%s", err, listing)
							}
							sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <_?(AbsAlignment[0-9]+_(?:live|dead))>:\r?\n`).FindAllSubmatchIndex(listing, -1)
							if len(sections) != 12 {
								t.Fatal("actual object lost a complete live/dead original function", len(sections))
							}
							for index, section := range sections {
								name := string(listing[section[2]:section[3]])
								end := len(listing)
								if index+1 < len(sections) {
									end = sections[index+1][0]
								}
								body := listing[section[1]:end]
								t.Run(name, func(t *testing.T) {
									var row int
									if _, err := fmt.Sscanf(name, "AbsAlignment%d_", &row); err != nil || row < 0 || row >= 6 {
										t.Fatal("unexpected physical object function", name, err)
									}
									pattern := `(?m)\b` + strings.ToLower(x86AbsSignAlignmentRows()[row].opcode) + `[ \t]+[^\r\n]*\([^\r\n]+\),[ \t]*%xmm[0-9]+`
									if count := len(regexp.MustCompile(pattern).FindAll(body, -1)); count != 1 {
										t.Fatalf("original faulting m128 opcode not retained exactly once: %d\n%s", count, body)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
