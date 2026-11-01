package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86OriginalFloatingPolicyFile(t *testing.T, path string) ([]byte, *ast.File, *token.FileSet) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("original floating allocation preflight is missing", path, err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	return data, file, set
}

func x86OriginalFloatingPolicyFunction(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == name {
			return function
		}
	}
	t.Fatal("original floating runtime owner disappeared", name)
	return nil
}

func x86OriginalFloatingPolicyConstants(t *testing.T, node ast.Node) map[string]string {
	t.Helper()
	result := make(map[string]string)
	ast.Inspect(node, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
			return true
		}
		literal, ok := value.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil || result[value.Names[0].Name] != "" {
			t.Fatal("ambiguous original floating runtime literal", err)
		}
		result[value.Names[0].Name] = text
		return true
	})
	return result
}

func TestX86OriginalFloatingRuntimeOwnersKeepAllocationPreflight(t *testing.T) {
	for _, owner := range []struct {
		file, root, profile, target, prefix, boundary string
	}{
		{"amd64_lower_vcvtss2sd_test.go", "TestAMD64ScalarPrecisionConvertRuntimeSemantics", "scalar-precision",
			"triple", "runPrefix", "compileAndRunRuntimeTestForTarget"},
		{"amd64_go_caller_fma3_runtime_test.go", "TestCrossLinuxRuntimeMatrixX86FMA3GoCallerNumericalFamily", "fma-caller",
			`testTargetTriple(runtime.GOOS, "amd64")`, "runner", "runX86FMA3GoCallerNumericalBatch"},
	} {
		t.Run(owner.profile, func(t *testing.T) {
			data, file, set := x86OriginalFloatingPolicyFile(t, owner.file)
			function := x86OriginalFloatingPolicyFunction(t, file, owner.root)
			constants := x86OriginalFloatingPolicyConstants(t, file)
			if owner.profile == "scalar-precision" {
				for name, expected := range map[string]string{
					"source": "55df95012f1cab5b5616e3c1a6a4921ab6af2ddb95381c11ee70198ca68882ab",
					"mainC":  "e2f9b43bb03c8ea3557f9fc78f758df91129771197e7efc46df6ae4d17d1320d",
				} {
					if fmt.Sprintf("%x", sha256.Sum256([]byte(constants[name]))) != expected {
						t.Fatal("original scalar precision ASM, C or samples changed", name)
					}
				}
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", "#include \"textflag.h\"\n"+constants["source"])
				original, err := Parse(ArchAMD64, constants["source"])
				if err != nil || len(original.Funcs) != 1 {
					t.Fatal("complete original scalar precision source changed", err)
				}
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", original.Funcs[0])
				if !strings.Contains(features, "+avx512f") {
					t.Fatal("original scalar precision lost its actual native ISA requirement", features)
				}
				for _, extra := range []string{"+avx512vl", "+avx512dq", "+avx512bw", "+fma"} {
					if strings.Contains(features, extra) {
						t.Fatal("scalar runtime borrowed a stronger ISA profile to hide an opcode error", features)
					}
				}
			} else {
				batch := x86OriginalFloatingPolicyFunction(t, file, owner.boundary)
				original := data[set.Position(batch.Pos()).Offset:set.Position(batch.End()).Offset]
				if fmt.Sprintf("%x", sha256.Sum256(original)) != "671c54ae2be89372425614cf9d9ef893080a25f929ad8e31d3087d69bbb927b7" ||
					fmt.Sprintf("%x", sha256.Sum256([]byte(constants["x86FMA3CallerCOracle"]))) != "e5e92fdff02fdf254f04b6dcf0a88ec120ff19d152f4ce4b7eddb7191d5f943e" ||
					len(x86FMA3NamedFormats("amd64")) != 1836 {
					t.Fatal("complete original FMA source builder, C, 1836 formats or samples changed")
				}
			}
			var calls []*ast.CallExpr
			boundary := function.End()
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, ok := call.Fun.(*ast.Ident)
				if ok && name.Name == "x86OriginalFloatingRuntimeRequireCPU" {
					calls = append(calls, call)
				}
				if ok && name.Name == owner.boundary && call.Pos() < boundary {
					boundary = call.Pos()
				}
				return true
			})
			if len(calls) != 1 || boundary == function.End() || calls[0].End() >= boundary {
				t.Fatal("original runtime must own one actual-allocation preflight before any original program executes")
			}
			topLevel := false
			for _, statement := range function.Body.List {
				if expression, ok := statement.(*ast.ExprStmt); ok && expression.X == calls[0] {
					topLevel = true
				}
			}
			if !topLevel {
				t.Fatal("actual allocation preflight must not be conditional, deferred or nested in another owner")
			}
			var actual bytes.Buffer
			if err := format.Node(&actual, set, calls[0]); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("x86OriginalFloatingRuntimeRequireCPU(t, %q, clang, %s, %s)", owner.profile, owner.target, owner.prefix)
			if actual.String() != want {
				t.Fatal("preflight substituted the original execution profile, compiler, target or runner", actual.String(), want)
			}
		})
	}
}

func x86OriginalFloatingPolicyDriver(t *testing.T) (string, string) {
	t.Helper()
	_, file, _ := x86OriginalFloatingPolicyFile(t, "x86_original_floating_runtime_preflight_test.go")
	constants := x86OriginalFloatingPolicyConstants(t, file)
	state, opcodes := constants["x86OriginalFloatingRuntimeStateC"], constants["x86OriginalFloatingRuntimeOpcodeC"]
	if state == "" || opcodes == "" {
		t.Fatal("complete original floating capability predicate or opcode preflight missing")
	}
	return state, opcodes
}

func TestX86OriginalFloatingRuntimeMinimumCapabilityBoundary(t *testing.T) {
	state, _ := x86OriginalFloatingPolicyDriver(t)
	_, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 clang required for independent capability boundary execution")
	}
	// This executes only the actual pure predicate on the actual host. The
	// synthetic rows never authorize the separate original native opcodes.
	const checks = `
int main(void) {
    for(unsigned profile=0;profile<8;profile++) for(unsigned flags=0;flags<64;flags++) {
        unsigned sse2=flags&1,avx=(flags>>1)&1,os=(flags>>2)&1;
        unsigned f=(flags>>3)&1,vl=(flags>>4)&1,fma=(flags>>5)&1;
        for(unsigned bits=0;bits<32;bits++) {
            const unsigned positions[]={1,2,5,6,7}; uint64_t xcr0=0;
            for(unsigned i=0;i<5;i++) if(bits&(1u<<i)) xcr0|=UINT64_C(1)<<positions[i];
            int expected=sse2&&avx&&os&&f&&bits==31&&
                         (profile==1||profile==3||profile==5||(profile==2&&vl&&fma)||((profile==4||profile==6)&&vl));
            if(original_floating_required_state(profile,sse2,avx,os,f,vl,fma,xcr0)!=expected ||
               original_floating_required_state(profile,sse2,avx,os,f,vl,fma,xcr0|0x101)!=expected) return 1;
        }
    }
    return 0;
}
`
	execution := x86FloatCompareExecution{triple: testTargetTriple(runtime.GOOS, runtime.GOARCH), compiler: []string{clang}}
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "capability.c"), filepath.Join(directory, "capability")
	if err := os.WriteFile(source, []byte(state+checks), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	execution.run(t, executable)
}

func TestX86OriginalFloatingRuntimeBaselineObjectsAndFaultBoundary(t *testing.T) {
	state, opcodes := x86OriginalFloatingPolicyDriver(t)
	data, file, _ := x86OriginalFloatingPolicyFile(t, "x86_original_floating_runtime_preflight_test.go")
	driver := x86OriginalFloatingPolicyFunction(t, file, "x86OriginalFloatingRuntimeRequireCPU")
	var rendered bytes.Buffer
	if err := format.Node(&rendered, token.NewFileSet(), driver); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{".Skip(", "-mavx", "-march=", "x86FloatCompareRuntimeTools"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("actual CPU diagnostic was replaced by a skip, Linux-only owner or nonbaseline compilation", forbidden)
		}
	}
	compact := strings.Join(strings.Fields(rendered.String()), "")
	for _, required := range []string{"compileC(t,", "runtimeOracleCombinedOutput(ctx,exec.CommandContext(ctx,", "runtimeOracleStageContext(t)", "prefix:prefix", "triple:triple"} {
		if !strings.Contains(compact, required) {
			t.Fatal("preflight lost its original owned execution route", required)
		}
	}
	// The explicit auto policy can skip only the classified capability exit.
	// Keep every other compiler, opcode, execution and cleanup failure fatal.
	if strings.Count(string(data), ".Skipf(") != 1 ||
		!strings.Contains(compact, "ifx86OriginalFloatingRuntimeAllowsSkip(mode,required,output,err){t.Skipf(") ||
		!strings.Contains(compact, "iferr!=nil{t.Fatalf(") {
		t.Fatal("optional hardware execution bypassed its receipt or failure boundary")
	}
	start := strings.LastIndex(opcodes, "int main(void)")
	if start < 0 {
		t.Fatal("actual native preflight main is missing")
	}
	main := opcodes[start:]
	flush, guard := strings.Index(main, "fflush(stdout);"), strings.Index(main, "if (!original_floating_required_state(")
	if flush < 0 || guard <= flush || strings.Index(main[guard:], "return 78;") < 0 {
		t.Fatal("real CPU receipt must precede the mandatory missing-capability failure")
	}
	for _, opcode := range []string{"original_scalar_precision()", "original_fma_caller()", "original_unsigned_scalar_integer()", "original_packed_abs_sign()"} {
		if at := strings.Index(main, opcode); at <= guard {
			t.Fatal("original opcode executes before its actual feature/OS-state proof", opcode)
		}
	}
	for _, required := range []string{"__get_cpuid(1", "__get_cpuid_count(7,0", "if (osxsave)", "xgetbv",
		"AVX512F=%u", "AVX512VL=%u", "FMA=%u", "XCR0=%llx", "vcvtsd2ss", "vcvtss2sd", "vfmadd"} {
		if !strings.Contains(opcodes, required) {
			t.Fatal("actual CPUID/OS-state or original opcode diagnostic is incomplete", required)
		}
	}
	_, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 clang required for baseline preflight objects")
	}
	for _, target := range []struct {
		triple  string
		windows bool
	}{
		{"x86_64-unknown-linux-gnu", false}, {"x86_64-apple-darwin", false}, {"x86_64-pc-windows-msvc", true},
	} {
		t.Run(target.triple, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, "sys"), 0700); err != nil {
				t.Fatal(err)
			}
			resource := "struct rlimit { unsigned long rlim_cur,rlim_max; };\n#define RLIMIT_CORE 917\nint setrlimit(int,const struct rlimit*);\n"
			if target.windows {
				resource = "#error original_floating_windows_must_not_include_posix_resource\n"
			}
			for name, contents := range map[string]string{
				"stdint.h":       "typedef unsigned int uint32_t; typedef unsigned long long uint64_t;\n#define UINT64_C(v) v##ULL\n",
				"stdio.h":        "typedef struct FILE FILE; extern FILE *stdout; int printf(const char*,...); int fflush(FILE*); int puts(const char*);\n",
				"cpuid.h":        "int __get_cpuid(unsigned,unsigned*,unsigned*,unsigned*,unsigned*); int __get_cpuid_count(unsigned,unsigned,unsigned*,unsigned*,unsigned*,unsigned*);\n",
				"sys/resource.h": resource,
			} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for caseID := 0; caseID < 12; caseID++ {
				profile, level := caseID%6+1, []string{"-O0", "-O2"}[caseID/6]
				source, object := filepath.Join(directory, "preflight.c"), filepath.Join(directory, "preflight.o")
				program := fmt.Sprintf("#define REQUIRED_PROFILE %d\n", profile) + state + opcodes
				if err := os.WriteFile(source, []byte(program), 0600); err != nil {
					t.Fatal(err)
				}
				for _, ir := range []bool{false, true} {
					output := object
					args := []string{"-target", target.triple, "-nostdinc", "-I", directory, level, "-c"}
					if ir {
						output = filepath.Join(directory, "preflight.ll")
						args = append(args, "-S", "-emit-llvm")
					}
					args = append(args, source, "-o", output)
					ctx, cancel := runtimeOracleStageContext(t)
					observed, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, clang, args...))
					cancel()
					if err != nil {
						t.Fatalf("complete baseline preflight profile%d %s: %v\n%s", profile, level, err, observed)
					}
					payload, err := os.ReadFile(output)
					if err != nil || len(payload) == 0 {
						t.Fatal("actual preflight compiler object/IR missing", err)
					}
					if ir {
						identity := regexp.MustCompile(`(?m)^define [^\n]*@main\([^\n]* #([0-9]+)`).FindSubmatch(payload)
						if len(identity) != 2 {
							t.Fatal("actual preflight main lost its independent baseline feature group")
						}
						group := regexp.MustCompile(`(?m)^attributes #` + string(identity[1]) + ` = [^\n]*`).Find(payload)
						if len(group) == 0 || bytes.Contains(group, []byte("+avx")) || bytes.Contains(group, []byte("+fma")) {
							t.Fatal("preflight main can fault before its CPUID/OS-state guard", string(group))
						}
						if profile >= 3 && profile <= 6 {
							name := "original_unsigned_scalar_integer"
							required := []string{"+avx512f"}
							forbidden := []string{"+avx512vl", "+avx512dq", "+avx512bw"}
							opcodes := []string{"vcvtusi2sdl ", "vcvtusi2sdq ", "vcvtusi2ssl ", "vcvtusi2ssq "}
							if profile == 4 {
								name = "original_packed_abs_sign"
								required = append(required, "+avx512vl", "+ssse3", "+avx2")
								forbidden = []string{"+avx512dq", "+avx512bw"}
								opcodes = []string{"vpabsb ", "psignw ", "vpsignd ", "vpabsd ", "vpabsq "}
							}
							if profile == 5 || profile == 6 {
								name = "original_estimate14_f"
								opcodes = []string{"vrcp14ps ", "vrcp14pd ", "vrsqrt14ps ", "vrsqrt14pd ",
									"vrcp14ss ", "vrcp14sd ", "vrsqrt14ss ", "vrsqrt14sd "}
								if profile == 6 {
									name = "original_estimate14_fvl"
									required = append(required, "+avx512vl")
									forbidden = []string{"+avx512dq", "+avx512bw"}
									opcodes = opcodes[:4]
								}
							}
							probe := regexp.MustCompile(`(?m)^define [^\n]*@` + name + `\([^\n]* #([0-9]+)`).FindSubmatch(payload)
							if len(probe) != 2 {
								t.Fatal("actual original-opcode function is missing from the compiled baseline driver", name)
							}
							probeGroup := regexp.MustCompile(`(?m)^attributes #` + string(probe[1]) + ` = [^\n]*`).Find(payload)
							for _, feature := range required {
								if !bytes.Contains(probeGroup, []byte(feature)) {
									t.Fatal("actual original-opcode probe lost its independent minimum ISA", name, feature, string(probeGroup))
								}
							}
							for _, feature := range forbidden {
								if bytes.Contains(probeGroup, []byte(feature)) {
									t.Fatal("original-opcode probe borrowed a stronger ISA", name, feature, string(probeGroup))
								}
							}
							for _, opcode := range opcodes {
								if !bytes.Contains(payload, []byte(opcode)) {
									t.Fatal("compiled actual probe lost an original opcode", name, opcode)
								}
							}
						}
					}
				}
			}
		})
	}
}
