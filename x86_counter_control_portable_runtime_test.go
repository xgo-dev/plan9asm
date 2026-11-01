package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86CounterPortableProgram struct {
	fixture               x86GPFaultingFixture
	kind                  int
	half, back, fromCount bool
}

func x86CounterPortablePrograms(arch string) []x86CounterPortableProgram {
	word, move, suffix, typ := 8, "MOVQ", "Q", "uint64"
	if arch == "386" {
		word, move, suffix, typ = 4, "MOVL", "L", "uint32"
	}
	var programs []x86CounterPortableProgram
	for _, row := range x86CounterControlOracle {
		for _, back := range []bool{false, true} {
			if back && !row.decrement {
				continue
			}
			for _, fromCount := range []bool{false, true} {
				name := fmt.Sprintf("PortableCounter%d", len(programs))
				fixture := x86CounterControlSource(arch, row.op, name, "", back, true)
				// The runtime oracle observes only scalar arguments. It needs
				// neither a synthetic pointer nor a memory-read trigger: the
				// complete counter effect already requires its NUM inputs.
				memory := fmt.Sprintf("%s p+%d(FP),SI\nMOVL (SI),DI\n", move, 2*word)
				if strings.Count(fixture.source, memory) != 1 {
					panic("counter oracle lost its exact memory prologue")
				}
				fixture.source = strings.Replace(fixture.source, memory, "", 1)
				fixture.source = strings.Replace(fixture.source, fmt.Sprintf("$0-%d\n", 4*word), fmt.Sprintf("$0-%d\n", 3*word), 1)
				fixture.source = strings.Replace(fixture.source, fmt.Sprintf("ret+%d(FP)", 3*word), fmt.Sprintf("ret+%d(FP)", 2*word), 1)
				fixture.declaration = fmt.Sprintf("func %s(count,seed %s) %s", name, typ, typ)
				if fromCount {
					fixture.source = strings.Replace(fixture.source, "CMP"+suffix+" AX,$0\n", "CMP"+suffix+" CX,$0\n", 1)
				}
				kind := 0
				switch row.op {
				case "LOOP":
					kind = 1
				case "LOOPEQ":
					kind = 2
				case "LOOPNE":
					kind = 3
				}
				programs = append(programs, x86CounterPortableProgram{fixture, kind, row.halfCounter, back, fromCount})
			}
		}
	}
	return programs
}

func x86CounterPortableDriver(t *testing.T, ir, arch string, programs []x86CounterPortableProgram) string {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if err != nil {
		t.Fatal(err)
	}
	defer module.Dispose()
	names := make(map[string]string)
	for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
		if function.FirstBasicBlock().IsNil() {
			continue
		}
		for _, program := range programs {
			name := program.fixture.name
			if function.Name() == name || strings.HasSuffix(function.Name(), "."+name) {
				if names[name] != "" {
					t.Fatal("ambiguous actual counter function", name)
				}
				names[name] = function.Name()
			}
		}
	}
	if len(names) != len(programs) {
		t.Fatal("runtime oracle lost an actual complete source function", len(names), len(programs))
	}
	word, bits := "unsigned long long", 64
	if arch == "386" {
		word, bits = "unsigned int", 32
	}
	var source strings.Builder
	source.WriteString(runtimeCAsmLabelPreamble)
	fmt.Fprintf(&source, "typedef %s Word;\nextern int printf(const char*,...);\n", word)
	for index, program := range programs {
		symbol := names[program.fixture.name]
		if runtime.GOOS == "darwin" {
			symbol = "_" + symbol // __asm__ names the actual Mach-O linker symbol.
		}
		fmt.Fprintf(&source, "extern Word function%d(Word,Word) __asm__(%s);\n", index, runtimeCAsmLabel(symbol))
	}
	source.WriteString("struct Case { Word(*function)(Word,Word); int kind,half,back,from_count; };\nstatic const struct Case cases[]={\n")
	for index, program := range programs {
		bit := func(value bool) int {
			if value {
				return 1
			}
			return 0
		}
		fmt.Fprintf(&source, "{function%d,%d,%d,%d,%d},\n", index, program.kind, bit(program.half), bit(program.back), bit(program.fromCount))
	}
	source.WriteString("};\n")
	fmt.Fprintf(&source, "enum { WORD_BITS=%d };\n", bits)
	// This independent scalar reference caches the original comparison flags.
	// In particular, decrementing CX never recomputes ZF or clears STC's CF.
	source.WriteString(`
static Word reference(const struct Case *c, Word count, Word seed) {
    unsigned zf=c->from_count ? count==0 : seed==0;
    Word marker;
    if (!c->kind) {
        Word mask=c->half ? (((Word)1<<(WORD_BITS/2))-1) : ~(Word)0;
        marker=(count&mask)==0 ? 100 : 200;
    } else if (c->back) {
        marker=0;
        do {
            marker++;
            count--;
        } while (count && (c->kind==1 || (c->kind==2 ? zf : !zf)));
    } else {
        count--;
        unsigned taken=count && (c->kind==1 || (c->kind==2 ? zf : !zf));
        marker=taken ? 100 : 200;
    }
    return marker+count*4+1+zf*2;
}
int main(void) {
    static const unsigned long long inputs[]={
        0,1,2,3,17,0xffff,0x10000,0xffffffffULL,
        0x100000000ULL,0x8000000000000000ULL,0xffffffffffffffffULL
    };
    unsigned checked=0;
    for (unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        for (unsigned j=0;j<sizeof(inputs)/sizeof(inputs[0]);j++) {
            Word count=(Word)inputs[j];
            if (cases[i].back && (count==0 || count>17)) continue;
            for (Word seed=0;seed<2;seed++) {
                Word want=reference(&cases[i],count,seed);
                Word got=cases[i].function(count,seed);
                if (got!=want) {
                    printf("case=%u count=%llx seed=%llu got=%llx want=%llx\n",
                           i,(unsigned long long)count,(unsigned long long)seed,
                           (unsigned long long)got,(unsigned long long)want);
                    return 1;
                }
                checked++;
            }
        }
    }
    printf("COUNTER_RUNTIME checked=%u\n",checked);
    return checked==312 ? 0 : 2;
}
`)
	return source.String()
}

func TestX86CounterControlPortableRuntime(t *testing.T) {
	llc, clang := findLLVM22Tool("llc"), findLLVM22Tool("clang")
	if llc == "" || clang == "" {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, arch := range []string{"amd64", "386"} {
		programs := x86CounterPortablePrograms(arch)
		var fixtures []x86GPFaultingFixture
		var assembly, declarations strings.Builder
		for _, program := range programs {
			fixtures = append(fixtures, program.fixture)
			assembly.WriteString(program.fixture.source)
			declarations.WriteString(program.fixture.declaration + "\n")
		}
		x86CounterControlGoObjects(t, arch, fixtures)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized portable counter program rejected", err)
				}
				driver := x86CounterPortableDriver(t, ir, arch, programs)
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(level, func(t *testing.T) {
						directory := t.TempDir()
						input, main := filepath.Join(directory, "counter.ll"), filepath.Join(directory, "counter.c")
						object, executable := filepath.Join(directory, "counter.o"), filepath.Join(directory, "counter")
						if runtime.GOOS == "windows" {
							executable += ".exe"
						}
						for path, contents := range map[string]string{input: ir, main: driver} {
							if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
								t.Fatal(err)
							}
						}
						x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+triple, "-relocation-model=pic", "-filetype=obj", input, "-o", object))
						ctx, cancel := runtimeOracleStageContext(t)
						defer cancel()
						process := runtimeOracleProcessSource(t, directory)
						x86FloatCompareCaptureCommand(t, runtimeOracleNativeCCommand(t, ctx, clang, level, object, main, process, "-o", executable))
						output := x86FloatCompareCaptureCommand(t, exec.Command(executable))
						if strings.TrimSpace(string(output)) != "COUNTER_RUNTIME checked=312" {
							t.Fatal("independent counter runtime did not complete every bounded input", string(output))
						}
						t.Logf("COUNTER_EXECUTED source=%s host=%s api=%s level=%s cases=312", arch, triple, api, level)
					})
				}
			})
		}
	}
}
