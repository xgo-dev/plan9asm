package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoModuleOrdinaryGlobalVectorReads(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	t.Run("logical", func(t *testing.T) {
		ordinaryGlobalLogicalRuntime(t, execution)
	})
	t.Run("AES", func(t *testing.T) {
		ordinaryGlobalAESRuntime(t, execution)
	})
}

func ordinaryGlobalLogicalRuntimeFixtures(t *testing.T) []x86LogicalRuntimeFixture {
	t.Helper()
	var fixtures []x86LogicalRuntimeFixture
	for _, fixture := range x86LogicalRuntimeFixtures(t) {
		// Register-source fixtures also load their setup value from (BX).
		// Select the logical operation itself, never that unrelated load.
		lines := strings.Split(fixture.assembly, "\n")
		selected := -1
		for index, line := range lines {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			opcode := Op(strings.Split(fields[0], ".")[0])
			if _, logical := x86PackedLogicalSpecs[opcode]; !logical || !strings.HasPrefix(fields[1], "(BX),") {
				continue
			}
			if selected >= 0 {
				t.Fatal("fixture contains more than one logical source", fixture.name)
			}
			selected = index
		}
		if selected < 0 {
			continue
		}
		lines[selected] = strings.Replace(lines[selected], "(BX)", "·words+64(SB)", 1)
		fixture.assembly = strings.Join(lines, "\n")
		fixture.assembly = strings.Replace(fixture.assembly,
			"TEXT "+fixture.name+"(SB)", "TEXT ·"+fixture.name+"(SB)", 1)
		call := "  " + fixture.name + "(output+1,a,b,mask);"
		if strings.Count(fixture.checks, call) != 1 {
			t.Fatal("the complete independent logical oracle call changed", fixture.name)
		}
		fixture.checks = strings.Replace(fixture.checks, call, `
  memset(globalWords, 0xc7, sizeof(globalWords));
  memcpy(globalWords + 64, a, 64);
`+call+`
  if (memcmp(globalWords + 64, a, 64)) return 1;
  for (int i = 0; i < 64; i++) {
      if (globalWords[i] != 0xc7 || globalWords[128 + i] != 0xc7) return 1;
  }
`, 1)
		fixtures = append(fixtures, fixture)
	}
	if len(fixtures) != 308 {
		t.Fatal("complete logical memory-source execution union changed", len(fixtures))
	}
	return fixtures
}

func TestGoModuleOrdinaryGlobalLogicalRuntimeFixtureSelection(t *testing.T) {
	for _, fixture := range ordinaryGlobalLogicalRuntimeFixtures(t) {
		if strings.Contains(fixture.assembly, "(BX)") ||
			strings.Count(fixture.assembly, "·words+64(SB)") != 1 ||
			!strings.HasPrefix(fixture.assembly, "TEXT ·"+fixture.name+"(SB)") {
			t.Fatal("global runtime fixture changed setup memory or lost its Go declaration", fixture.name)
		}
	}
}

func ordinaryGlobalLogicalRuntime(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	fixtures := ordinaryGlobalLogicalRuntimeFixtures(t)
	// Retain the existing independent all-byte, mask, FLAGS and alias oracle.
	// Only its first numerical input is now the same mutable Go global across
	// repeated calls; no source observation or SDK capability is fabricated.
	for start := 0; start < len(fixtures); start += 32 {
		end := start + 32
		if end > len(fixtures) {
			end = len(fixtures)
		}
		t.Run(fmt.Sprintf("batch-%02d", start/32), func(t *testing.T) {
			batch := fixtures[start:end]
			var source, declarations, wrappers strings.Builder
			declarations.WriteString("var words [192]byte\n")
			for _, fixture := range batch {
				source.WriteString(fixture.assembly)
				fmt.Fprintf(&declarations, "func %s(out *[65]byte,a,b *[64]byte,mask uint64)\n", fixture.name)
				fmt.Fprintf(&wrappers, `
define void @%s(ptr %%out, ptr %%a, ptr %%b, i64 %%mask) {
  call void %s(ptr %%out, ptr %%a, ptr %%b, i64 %%mask)
  ret void
}
`, fixture.name, llvmGlobal("ordinaryglobals."+fixture.name))
			}
			goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
			global := fmt.Sprintf("_Alignas(64) unsigned char globalWords[192] __asm__(%q);\n",
				ordinaryGlobalVectorNativeSymbol("words"))
			driver := global + x86LogicalRuntimeC(batch)
			ordinaryGlobalVectorExecute(t, execution, source.String(), declarations.String(), wrappers.String(), driver)
		})
	}
	t.Log("308 logical global-source functions x16 independent full-byte/mask inputs; preserved inputs, FLAGS, wider aliases and global canaries")
}

func ordinaryGlobalAESRuntime(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	rows := ordinaryGlobalAESCases()
	if len(rows) != 20 {
		t.Fatal("complete AES memory-source execution union changed", len(rows))
	}
	source, declarations := ordinaryGlobalVectorSource(rows)
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	var prototypes, table strings.Builder
	for index, row := range rows {
		name := strings.Fields(row.instruction)[0]
		operation := -1
		for candidate, original := range x86AESOracleNames {
			if name == original {
				operation = candidate % 6
			}
		}
		if operation < 0 {
			t.Fatal("unknown independent AES operation", row.instruction)
		}
		fmt.Fprintf(&prototypes, "extern uint32_t vector%d(void) __asm__(%q);\n", index,
			ordinaryGlobalVectorNativeSymbol(fmt.Sprintf("vector%d", index)))
		fmt.Fprintf(&table, "    {vector%d, %d},\n", index, operation)
	}
	driver := x86AESIndependentC + prototypes.String() + fmt.Sprintf(`
_Alignas(64) unsigned char globalWords[96] __asm__(%q);
struct kernel { uint32_t (*run)(void); unsigned operation; };
static const struct kernel kernels[] = {
%s};

int main(void) {
    for (unsigned sample = 0; sample < 37; sample++) {
        for (unsigned i = 0; i < sizeof(globalWords); i++)
            globalWords[i] = (uint8_t)(sample * 19 + i * 37);
        uint8_t before[96];
        memcpy(before, globalWords, sizeof(before));
        for (unsigned k = 0; k < sizeof(kernels) / sizeof(kernels[0]); k++) {
            uint8_t state[16] = {0}, expected[16];
            aes(expected, state, globalWords + 16, kernels[k].operation, 27);
            uint32_t want;
            memcpy(&want, expected, sizeof(want));
            if (kernels[k].run() != want || memcmp(before, globalWords, sizeof(before))) {
                fprintf(stderr, "mutable AES global mismatch sample=%%u kernel=%%u\n", sample, k);
                return 1;
            }
        }
    }
    return 0;
}
`, ordinaryGlobalVectorNativeSymbol("words"), table.String())
	ordinaryGlobalVectorExecute(t, execution, source, declarations, "", driver)
	t.Log("20 AES/VAES memory-source functions x37 mutable inputs; independent FIPS byte oracle and complete source immutability")
}

func ordinaryGlobalVectorNativeSymbol(name string) string {
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	return prefix + "ordinaryglobals." + name
}

func ordinaryGlobalVectorExecute(t *testing.T, execution x86FloatCompareExecution,
	source, declarations, wrappers, driver string,
) {
	t.Helper()
	for _, api := range []string{"public", "owned-context"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			pkg.Path = "ordinaryglobals"
			ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			ir += wrappers
			for _, pipeline := range []struct{ name, text, level string }{
				{"backend_O0", ir, "-O0"},
				{"IR_O2/backend_O2", x86MulDivRoundOptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					execution.compileAndRunLLVM(t, "ordinary-global-vector", pipeline.text, driver, pipeline.level)
				})
			}
		})
	}
}
