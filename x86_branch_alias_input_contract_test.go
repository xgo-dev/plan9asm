package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func x86ConditionalBranchAliasOracle() map[string]string {
	groups := map[string][]string{
		"JCC": {"JAE", "JCC", "JHS", "JNB", "JNC"},
		"JCS": {"JB", "JC", "JCS", "JLO", "JNAE"},
		"JEQ": {"JE", "JEQ", "JZ"},
		"JGE": {"JGE", "JNL"},
		"JGT": {"JG", "JGT", "JNLE"},
		"JHI": {"JA", "JHI", "JNBE"},
		"JLE": {"JLE", "JNG"},
		"JLS": {"JBE", "JLS", "JNA"},
		"JLT": {"JL", "JLT", "JNGE"},
		"JMI": {"JMI", "JS"},
		"JNE": {"JNE", "JNZ"},
		"JOC": {"JNO", "JOC"},
		"JOS": {"JO", "JOS"},
		"JPC": {"JNP", "JPC", "JPO"},
		"JPL": {"JNS", "JPL"},
		"JPS": {"JP", "JPE", "JPS"},
	}
	aliases := make(map[string]string)
	for canonical, names := range groups {
		for _, name := range names {
			aliases[name] = canonical
		}
	}
	return aliases
}

func x86ConditionalBranchAliasOriginalSource() string {
	aliases := x86ConditionalBranchAliasOracle()
	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Strings(names)

	var source strings.Builder
	source.WriteString("TEXT conditionalbranchaliases(SB),NOSPLIT,$0-0\n")
	source.WriteString("\tUCOMISD X0, X1\n")
	for index, name := range names {
		for hint := -1; hint <= 1; hint++ {
			label := fmt.Sprintf("branch_alias_%d_%d", index, hint+1)
			if hint < 0 {
				fmt.Fprintf(&source, "\t%s %s\n", name, label)
			} else {
				fmt.Fprintf(&source, "\t%s $%d, %s\n", name, hint, label)
			}
			fmt.Fprintf(&source, "%s:\n", label)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestX86ConditionalBranchAliasIndependentCompleteGoInventory(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	grammar := "var yjcond = []ytab{\n\t{Zbr, 0, argList{Ybr}},\n\t{Zbr, 0, argList{Yi0, Ybr}},\n\t{Zbr, 1, argList{Yi1, Ybr}},\n}"
	if !strings.Contains(string(data), grammar) {
		t.Fatal("complete Go conditional branch target/hint grammar changed")
	}
	wantEncoders := map[string]string{
		"JCC": "0x73,0x83,00",
		"JCS": "0x72,0x82",
		"JEQ": "0x74,0x84",
		"JGE": "0x7d,0x8d",
		"JGT": "0x7f,0x8f",
		"JHI": "0x77,0x87",
		"JLE": "0x7e,0x8e",
		"JLS": "0x76,0x86",
		"JLT": "0x7c,0x8c",
		"JMI": "0x78,0x88",
		"JNE": "0x75,0x85",
		"JOC": "0x71,0x81,00",
		"JOS": "0x70,0x80,00",
		"JPC": "0x7b,0x8b",
		"JPL": "0x79,0x89",
		"JPS": "0x7a,0x8a",
	}
	rows := regexp.MustCompile(`\{A(J[A-Z]+),\s*yjcond,\s*([A-Za-z0-9_]+),\s*opBytes\{([^}]*)\}\}`).FindAllStringSubmatch(string(data), -1)
	encoders := make(map[string]string)
	aliases := make(map[string]string)
	for _, row := range rows {
		if row[2] != "Px" {
			t.Fatal("conditional branch encoder prefix changed", row)
		}
		encoders[row[1]] = strings.Join(strings.Fields(row[3]), "")
		aliases[row[1]] = row[1]
	}
	if len(rows) != 16 || !reflect.DeepEqual(encoders, wantEncoders) {
		t.Fatal("complete sixteen-row conditional branch encoder directory changed", encoders)
	}

	frontend, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	registrations := regexp.MustCompile(`instructions\["(J[A-Z]+)"\]\s*=\s*x86\.A(J[A-Z]+)`).FindAllStringSubmatch(string(frontend), -1)
	for _, registration := range registrations {
		if _, conditional := encoders[registration[2]]; conditional {
			aliases[registration[1]] = registration[2]
		}
	}
	if len(aliases) != 45 || !reflect.DeepEqual(aliases, x86ConditionalBranchAliasOracle()) {
		t.Fatal("complete original Go conditional branch aliases changed", aliases)
	}

	file, err := Parse(ArchAMD64, x86ConditionalBranchAliasOriginalSource())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string][3]int)
	for _, instruction := range file.Funcs[0].Instrs {
		if _, conditional := aliases[string(instruction.Op)]; !conditional {
			continue
		}
		form := 0
		if len(instruction.Args) == 2 {
			hint := instruction.Args[0]
			if hint.Kind != OpImm || hint.ImmIsFloat || hint.ImmRaw != "" || hint.Imm < 0 || hint.Imm > 1 {
				t.Fatal("branch fixture contains a non-Go hint", instruction.Raw)
			}
			form = int(hint.Imm) + 1
		} else if len(instruction.Args) != 1 {
			t.Fatal("branch fixture lost its target operand", instruction.Raw)
		}
		count := counts[string(instruction.Op)]
		count[form]++
		counts[string(instruction.Op)] = count
	}
	if len(counts) != 45 {
		t.Fatal("complete branch fixture lost an alias", counts)
	}
	for alias, count := range counts {
		if count != [3]int{1, 1, 1} {
			t.Fatal("branch fixture must retain every alias/hint exactly once", alias, count)
		}
	}
}

// This private format object emits the unchanged original CFG without claiming
// initialized entry inputs. Its public APIs must independently retain Context.
func x86ConditionalBranchAliasOriginalFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	if source != x86ConditionalBranchAliasOriginalSource() {
		t.Fatal("original conditional branch source or complete 135-row inventory changed")
	}
	file, signatures := x86UnboundVoidFormatSource(t, source, "conditionalbranchaliases", arch, triple)
	function := file.Funcs[0]
	signature := signatures["conditionalbranchaliases"]
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\n", triple)
	emitAMD64Prelude(&ir, arch, file)
	attributes := newFeatureAttrRegistry()
	features := attributes.ref(inferFuncTargetFeaturesForGOARCH(file.Arch, arch, function))
	fmt.Fprintf(&ir, "define void @ConditionalBranchAliasFormats() %s {\n", features)
	consumer := newX86Ctx(&ir, function, signature, func(name string) string { return name }, signatures, arch, triple, false)
	if err := consumer.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	if err := consumer.lowerBlocks(); err != nil {
		t.Fatal("original named branch CFG format was not emitted", err)
	}
	ir.WriteString("}\n")
	attributes.emit(&ir)
	if strings.Count(ir.String(), "  br i1 ") != 135 || strings.Count(ir.String(), `asm sideeffect "ucomisd `) != 1 {
		t.Fatal("original private format object lost a branch or its native FLAGS producer")
	}
	return ir.String()
}

func TestX86ConditionalBranchAliasOriginalAndInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	original := x86ConditionalBranchAliasOriginalSource()
	initialized := strings.Replace(original, "\tUCOMISD X0, X1\n", "\tPXOR X0, X0\n\tPXOR X1, X1\n\tUCOMISD X0, X1\n", 1)
	declaration := "func conditionalbranchaliases()\n"
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			ir := x86ConditionalBranchAliasOriginalFormatObject(t, original, target.arch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "original-branch-alias-formats.ll", "original-branch-alias-formats.o", ir)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, "#include \"textflag.h\"\n"+initialized)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, initialized, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized branch source rejected", err)
					}
					if strings.Count(ir, "  br i1 ") != 135 || strings.Count(ir, `asm sideeffect "ucomisd `) != 1 {
						t.Fatal("initialized public object lost an original branch or native FLAGS producer")
					}
					compileLLVMToObject(t, llc, target.triple, "initialized-branch-aliases.ll", "initialized-branch-aliases.o", ir)
				})
			}
		})
	}
}

func TestX86ConditionalBranchAliasFullSourceDoesNotInventCOMIInputs(t *testing.T) {
	original := x86ConditionalBranchAliasOriginalSource()
	for _, target := range x86RawReturnTargets {
		for _, input := range []struct {
			name, setup string
		}{
			{"neither", ""},
			{"only-X0", "\tPXOR X0, X0\n"},
			{"only-X1", "\tPXOR X1, X1\n"},
		} {
			source := strings.Replace(original, "\tUCOMISD X0, X1\n", input.setup+"\tUCOMISD X0, X1\n", 1)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+input.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func conditionalbranchaliases()\n", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("complete branch source invented a missing COMI scalar input", err)
					}
				})
			}
		}
	}
}
