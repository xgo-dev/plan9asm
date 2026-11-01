package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86SourceStackRuntimeDeclarations(arch string) string {
	var declaration strings.Builder
	for _, row := range x86SourceStackRuntimeCases(arch) {
		fmt.Fprintf(&declaration, "func %s(x uint%d) uint%d\n", row.name, row.width, row.width)
	}
	declaration.WriteString("func PhysicalBool(x bool) bool\n")
	declaration.WriteString("func PhysicalBoolIntermediate(x bool) bool\n")
	declaration.WriteString("func PhysicalBoolNamedFP(x bool) bool\n")
	return declaration.String()
}

// Share every original CI kernel, including its physical loads, frame-pointer
// transport, private PUSH/POP, branch join and saved FLAGS. This object owner
// cannot disappear merely because native x86 execution is inapplicable here.
func TestX86PhysicalSourceStackScalarRuntimeSourceThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, _ := x86SourceStackRuntimeSource(target.arch)
			declaration := x86SourceStackRuntimeDeclarations(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete physical source stack lost its independent numerical proof", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86PhysicalSourceStackScalarDoesNotInventDataOrStorage(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix, typ, resultType := int64(8), "Q", "uint64", I64
		if target.arch == "386" {
			word, suffix, typ, resultType = 4, "L", "uint32", I32
		}
		read := "MOV" + suffix + " @WORD(SP),AX\n"
		write := "MOV" + suffix + " AX,@RESULT(SP)\nBYTE $0xc3"
		for _, row := range []struct{ name, body string }{
			{"unknown-result", "MOV" + suffix + " BX,@RESULT(SP)\nBYTE $0xc3"},
			{"partial-result", read + "MOVB AX,@RESULT(SP)\nBYTE $0xc3"},
			{"unknown-wide-arithmetic", "MOVB @WORD(SP),AX\nADD" + suffix + " $7,AX\n" + write},
			{"unknown-saved-data", "PUSH" + suffix + " BX\nPOP" + suffix + " AX\n" + write},
			{"unknown-flags", read + "CMP" + suffix + " BX,$0\nJE done\ndone:\n" + write},
			{"unknown-result-on-one-path", read + "CMP" + suffix + " AX,$0\nJE done\nMOV" + suffix + " AX,@RESULT(SP)\ndone:\nBYTE $0xc3"},
			{"input-write", read + "MOV" + suffix + " AX,@WORD(SP)\n" + write},
			{"return-pc-write", read + "MOV" + suffix + " AX,0(SP)\n" + write},
			{"numerical-stack-address", "MOV" + suffix + " SP,AX\n" + write},
			{"unknown-native-store", read + "MOV" + suffix + " AX,(BX)\n" + write},
		} {
			source, _, _ := x86SourceStackTypedFixture(target.arch, typ, resultType, word, "MOV"+suffix, row.body)
			declaration := "func Value(x " + typ + ") " + typ
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("physical storage created unrelated numerical/address facts: %v", err)
					}
				})
			}
		}
	}
}

func TestX86PhysicalSourceStackScalarProofCannotBeRebound(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		source, sig, _ := x86SourceStackNumericalFixture(arch,
			"@MOV @WORD(SP),AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, arch, x86SourceStackOptions(arch, "", sig))
		if err != nil {
			t.Fatal(err)
		}
		original := normalized.Funcs[0]
		if original.x86SourceStack == nil || original.x86SourceStack.scalarResult == nil {
			t.Fatal("complete physical scalar source did not produce its own numerical proof")
		}
		for _, change := range []string{"none", "source", "access", "signature", "emitted signature", "copied owner"} {
			t.Run(arch+"/"+change, func(t *testing.T) {
				fn := original
				fn.Instrs = cloneX86ReplayInstrs(original.Instrs)
				signatures, err := cloneFixedLocalSigs(map[string]FuncSig{sig.Name: sig})
				if err != nil {
					t.Fatal(err)
				}
				consumer := &amd64Ctx{sig: sig, fpSourceSig: signatures[sig.Name], fpScalarSource: fn,
					sourceStack: fn.x86SourceStack, goarch: arch}
				switch change {
				case "source":
					consumer.fpScalarSource.Instrs[1].Raw = "MOVL $0,AX"
				case "access":
					consumer.fpScalarSource.Instrs[1].x86SourceStackFP[0]++
				case "signature":
					consumer.fpSourceSig.Frame.Results[0].Offset++
				case "emitted signature":
					consumer.sig.Ret = I8
				case "copied owner":
					copy := *consumer.sourceStack
					consumer.sourceStack = &copy
					consumer.fpScalarSource.x86SourceStack = &copy
				}
				err = consumer.checkSourceStackScalarResultInitialization()
				if change == "none" && err != nil || change != "none" && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("physical scalar proof rebound by %s: %v", change, err)
				}
			})
		}
	}
}

func TestX86PhysicalSourceStackScalarJoinOnlyIntersectsFacts(t *testing.T) {
	source, sig, _ := x86SourceStackNumericalFixture("amd64",
		"@MOV @WORD(SP),AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	initial := x86SourceStackScalarInitial(file.Funcs[0], sig, "amd64")
	if initial == nil {
		t.Fatal("complete scalar declaration rejected")
	}
	left := x86SourceStackState{sp: -8, bp: x86SourceStackAddress{original: true}, gOriginal: true,
		scalarResult: initial, numericFlags: true,
		cells: []x86SourceStackCell{{offset: -8, width: 8, flags: true, known: 0x3f,
			canonical: 0x0f, scalarFlags: x86ByteFlagsAll, numericFlags: true}}}
	right := left
	right.scalarResult = initial.clone()
	right.cells = append([]x86SourceStackCell(nil), left.cells...)
	left.scalarResult.bytes.gp[0], right.scalarResult.bytes.gp[0] = 0x0f, 0xf0
	left.scalarResult.bytes.flags, right.scalarResult.bytes.flags = x86ByteFlagsAll, x86ByteFlagCF
	right.numericFlags, right.partialNumericFlags = false, x86ByteFlagCF
	right.cells[0].known, right.cells[0].canonical = 0xf3, 0x03
	right.cells[0].scalarFlags = x86ByteFlagCF
	right.cells[0].numericFlags, right.cells[0].partialNumericFlags = false, x86ByteFlagCF
	merged, valid := x86SourceStackScalarMerge(left, right)
	if !valid || merged.scalarResult.bytes.gp[0] != 0 || merged.scalarResult.bytes.flags != x86ByteFlagCF ||
		merged.cells[0].known != 0x33 || merged.cells[0].canonical != 0x03 || merged.cells[0].scalarFlags != x86ByteFlagCF ||
		x86SourceStackNumericFlagMask(&merged) != x86ByteFlagCF || merged.cells[0].numericFlags ||
		merged.cells[0].partialNumericFlags != x86ByteFlagCF {
		t.Fatal("scalar join invented numerical/canonical/FLAGS knowledge")
	}
	merged.scalarResult.bytes.fp[0], merged.cells[0].known = false, 0xff
	if !left.scalarResult.bytes.fp[0] || !right.scalarResult.bytes.fp[0] || left.cells[0].known != 0x3f || right.cells[0].known != 0xf3 {
		t.Fatal("scalar join mutated a predecessor")
	}
	for _, change := range []string{"SP", "BP", "cell offset", "cell width", "opaque BP", "layout", "caller"} {
		t.Run(change, func(t *testing.T) {
			other := right
			other.cells = append([]x86SourceStackCell(nil), right.cells...)
			other.scalarResult = right.scalarResult.clone()
			switch change {
			case "SP":
				other.sp--
			case "BP":
				other.bp.original = false
			case "cell offset":
				other.cells[0].offset--
			case "cell width":
				other.cells[0].width = 2
			case "opaque BP":
				other.cells[0].bp = &x86SourceStackAddress{original: true}
			case "layout":
				other.scalarResult.width--
			case "caller":
				other.callers = map[Reg]x86CallerPointerValue{}
			}
			if _, valid := x86SourceStackScalarMerge(left, other); valid {
				t.Fatal("physical or foreign role merged as scalar bytes")
			}
		})
	}
}

// Execute the complete kernels whose source word matches the host pointer.
// Unlike pure GP arithmetic, physical MOVL SP,BP cannot carry a 64-bit host
// address. Both source widths retain their five-target objects above and their
// required original-Go/LLVM Linux AMD64/i386 execution owner, without skips here.
func TestX86PhysicalSourceStackScalarPortableCompleteRuntimeSource(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	source, _ := x86SourceStackRuntimeSource(arch)
	var adapters, declarations, checks strings.Builder
	for _, row := range x86SourceStackRuntimeCases(arch) {
		x86SourceStackPortableAdapter(&adapters, row.name, row.width)
		fmt.Fprintf(&declarations, "extern uint64_t %sPortable(uint64_t);\n", row.name)
		fmt.Fprintf(&checks, `    {
        const uint64_t mask=UINT64_MAX >> %d;
        const uint64_t value=input & mask;
        uint64_t want=value+7;
`, 64-row.width)
		if row.flags {
			checks.WriteString("        if (value==0) want++;\n")
		}
		if row.name == "WordImmediate" {
			checks.WriteString("        want=((value & ~UINT64_C(65535)) | 65530)+7;\n")
		}
		fmt.Fprintf(&checks, `        uint64_t got=%sPortable(input);
        if (got!=(want & mask)) {
            fprintf(stderr,"%s input=%%llx got=%%llx want=%%llx\n",
                (unsigned long long)input,(unsigned long long)got,(unsigned long long)(want & mask));
            return 1;
        }
    }
`, row.name, row.name)
	}
	for _, name := range []string{"PhysicalBool", "PhysicalBoolIntermediate", "PhysicalBoolNamedFP"} {
		x86SourceStackPortableAdapter(&adapters, name, 1)
		fmt.Fprintf(&declarations, "extern uint64_t %sPortable(uint64_t);\n", name)
	}
	const body = `int main(void) {
    const uint64_t inputs[]={0,1,17,253,249,UINT64_C(65530),UINT64_C(0xfffffffc),UINT64_MAX-3};
    for (unsigned index=0;index<sizeof(inputs)/sizeof(inputs[0]);++index) {
        const uint64_t input=inputs[index];
        volatile uint64_t canary[4]={11,23,37,41};
%s
        if (PhysicalBoolPortable(input)!=(input & 1) || PhysicalBoolIntermediatePortable(input)!=1 ||
            PhysicalBoolNamedFPPortable(input)!=1 || canary[0]!=11 || canary[1]!=23 || canary[2]!=37 || canary[3]!=41) {
            fprintf(stderr,"physical bool/canary input=%%llx\n",(unsigned long long)input);
            return 1;
        }
    }
    return 0;
}
`
	driver := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + fmt.Sprintf(body, checks.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(arch+"/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, x86SourceStackRuntimeDeclarations(arch), arch, triple, api)
			if err != nil {
				t.Fatal(err)
			}
			ir += adapters.String()
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "source-stack-scalar-values", triple, text, driver, nil, level)
				}
			}
		})
	}
}

func x86SourceStackPortableAdapter(out *strings.Builder, name string, bits int) {
	fmt.Fprintf(out, "define i64 @%sPortable(i64 %%input) {\n", name)
	value := "%input"
	if bits != 64 {
		fmt.Fprintf(out, "    %%argument = trunc i64 %%input to i%d\n", bits)
		value = "%argument"
	}
	fmt.Fprintf(out, "    %%value = call i%d @%s(i%d %s)\n", bits, name, bits, value)
	value = "%value"
	if bits != 64 {
		fmt.Fprintf(out, "    %%result = zext i%d %%value to i64\n", bits)
		value = "%result"
	}
	fmt.Fprintf(out, "    ret i64 %s\n}\n", value)
}
