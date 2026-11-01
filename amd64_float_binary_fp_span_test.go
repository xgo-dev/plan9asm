package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type x86FloatBinaryFPFixture struct {
	name, opcode, operation, declaration, assembly string
	bits, bytes, resultOffset                      int
	sig                                            FuncSig
}

// Derive these layouts from actual Go declarations. Aggregate byte fields have
// separate virtual slots, not a pointer to one contiguous native FP word.
func x86FloatBinaryFPFixtures(t *testing.T) []x86FloatBinaryFPFixture {
	t.Helper()
	var fixtures []x86FloatBinaryFPFixture
	var declarations strings.Builder
	declarations.WriteString("package oracle\n")
	for _, operation := range []string{"ADD", "SUB", "MUL", "DIV"} {
		for _, bits := range []int{32, 64} {
			for _, spelling := range []string{"legacy", "vex", "broadcast"} {
				fixture := x86FloatBinaryFPFixture{operation: operation, bits: bits, bytes: bits / 8}
				fixture.name = fmt.Sprintf("%s%d%s", strings.ToLower(operation), bits, spelling)
				fixture.declaration = fmt.Sprintf("func %s(source [%d]byte,left uint%d) uint%d\n", fixture.name, fixture.bytes, bits, bits)
				declarations.WriteString(fixture.declaration)
				fixtures = append(fixtures, fixture)
			}
		}
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "value.go", declarations.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	pkg, err := (&types.Config{Sizes: sizes}).Check("oracle", set, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range fixtures {
		fixture := &fixtures[i]
		fixture.sig, err = DeriveGoFuncABI0Signature(fixture.name, pkg.Scope().Lookup(fixture.name).(*types.Func), "amd64", sizes)
		if err != nil {
			t.Fatal(err)
		}
		fixture.resultOffset = int(fixture.sig.Frame.Results[0].Offset)
		if fixture.resultOffset != 2*fixture.bytes || len(fixture.sig.Frame.Params) != fixture.bytes+1 {
			t.Fatalf("independent Go ABI0 frame changed: %+v", fixture.sig.Frame)
		}
		move, suffix := "MOVSS", "SS"
		if fixture.bits == 64 {
			move, suffix = "MOVSD", "SD"
		}
		fixture.opcode = fixture.operation + suffix
		row, destination := fixture.opcode+" source+0(FP),X0", "X0"
		if strings.HasSuffix(fixture.name, "vex") {
			fixture.opcode = "V" + fixture.opcode
			row, destination = fixture.opcode+" source+0(FP),X0,X2", "X2"
		} else if strings.HasSuffix(fixture.name, "broadcast") {
			packedSuffix := "PS"
			if fixture.bits == 64 {
				packedSuffix = "PD"
			}
			fixture.opcode = "V" + fixture.operation + packedSuffix + ".BCST"
			row, destination = fixture.opcode+" source+0(FP),X0,X2", "X2"
		}
		fixture.assembly = fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s left+%d(FP),X0\n%s\n%s %s,ret+%d(FP)\nRET\n",
			fixture.name, fixture.resultOffset+fixture.bytes, move, fixture.bytes, row, move, destination, fixture.resultOffset)
	}
	return fixtures
}

func TestCrossLinuxRuntimeMatrixX86FloatBinaryOriginalGoFPByteFields(t *testing.T) {
	x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, checks strings.Builder
	declarations.WriteString("package oracle\n")
	checks.WriteString("package oracle\nimport \"testing\"\nfunc TestOriginalByteFields(t *testing.T){\n")
	for _, fixture := range x86FloatBinaryFPFixtures(t) {
		declarations.WriteString(fixture.declaration)
		// asmdecl refuses scalar arithmetic on array types even when its byte
		// size matches. A vetted LEAQ exposes the same original Go FP bytes;
		// the floating opcode, operand order and independently known bits stay
		// unchanged. The translator test below keeps the direct FP spelling.
		memoryRow := fixture.opcode + " source+0(FP)"
		addressedRow := "LEAQ source+0(FP),CX\n" + fixture.opcode + " (CX)"
		assembly.WriteString(strings.Replace(fixture.assembly, memoryRow, addressedRow, 1))
		// The original executable uses baseline SSE only. Go still assembles
		// every VEX/EVEX form; LLVM software lanes are checked separately.
		if !strings.HasSuffix(fixture.name, "legacy") {
			continue
		}
		left, source := uint64(0x3f800000), uint64(0x40200000)
		want := map[string]uint64{"ADD": 0x40600000, "SUB": 0xbfc00000, "MUL": 0x40200000, "DIV": 0x3ecccccd}[fixture.operation]
		if fixture.bits == 64 {
			left, source = 0x3ff0000000000000, 0x4004000000000000
			want = map[string]uint64{"ADD": 0x400c000000000000, "SUB": 0xbff8000000000000, "MUL": 0x4004000000000000, "DIV": 0x3fd999999999999a}[fixture.operation]
		}
		var args []string
		for i := 0; i < fixture.bytes; i++ {
			args = append(args, fmt.Sprint(byte(source>>uint(i*8))))
		}
		arguments := fmt.Sprintf("[%d]byte{%s},uint%d(0x%x)", fixture.bytes, strings.Join(args, ","), fixture.bits, left)
		fmt.Fprintf(&checks, "if got:=%s(%s);got!=0x%x{t.Fatalf(%q,got)}\n", fixture.name, arguments, want, fixture.name+" got=%x")
	}
	checks.WriteString("}\n")
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module oracle\n\ngo 1.20\n", "value.go": declarations.String(),
		"value_amd64.s": assembly.String(), "value_test.go": checks.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=asmdecl", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go cross-field floating memory oracle: %v\n%s", err, output)
	}
}

func TestCrossLinuxRuntimeMatrixX86FloatBinaryFPByteFields(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, wrappers, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for _, fixture := range x86FloatBinaryFPFixtures(t) {
		assembly.WriteString(fixture.assembly)
		sigs[fixture.name] = fixture.sig
		// A bit-carrier wrapper constructs the LLVM array argument explicitly;
		// C aggregate calling conventions are not the translated Go signature.
		fmt.Fprintf(&wrappers, "define i%d @check_%s(i%d %%right,i%d %%left){\n", fixture.bits, fixture.name, fixture.bits, fixture.bits)
		packed := "poison"
		for i := 0; i < fixture.bytes; i++ {
			fmt.Fprintf(&wrappers, " %%shift%d=lshr i%d %%right,%d\n %%byte%d=trunc i%d %%shift%d to i8\n %%pack%d=insertvalue [%d x i8] %s,i8 %%byte%d,%d\n",
				i, fixture.bits, i*8, i, fixture.bits, i, i, fixture.bytes, packed, i, i)
			packed = fmt.Sprintf("%%pack%d", i)
		}
		fmt.Fprintf(&wrappers, " %%result=call i%d @%s([%d x i8] %s,i%d %%left)\n ret i%d %%result\n}\n", fixture.bits, fixture.name, fixture.bytes, packed, fixture.bits, fixture.bits)
		fmt.Fprintf(&declarations, "extern uint%d_t check_%s(uint%d_t,uint%d_t);\n", fixture.bits, fixture.name, fixture.bits, fixture.bits)
		oracle, flags, secondOperation := "sse_result", "last_sse_csr", fixture.operation == "SUB"
		if fixture.operation == "MUL" || fixture.operation == "DIV" {
			oracle, flags, secondOperation = "sse_muldiv_result", "last_sse_muldiv_csr", fixture.operation == "DIV"
		}
		fmt.Fprintf(&checks, `
 for(unsigned rc=0;rc<4;rc++) for(unsigned index=0;index<64;index++) {
  uint64_t left=%[1]d==32?UINT64_C(0x3f800001)+index*3571:UINT64_C(0x3ff0000000000001)+index*7912347;
  uint64_t right=%[1]d==32?UINT64_C(0x40200001)+index*761:UINT64_C(0x4004000000000001)+index*1234567;
  unsigned csr=0x1f80|(rc<<13),after;
  __asm__ volatile("ldmxcsr %%0"::"m"(csr));
  uint64_t got=check_%[2]s(right,left);
  __asm__ volatile("stmxcsr %%0":"=m"(after));
  uint64_t want=%[3]s(%[1]d,left,right,%[4]d,csr);
  if(got!=want || after!=%[5]s){fprintf(stderr,"%[2]s rc=%%u got=%%llx want=%%llx after=%%x expectedCSR=%%x\n",rc,(unsigned long long)got,(unsigned long long)want,after,%[5]s);return 1;}
 }
`, fixture.bits, fixture.name, oracle, x86FloatAddSubBoolInt(secondOperation), flags)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	mulDivOracle := strings.NewReplacer("subss", "divss", "subsd", "divsd", "addss", "mulss", "addsd", "mulsd",
		"sse_result", "sse_muldiv_result", "last_sse_csr", "last_sse_muldiv_csr").Replace(x86FloatAddSubSSEOracle)
	main := x86FloatAddSubSSEOracle + mulDivOracle + declarations.String() + "int main(void){\n" + checks.String() +
		"unsigned csr=0x1f80;__asm__ volatile(\"ldmxcsr %0\"::\"m\"(csr));return 0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "float-binary-fp-bytes", triple, ir+wrappers.String(), main, prefix)
}
