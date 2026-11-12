package plan9asm

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The Go encoder tables do not express this helper rule. Go 1.20 could
// assemble EVEX.z=1/aaa=0; issue 57952 closed that bug in Go 1.21. Those
// historical objects are observations of invalid bytes, never legal forms.
func TestX86BinaryFloatZeroingRequiresNonzeroMaskAcrossAssemblerEpochs(t *testing.T) {
	oldAssembler := !goToolchainAtLeast(runtime.Version(), 1, 21)
	for _, arch := range []string{"386", "amd64"} {
		for operation, opcode := range map[string]byte{
			"ADD": 0x58, "SUB": 0x5c, "MUL": 0x59, "DIV": 0x5e,
		} {
			for pp, suffix := range []string{"PS", "PD", "SS", "SD"} {
				widths := []string{"X", "Y", "Z"}
				if pp >= 2 {
					widths = widths[:1]
				}
				for width, bank := range widths {
					name := "V" + operation + suffix
					row := fmt.Sprintf("%s.Z %s0,%s1,%s2", name, bank, bank, bank)
					t.Run(arch+"/"+row, func(t *testing.T) {
						source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
						goAssemblerOracleOutput(t, arch, source, "", oldAssembler)

						// Independent register encoding: source0, source1,
						// destination2; EVEX.v'=1 and the requested vector length.
						p1 := byte(0x74 | pp)
						if pp&1 != 0 {
							p1 |= 0x80
						}
						code := []byte{0x62, 0xf1, p1, 0x88 | byte(width<<5), opcode, 0xd0}
						if oldAssembler {
							listing := x86InsertExtractGoListing(t, arch, source)
							var observed []byte
							for _, line := range strings.Split(string(listing), "\n") {
								observed = append(observed, x86InsertExtractListedBytes(line)...)
							}
							want := append(append([]byte(nil), code...), 0xc3)
							if !bytes.Equal(observed, want) {
								t.Fatalf("historical assembler observation changed: got %x want %x", observed, want)
							}
							t.Logf("actual old Go emitted reserved z=1/aaa=0 bytes %x", code)
						}
						mode := 64
						if arch == "386" {
							mode = 32
						}
						if _, _, known, err := decodedX86EVEXBinaryFloatInstruction(code, 0, mode, "", false); !known || err == nil ||
							!strings.Contains(err.Error(), "zeroing requires a nonzero mask") {
							t.Fatalf("reserved zeroing acquired raw semantics: known=%t err=%v", known, err)
						}
						x86RequireZeroMaskAPIOutcome(t, arch, source, false)
						x86RequireZeroMaskAPIOutcome(t, arch, x86RawINSERTPSSource("f", code), false)

						explicit := fmt.Sprintf("%s.Z %s0,%s1,K0,%s2", name, bank, bank, bank)
						goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+explicit+"\nRET\n", "", false)
						x86RequireZeroMaskAPIOutcome(t, arch, "TEXT f(SB),4,$0-0\n"+explicit+"\nRET\n", false)

						if arch == "amd64" {
							valid := fmt.Sprintf("%s.Z %s0,%s1,K1,%s2", name, bank, bank, bank)
							goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+valid+"\nRET\n", "", true)
							control := append([]byte(nil), code...)
							control[3] |= 1
							ins, size, known, err := decodedX86EVEXBinaryFloatInstruction(control, 0, 64, "", false)
							if !known || err != nil || size != len(control) || ins.Op != Op(name+".Z") ||
								len(ins.Args) != 4 || ins.Args[2].Reg != "K1" {
								t.Fatalf("nonzero-mask control rejected: %+v size=%d known=%t err=%v", ins, size, known, err)
							}
							x86RequireZeroMaskAPIOutcome(t, arch, "TEXT f(SB),4,$0-0\n"+valid+"\nRET\n", true)
							x86RequireZeroMaskAPIOutcome(t, arch, x86RawINSERTPSSource("f", control), true)
						}
					})
				}
			}
		}
	}
}

func x86RequireZeroMaskAPIOutcome(t *testing.T, arch, source string, wantSuccess bool) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal("fixture must reach the semantic validators", err)
	}
	triples := []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
	if arch == "amd64" {
		triples = []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
	}
	pkg := x86FloatMulDivShapesPackage(t, "package shapes\nfunc f()\n", arch)
	for _, triple := range triples {
		options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}}
		if ir, err := Translate(file, options); (err == nil) != wantSuccess || err == nil && ir == "" {
			t.Fatalf("%s text API outcome wantSuccess=%t err=%v", triple, wantSuccess, err)
		}
		func() {
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := TranslateModuleInContext(context, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if (err == nil) != wantSuccess || err == nil && module.IsNil() {
				t.Fatalf("%s module API outcome wantSuccess=%t err=%v", triple, wantSuccess, err)
			}
			goSource := strings.Replace(source, "TEXT f(SB)", "TEXT ·f(SB)", 1)
			result, err := translateGoModuleInContext(context, pkg, []byte(goSource),
				GoModuleOptions{GOARCH: arch, TargetTriple: triple})
			if result != nil && !result.Module.IsNil() {
				defer result.Module.Dispose()
			}
			if (err == nil) != wantSuccess || err == nil && (result == nil || result.Module.IsNil()) {
				t.Fatalf("%s Go API outcome wantSuccess=%t err=%v", triple, wantSuccess, err)
			}
		}()
	}
}
