package plan9asm

import (
	"fmt"
	"go/types"
	"math/bits"
	"strconv"
	"strings"
	"testing"
)

type x86BitScanExecutionRow struct {
	name, op string
	role     int // Prior, Alias, ZeroFlag, original-only Observe, ObserveAlias.
}

type x86BitScanExecutionFixture struct {
	arch, public, declarations, observers, observerDeclarations string
	callers, callerDeclarations                                 string
	rows                                                        []x86BitScanExecutionRow
}

var x86BitScanExecutionValues = []uint64{0, 1, 7, 128, 255, 0x10000, 0x80000000, 0x8000000000000000, ^uint64(0)}
var x86BitScanExecutionPriors = []uint64{0, ^uint64(0), 0x1122334455667788, 0x8877665544332211}

func x86BitScanExecutionSeed(index int) uint64 {
	var result uint64
	for bit, position := range []uint{0, 2, 4, 6, 7, 11} {
		result |= uint64(index>>bit&1) << position
	}
	return result
}

func x86BitScanExecutionFixtureFor(t *testing.T, arch string) x86BitScanExecutionFixture {
	t.Helper()
	source, declarations := x86BitScanOriginalObjectFixture(t, arch)
	fixture := x86BitScanExecutionFixture{arch: arch, public: source, declarations: declarations,
		callers: "#include \"funcdata.h\"\n"}
	word, typ, suffix := 8, "uint64", "Q"
	if arch == "386" {
		word, typ, suffix = 4, "uint32", "L"
	}
	for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
		if arch == "386" && strings.HasSuffix(op, "Q") {
			continue // No Go mode32 Q instruction exists; its grammar stays rejected.
		}
		for role, prefix := range []string{"Prior", "Alias", "ZeroFlag", "Observe", "ObserveAlias"} {
			name := prefix + op
			fixture.rows = append(fixture.rows, x86BitScanExecutionRow{name, op, role})
			if role < 3 {
				declaration, caller := x86BitScanExecutionGuardCallerFor(t, arch, name)
				fixture.callerDeclarations += declaration
				fixture.callers += caller
				continue
			}
			fixture.observerDeclarations += fmt.Sprintf("func %s(out *[4]%s,x,prior,status %s)\n", name, typ, typ)
			destination := "BX"
			if role == 4 {
				destination = "AX"
			}
			// Independent original-only physical observation. Neither this
			// FLAGS seed nor its pointer writes enters the public translator.
			fixture.observers += fmt.Sprintf(`TEXT ·%s(SB),4,$0-%d
MOV%s out+0(FP),DI
MOV%s x+%d(FP),AX
MOV%s prior+%d(FP),BX
MOV%s status+%d(FP),CX
AND%s $2261,CX
OR%s $2,CX
PUSH%s CX
POPF%s
%s AX,%s
PUSHF%s
POP%s DX
MOV%s %s,%d(DI)
MOV%s DX,%d(DI)
RET
`, name, 4*word, suffix, suffix, word, suffix, 2*word, suffix, 3*word,
				suffix, suffix, suffix, suffix, op, destination, suffix, suffix,
				suffix, destination, word, suffix, 2*word)
		}
	}
	return fixture
}

// Original-only callers check the actual ABI0 outgoing arguments and two
// adjacent post-result slots. They are not translated source or caller proof.
func x86BitScanExecutionGuardCallerFor(t *testing.T, arch, name string) (string, string) {
	t.Helper()
	word, typ, suffix := 8, "uint64", "Q"
	if arch == "386" {
		word, typ, suffix = 4, "uint32", "L"
	}
	declaration := fmt.Sprintf("func Guard%s(out *[4]%s,x,prior %s,a,b uint32)\n", name, typ, typ)
	pkg := mustGoPackage(t, "caller", "package caller\n"+declaration)
	sig, err := DeriveGoFuncABI0Signature("Guard"+name, pkg.Types.Scope().Lookup("Guard"+name).(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil || len(sig.Frame.Params) != 5 || len(sig.Frame.Results) != 0 || sig.Frame.Params[1].Offset != int64(word) || sig.Frame.Params[2].Offset != int64(2*word) || sig.Frame.Params[3].Offset != int64(3*word) || sig.Frame.Params[4].Offset != int64(3*word+4) {
		t.Fatal("original caller lost its complete actual Go ABI0 layout", err)
	}
	result := 2*word + 8
	arguments := []struct {
		name          string
		input, output int
		suffix        string
	}{{"x", word, 0, suffix}, {"prior", 2 * word, word, suffix}, {"a", 3 * word, 2 * word, "L"}, {"b", 3*word + 4, 2*word + 4, "L"}}
	var assembly strings.Builder
	fmt.Fprintf(&assembly, "TEXT ·Guard%s(SB),4,$%d-%d\nNO_LOCAL_POINTERS\n", name, result+3*word, 3*word+8)
	for _, argument := range arguments {
		fmt.Fprintf(&assembly, "MOV%s %s+%d(FP),AX\nMOV%s AX,%d(SP)\n", argument.suffix, argument.name, argument.input, argument.suffix, argument.output)
	}
	for index, value := range []int{0x77a7a7a7, 0x2468ace, 0x13579bdf} {
		fmt.Fprintf(&assembly, "MOV%s $%#x,%d(SP)\n", suffix, value, result+index*word)
	}
	fmt.Fprintf(&assembly, "CALL ·%s(SB)\nMOV%s out+0(FP),DI\nMOV%s $1,BX\n", name, suffix, suffix)
	for index, value := range []int{0x2468ace, 0x13579bdf} {
		fmt.Fprintf(&assembly, "MOV%s $%#x,AX\nMOV%s %d(SP),CX\nCMP%s AX,CX\nJNE broken\n", suffix, value, suffix, result+(index+1)*word, suffix)
	}
	for _, argument := range arguments {
		fmt.Fprintf(&assembly, "MOV%s %s+%d(FP),AX\nMOV%s %d(SP),CX\nCMP%s AX,CX\nJNE broken\n", argument.suffix, argument.name, argument.input, argument.suffix, argument.output, argument.suffix)
	}
	fmt.Fprintf(&assembly, "JMP guarded\nbroken:\nMOV%s $0,BX\nguarded:\nMOV%s BX,%d(DI)\nMOV%s %d(SP),AX\nMOV%s AX,%d(DI)\nRET\n", suffix, suffix, 2*word, suffix, result, suffix, word)
	return declaration, assembly.String()
}

func x86BitScanExecutionWord(value uint64, arch string) uint64 {
	if arch == "386" {
		return uint64(uint32(value))
	}
	return value
}

// An independent numeric oracle. The historical dword-zero high half has two
// allowed physical observations; only actual original-Go records choose one.
// Other five status flags have no invented mathematical expectation.
func x86BitScanExecutionAccepts(row x86BitScanExecutionRow, arch string, x, prior, got, flags uint64) bool {
	x, prior = x86BitScanExecutionWord(x, arch), x86BitScanExecutionWord(prior, arch)
	if got != x86BitScanExecutionWord(got, arch) || flags&^uint64(2261) != 0 {
		return false
	}
	width := map[byte]int{'W': 16, 'L': 32, 'Q': 64}[row.op[len(row.op)-1]]
	input := x
	if width < 64 {
		input &= uint64(1)<<width - 1
	}
	if row.role == 1 || row.role == 4 {
		prior = x
	}
	if row.role < 3 && flags != 0 || row.role >= 3 && (flags>>6&1 == 1) != (input == 0) {
		return false
	}
	want := prior
	if input != 0 {
		want = uint64(bits.TrailingZeros64(input))
		if strings.HasPrefix(row.op, "BSR") {
			want = uint64(63 - bits.LeadingZeros64(input))
		}
		if width == 16 {
			want |= prior &^ 0xffff
		}
	}
	if row.role == 2 && input == 0 {
		want ^= uint64(1) << map[string]uint{"amd64": 63, "386": 31}[arch]
	}
	if got == want {
		return true
	}
	if input == 0 && width == 32 && arch == "amd64" {
		old := prior & 0xffffffff
		if row.role == 2 {
			old ^= uint64(1) << 63
		}
		return got == old
	}
	return false
}

func x86BitScanExecutionVisit(fixture x86BitScanExecutionFixture, visit func(x, prior, seed uint64, row x86BitScanExecutionRow) error) error {
	for _, x := range x86BitScanExecutionValues {
		for _, prior := range x86BitScanExecutionPriors {
			for status := 0; status < 64; status++ {
				for _, row := range fixture.rows {
					if err := visit(x, prior, x86BitScanExecutionSeed(status), row); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func x86BitScanExecutionCheckRecords(fixture x86BitScanExecutionFixture, output []byte) error {
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	index := 0
	err := x86BitScanExecutionVisit(fixture, func(x, prior, seed uint64, row x86BitScanExecutionRow) error {
		if index >= len(lines) {
			return fmt.Errorf("missing original physical observation %d", index)
		}
		fields := strings.Fields(lines[index])
		if len(fields) != 2 {
			return fmt.Errorf("invalid original physical observation %d", index)
		}
		value, valueErr := strconv.ParseUint(fields[0], 16, 64)
		flags, flagsErr := strconv.ParseUint(fields[1], 16, 64)
		if valueErr != nil || flagsErr != nil || !x86BitScanExecutionAccepts(row, fixture.arch, x, prior, value, flags) {
			return fmt.Errorf("original %s x=%x prior=%x seed=%x observation %d: %q", row.name, x, prior, seed, index, lines[index])
		}
		index++
		return nil
	})
	if err == nil && index != len(lines) {
		err = fmt.Errorf("unexpected original observation count %d (want %d)", len(lines), index)
	}
	return err
}

func TestX86ScalarBitScanExecutionOracleDoesNotInventZeroOrFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		fixture := x86BitScanExecutionFixtureFor(t, arch)
		wantNames := 6
		if arch == "386" {
			wantNames = 4
		}
		if len(fixture.rows) != 5*wantNames || strings.Count(fixture.public, "TEXT ·") != 3*wantNames || strings.Count(fixture.observers, "TEXT ·") != 2*wantNames {
			t.Fatal("complete original public/physical source inventory missing")
		}
		if strings.Count(fixture.callers, "TEXT ·Guard") != 3*wantNames || strings.Count(fixture.callers, "CALL ·") != 3*wantNames || strings.Count(fixture.callers, "NO_LOCAL_POINTERS") != 3*wantNames || strings.Count(fixture.callers, "0x2468ace") != 6*wantNames || strings.Count(fixture.callers, "0x13579bdf") != 6*wantNames {
			t.Fatal("actual ABI0 outgoing argument/result-adjacent guard inventory missing")
		}
		if strings.Contains(fixture.public, "PUSH") || strings.Contains(fixture.public, "POPF") || strings.Count(fixture.observers, "PUSH"+map[string]string{"amd64": "Q", "386": "L"}[arch]) != 2*wantNames {
			t.Fatal("test-only physical FLAGS observation leaked into numerical source")
		}
		for _, row := range fixture.rows {
			prior := x86BitScanExecutionWord(0x1122334455667788, arch)
			if row.role == 1 || row.role == 4 {
				continue // Its prior is the actual source, separately covered below.
			}
			flags, good := uint64(0), prior
			if row.role >= 3 {
				flags = 1 << 6
			}
			if row.role == 2 {
				good ^= uint64(1) << map[string]uint{"amd64": 63, "386": 31}[arch]
			}
			if !x86BitScanExecutionAccepts(row, arch, 0, prior, good, flags) {
				t.Fatal("known zero prior was not retained", row)
			}
			for _, invented := range []uint64{16, 32, 64, ^uint64(0)} {
				if x86BitScanExecutionAccepts(row, arch, 0, prior, invented, flags) {
					t.Fatal("old software zero result became an allowed physical observation", row, invented)
				}
			}
			if row.role >= 3 {
				for seed := 0; seed < 64; seed++ {
					other := x86BitScanExecutionSeed(seed) | 1<<6
					if !x86BitScanExecutionAccepts(row, arch, 0, prior, good, other) || x86BitScanExecutionAccepts(row, arch, 0, prior, good, other&^(1<<6)) {
						t.Fatal("oracle guessed nonportable status bits or ignored portable ZF")
					}
				}
			}
		}
	}
}

func TestX86ScalarBitScanExecutionOracleCompleteWidthsAliasesAndRecords(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		fixture := x86BitScanExecutionFixtureFor(t, arch)
		for _, row := range fixture.rows {
			width := map[byte]int{'W': 16, 'L': 32, 'Q': 64}[row.op[len(row.op)-1]]
			for _, x := range []uint64{0, 1, 7, 128, 255, 1 << (width - 1)} {
				prior := x86BitScanExecutionWord(0x1122334455667788, arch)
				if row.role == 1 || row.role == 4 {
					prior = x86BitScanExecutionWord(x, arch)
				}
				want := prior
				if x != 0 {
					want = uint64(bits.TrailingZeros64(x))
					if strings.HasPrefix(row.op, "BSR") {
						want = uint64(63 - bits.LeadingZeros64(x))
					}
					if width == 16 {
						want |= prior &^ 0xffff
					}
				}
				if row.role == 2 && x == 0 {
					want ^= uint64(1) << map[string]uint{"amd64": 63, "386": 31}[arch]
				}
				flags := uint64(0)
				if row.role >= 3 && x == 0 {
					flags = 1 << 6
				}
				if !x86BitScanExecutionAccepts(row, arch, x, prior, want, flags) || x86BitScanExecutionAccepts(row, arch, x, prior, want^0x8000, flags) {
					t.Fatal("scan width/prior/alias numeric model changed", arch, row, x)
				}
			}
			if arch == "amd64" && width == 32 {
				prior := uint64(0x1122334455667788)
				x := uint64(0)
				if row.role == 1 || row.role == 4 {
					x, prior = 1<<32, 1<<32 // A zero dword with live high alias bytes.
				}
				flags, full, low := uint64(0), prior, prior&0xffffffff
				if row.role >= 3 {
					flags = 1 << 6
				}
				if row.role == 2 {
					full, low = full^(1<<63), low^(1<<63)
				}
				if !x86BitScanExecutionAccepts(row, arch, x, prior, full, flags) || !x86BitScanExecutionAccepts(row, arch, x, prior, low, flags) || x86BitScanExecutionAccepts(row, arch, x, prior, low|1<<40, flags) {
					t.Fatal("oracle guessed old/new CPU dword-zero upper behavior", row)
				}
			}
		}
		// A complete synthetic record stream certifies the reader's checking,
		// not execution. Give the nonportable five flags arbitrary values.
		one := x86BitScanExecutionFixture{arch: arch, rows: []x86BitScanExecutionRow{{"ObserveBSFQ", "BSFQ", 3}}}
		if arch == "386" {
			one.rows[0].name, one.rows[0].op = "ObserveBSFL", "BSFL"
		}
		var records strings.Builder
		err := x86BitScanExecutionVisit(one, func(x, prior, seed uint64, row x86BitScanExecutionRow) error {
			x, prior = x86BitScanExecutionWord(x, arch), x86BitScanExecutionWord(prior, arch)
			value, flags := prior, seed&^(1<<6)
			if x == 0 {
				flags |= 1 << 6
			} else {
				value = uint64(bits.TrailingZeros64(x))
			}
			fmt.Fprintf(&records, "%016x %04x\n", value, flags)
			return nil
		})
		if err != nil || x86BitScanExecutionCheckRecords(one, []byte(records.String())) != nil {
			t.Fatal("bounded complete record reader rejected numeric/ZF observations", err)
		}
		lines := strings.Split(strings.TrimSuffix(records.String(), "\n"), "\n")
		for _, bad := range []string{
			strings.Join(lines[:len(lines)-1], "\n") + "\n",
			records.String() + "0 0\n",
			"not-a-record\n" + strings.Join(lines[1:], "\n") + "\n",
			"0000000000000040 0040\n" + strings.Join(lines[1:], "\n") + "\n",
			"0000000000000000 0000\n" + strings.Join(lines[1:], "\n") + "\n",
		} {
			if x86BitScanExecutionCheckRecords(one, []byte(bad)) == nil {
				t.Fatal("missing/extra/invalid/invented-zero/ZF record escaped validation")
			}
		}
	}
}
