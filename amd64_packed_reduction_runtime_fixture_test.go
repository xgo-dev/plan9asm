//go:build unix

package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	x86PackedReductionNativeOwners = 4
	x86PackedReductionValueCapture = 64
	x86PackedReductionFaultCapture = 8
)

type x86PackedReductionRuntimeRow struct {
	oracle      x86PackedReductionOracleRow
	instruction string
	destination int
	selector    byte
	memory      bool
	self        bool
}

func x86PackedReductionNativeRows(faults bool) []x86PackedReductionRuntimeRow {
	var rows []x86PackedReductionRuntimeRow
	for _, oracle := range x86PackedReductionOracleRows() {
		if strings.Contains(oracle.row, "(BX)") {
			continue
		}
		selectors := []byte{0}
		if oracle.dot {
			selectors = []byte{0, 0x0f, 0x10, 0x11, 0x5a, 0x7f, 0xf0, 0xf1, 0xff}
			if strings.HasSuffix(oracle.mnemonic, "pd") {
				selectors = []byte{0, 0x0f, 0x10, 0x11, 0x33, 0xcc, 0xff}
			}
			if faults {
				selectors = []byte{0, 0x0f, 0xf0, 0xf1, 0xff}
			}
		}
		for _, selector := range selectors {
			variants := 6
			if oracle.legacy {
				variants = 3
			}
			if faults {
				variants = 1
			}
			for variant := 0; variant < variants; variant++ {
				row := x86PackedReductionRuntimeRow{oracle: oracle, selector: selector}
				row.destination, row.memory = variant/2, variant%2 == 1
				if oracle.legacy {
					row.destination, row.self = 1, variant == 2
				}
				if faults {
					row.memory, row.destination = true, 2
					if oracle.legacy {
						row.destination = 1
					}
				}
				bank := "X"
				if oracle.width == 32 {
					bank = "Y"
				}
				first := bank + "0"
				if row.self {
					first = bank + "1"
				}
				if row.memory {
					first = "(SI)"
					if faults {
						first = "(DI)"
					}
				}
				row.instruction = strings.ToUpper(oracle.mnemonic) + " "
				if oracle.dot {
					row.instruction += fmt.Sprintf("$%d,", selector)
				}
				row.instruction += first + "," + bank + "1"
				if !oracle.legacy {
					row.instruction += fmt.Sprintf(",%s%d", bank, row.destination)
				}
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func x86PackedReductionRuntimeExpectedBytes(row x86PackedReductionRuntimeRow, faults bool) []byte {
	code := x86PackedReductionIndependentFixtureBytes(row.oracle)
	modRM := byte(0xc0 | row.destination<<3)
	if row.self {
		modRM |= 1
	}
	if row.memory {
		modRM = byte(row.destination<<3 | 6) // Runtime's actual (SI).
		if faults {
			modRM = byte(row.destination<<3 | 7) // Dead native source is (DI).
		}
	}
	index := len(code) - 1
	if row.oracle.dot {
		index--
		code[index+1] = row.selector
	}
	code[index] = modRM
	return code
}

func x86PackedReductionRuntimeRawRows(t *testing.T, rows []x86PackedReductionRuntimeRow, faults bool) []string {
	t.Helper()
	var instructions []string
	var oracle []x86PackedReductionOracleRow
	var expected [][]byte
	for _, row := range rows {
		instructions = append(instructions, row.instruction)
		item := row.oracle
		item.row = row.instruction
		oracle = append(oracle, item)
		expected = append(expected, x86PackedReductionRuntimeExpectedBytes(row, faults))
	}
	listing, err := x86ExtensionGoListing(t, "amd64", strings.Join(instructions, "\n"))
	if err != nil {
		t.Fatalf("actual runtime instruction Go listing: %v\n%s", err, listing)
	}
	raw, err := x86PackedReductionRawRowsFromGoListingWithExpected(listing, oracle, expected)
	if err != nil {
		t.Fatalf("independent runtime original opcode/PC boundaries: %v\n%s", err, listing)
	}
	return raw
}

func x86PackedReductionRuntimeFixture(rows []x86PackedReductionRuntimeRow) (assembly, declarations, original, driver string) {
	var asm, decl, goCalls, cDecl, cCalls strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("reduction%d", index)
		fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$8-36\nSTMXCSR saved-4(SP)\n"+
			"MOVQ out+0(FP),DI\nMOVQ a+8(FP),SI\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),CX\n"+
			"VMOVDQU (SI),Y0\nVMOVDQU (DX),Y1\nVMOVDQU (CX),Y2\n"+
			"LDMXCSR csr+32(FP)\nMOVQ $-1,R8\nCMPQ R8,$-1\n%s\n"+
			"VMOVDQU Y%d,(DI)\nSTMXCSR 40(DI)\nSETEQ 32(DI)\nSETCS 33(DI)\n"+
			"SETOS 34(DI)\nSETMI 35(DI)\nSETPC 36(DI)\nLDMXCSR saved-4(SP)\nRET\n",
			name, row.instruction, row.destination)
		fmt.Fprintf(&decl, "func %s(out *[8]uint64,a,b,old *[4]uint64,csr uint32)\n", name)
		bits := 32
		if strings.HasSuffix(row.oracle.mnemonic, "pd") {
			bits = 64
		}
		fmt.Fprintf(&goCalls, "check(%d,%d,%s)\n", index, bits, name)
		fmt.Fprintf(&cDecl, "extern void %s(uint64_t*,const uint64_t*,const uint64_t*,const uint64_t*,uint32_t);\n", name)
		fmt.Fprintf(&cCalls, "check(%d,%d,%s);\n", index, bits, name)
	}
	var gValues, cValues strings.Builder
	values := append(append([]uint64(nil), x86ScalarFloatIntegerSSInputs...), x86ScalarFloatIntegerSDInputs...)
	for _, value := range values {
		fmt.Fprintf(&gValues, "%#x,", value)
		fmt.Fprintf(&cValues, "UINT64_C(%#x),", value)
	}
	original = `package main
import ("fmt";"unsafe")
var values=[]uint64{` + gValues.String() + `}
func check(index,bits int,fn func(*[8]uint64,*[4]uint64,*[4]uint64,*[4]uint64,uint32)) {
    hash:=uint64(1469598103934665603);count:=0
    for n:=range values {for rc:=0;rc<4;rc++ {for controls:=0;controls<8;controls++ {
        var backing [3][6]uint64
        var inputs [3]*[4]uint64
        for source:=range inputs {
            p:=unsafe.Pointer(&backing[source][0])
            inputs[source]=(*[4]uint64)(unsafe.Add(p,(-uintptr(p))&15))
            for lane:=range inputs[source] {
                start:=n+2*lane+7*source
                value:=values[start%len(values)]
                if bits==32 {value=uint64(uint32(value))|uint64(uint32(values[(start+1)%len(values)]))<<32}
                inputs[source][lane]=value
            }
        }
        var out [8]uint64
        for lane:=range out {out[lane]=uint64(lane+1)*0x0101010101010101}
        csr:=uint32(0x1f80|rc<<13)
        if controls&1!=0 {csr|=0x40};if controls&2!=0 {csr|=0x8000};if controls&4!=0 {csr|=0x21}
        fn(&out,inputs[0],inputs[1],inputs[2],csr)
        for _,word:=range out {for shift:=0;shift<64;shift+=8 {hash=(hash^uint64(byte(word>>shift)))*1099511628211}}
        count++
    }}}
    fmt.Printf("%d %d %016x\n",index,count,hash)
}
` + decl.String() + "func main(){\n" + goCalls.String() + "}\n"
	driver = `#include <stdint.h>
#include <stdio.h>
static const uint64_t values[]={` + cValues.String() + `};
static void check(unsigned index,unsigned bits,void (*fn)(uint64_t*,const uint64_t*,const uint64_t*,const uint64_t*,uint32_t)) {
    uint64_t hash=UINT64_C(1469598103934665603);unsigned count=0,N=sizeof(values)/sizeof(*values);
    for(unsigned n=0;n<N;n++) for(unsigned rc=0;rc<4;rc++) for(unsigned controls=0;controls<8;controls++) {
        _Alignas(16) uint64_t inputs[3][4],out[8];
        for(unsigned source=0;source<3;source++) for(unsigned lane=0;lane<4;lane++) {
            unsigned start=n+2*lane+7*source;
            uint64_t value=values[start%N];
            if(bits==32) value=(uint64_t)(uint32_t)value|(uint64_t)(uint32_t)values[(start+1)%N]<<32;
            inputs[source][lane]=value;
        }
        for(unsigned lane=0;lane<8;lane++) out[lane]=(lane+1)*UINT64_C(0x0101010101010101);
        uint32_t csr=0x1f80|(rc<<13);
        if(controls&1) csr|=0x40;if(controls&2) csr|=0x8000;if(controls&4) csr|=0x21;
        fn(out,inputs[0],inputs[1],inputs[2],csr);
        for(unsigned lane=0;lane<8;lane++) for(unsigned shift=0;shift<64;shift+=8) hash=(hash^(uint8_t)(out[lane]>>shift))*UINT64_C(1099511628211);
        count++;
    }
    printf("%u %u %016llx\n",index,count,(unsigned long long)hash);
}
` + cDecl.String() + "int main(void){\n" + cCalls.String() + "return 0;}\n"
	return asm.String(), decl.String(), original, driver
}

func TestX86PackedReductionCompleteNativeFixtureInventory(t *testing.T) {
	for _, faults := range []bool{false, true} {
		rows := x86PackedReductionNativeRows(faults)
		want := 258
		if faults {
			want = 37
		}
		if len(rows) != want {
			t.Fatal("complete semantic class lost value/fault shapes", faults, len(rows))
		}
		members := make(map[string]map[int]bool)
		owners := [4]int{}
		limit := x86PackedReductionValueCapture
		if faults {
			limit = x86PackedReductionFaultCapture
		}
		for index, row := range rows {
			if members[row.oracle.mnemonic] == nil {
				members[row.oracle.mnemonic] = make(map[int]bool)
			}
			members[row.oracle.mnemonic][row.oracle.width] = true
			owners[index/limit%4]++
			if strings.Contains(row.instruction, "Z") || row.oracle.width > 32 {
				t.Fatal("native X/Y fixture acquired physical Z state", row.instruction)
			}
		}
		for _, name := range []string{"dppd", "dpps", "vdppd", "vdpps", "haddps", "haddpd", "hsubps", "hsubpd", "vhaddps", "vhaddpd", "vhsubps", "vhsubpd"} {
			widths := members[name]
			want := map[int]bool{16: true}
			if name == "vdpps" || strings.HasPrefix(name, "vh") {
				want[32] = true
			}
			if !reflect.DeepEqual(widths, want) {
				t.Fatal("native member omitted an independent physical width", faults, name, widths)
			}
		}
		if len(members) != 12 {
			t.Fatal("native semantic class lost or invented members", members)
		}
		for owner, count := range owners {
			if count == 0 {
				t.Fatal("empty native semantic owner", faults, owner)
			}
		}
	}
}
