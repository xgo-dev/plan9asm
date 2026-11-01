//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ScalarArithmeticNativeResultsAndFaults(t *testing.T) {
	x86ScalarArithmeticNativeRuntime(t, false)
}

func TestCrossLinuxRuntimeMatrixX86ScalarArithmeticNativeFlagsAndAliases(t *testing.T) {
	x86ScalarArithmeticNativeRuntime(t, true)
}

func x86ScalarArithmeticNativeRuntime(t *testing.T, flagsAndAliases bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, rows strings.Builder
	count := 0
	appendKernel := func(op string, width, carry int, dead, flags bool, alias string) {
		name, original := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count)
		comparison := "CMPL BX,BX\n"
		nativeComparison := "MOVL $1,R10\nCMPL R10,R10\n"
		if carry != 0 {
			comparison = "CMPL BX,$2\n"
			nativeComparison = "MOVL $1,R10\nCMPL R10,$2\n"
		}
		body := comparison + op + " -1(DX)(BX*1),CX"
		native := "MOVQ $0x87654321fedcba98,AX\n" + nativeComparison + op + " (DI),AX\n"
		mode := 0 // value result
		if flags {
			body += "\n" + x86ScalarArithmeticNativeFlagObserver + "\nMOVQ AX,CX"
			native += x86ScalarArithmeticNativeFlagObserver + "\n"
			mode = 1
		}
		if alias != "" {
			effective := "SI"
			if alias == "BH" {
				effective = "DI"
			}
			body = "MOVQ DX,R8\nMOVQ $0x87654321fedcba98," + effective + "\n" + comparison + op + " (R8)," + alias + "\nMOVQ " + effective + ",CX"
			native = "MOVQ DI,R8\nMOVQ $0x87654321fedcba98," + effective + "\n" + nativeComparison + op + " (R8)," + alias + "\nMOVQ " + effective + ",AX\n"
		}
		if dead {
			body += "\nMOVQ $0x87654321fedcba98,CX"
			native += "MOVQ $0x87654321fedcba98,AX\n"
		}
		assembly, declaration := x86ExtensionNativeFixture(name, "amd64", body, false)
		source.WriteString(assembly)
		declarations.WriteString(strings.ReplaceAll(declaration, "*[4]byte", "*[16]byte"))
		code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+native+"RET\n")
		var bytes []string
		for _, b := range code {
			bytes = append(bytes, fmt.Sprintf("0x%02x", b))
		}
		symbol := original
		if strings.Contains(execution.triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
		fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\nextern uint64_t %s(const uint8_t*);\n", name, original)
		operation, discarded := 0, 0
		if strings.HasPrefix(op, "SUB") || strings.HasPrefix(op, "SBB") {
			operation = 1
		} else if strings.HasPrefix(op, "AND") {
			operation = 2
		} else if strings.HasPrefix(op, "OR") {
			operation = 3
		} else if strings.HasPrefix(op, "XOR") {
			operation = 4
		}
		if dead {
			discarded = 1
		}
		effectiveCarry := 0
		if strings.HasPrefix(op, "ADC") || strings.HasPrefix(op, "SBB") {
			effectiveCarry = carry
		}
		fmt.Fprintf(&rows, "{%s,%s,%d,%d,%d,%d,%d},\n", name, original, width, operation, effectiveCarry, discarded, mode)
		count++
	}
	for _, op := range x86ScalarArithmeticNativeNames {
		width := map[byte]int{'B': 1, 'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
		for carry := 0; carry < 2; carry++ {
			if flagsAndAliases {
				appendKernel(op, width, carry, false, true, "")
				if width == 1 {
					for _, alias := range []string{"DH", "BH"} {
						appendKernel(op, width, carry, false, false, alias)
					}
				}
			} else {
				for _, dead := range []bool{false, true} {
					appendKernel(op, width, carry, dead, false, "")
				}
			}
		}
	}
	wantCount := 112
	if flagsAndAliases {
		wantCount = 84
	}
	if count != wantCount {
		t.Fatal("incomplete arithmetic/native state matrix", count, wantCount)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	// Reuse only the independent process/guard-page machinery. The arithmetic
	// reference below does not consume a production descriptor or lowering.
	start := strings.Index(x86ExtensionNativeRuntimeC, "static uint64_t reference(")
	end := strings.Index(x86ExtensionNativeRuntimeC, "static int fault(")
	if start < 0 || end <= start {
		t.Fatal("missing complete fault-harness boundary")
	}
	driverTemplate := x86ExtensionNativeRuntimeC[:start] + x86ScalarArithmeticNativeReferenceC + "\n" + x86ExtensionNativeRuntimeC[end:]
	driverTemplate = strings.NewReplacer(
		"unsigned width, destination, sign, dead;", "unsigned width, operation, carry, dead, flags;",
		"uint8_t bytes[8];", "uint8_t bytes[16];",
		"const uint8_t *p=bytes+(pattern&1);", `
            uint8_t *p=bytes+(pattern&1);
            uint64_t mask=k.width==8?UINT64_MAX:(UINT64_C(1)<<(k.width*8))-1;
            uint64_t sign=UINT64_C(1)<<(k.width*8-1), a=seed&mask;
            const uint64_t edges[]={0,1,mask,mask-1,sign,sign-1,a,a-1,a+1,~a,-a,-a-1};
            if(pattern<sizeof(edges)/sizeof(*edges)) {
                for(unsigned b=0;b<k.width;b++) p[b]=(uint8_t)(edges[pattern]>>(8*b));
            }`,
		"28 extension kernels", fmt.Sprintf("%d scalar arithmetic kernels", count),
	).Replace(driverTemplate)
	driver := fmt.Sprintf(driverTemplate, prototypes.String(), originals.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
					text, level := ir, "-O0"
					if optimized {
						text, level = x86MulDivRoundOptimize(t, ir), "-O2"
					}
					output := execution.compileAndRunLLVM(t, "scalar-arithmetic-native", text, driver, level)
					want := fmt.Sprintf("%d scalar arithmetic kernels: numerical %d, fault %d, tripwires 2; failures 0\n", count, count*128, count*12)
					if string(output) != want {
						t.Fatal("original Go/LLVM arithmetic differs", string(output), want)
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}

// Capture every SETcc-observable status bit before combining them with
// flag-writing arithmetic. MOV/SETcc preserve the original flags.
const x86ScalarArithmeticNativeFlagObserver = `MOVL $0,AX
MOVL $0,SI
MOVL $0,DI
MOVL $0,R10
MOVL $0,R11
SETCS AL
SETEQ SIB
SETMI DIB
SETOS R10B
SETPS R11B
SHLL $1,SI
SHLL $2,DI
SHLL $3,R10
SHLL $4,R11
ORL SI,AX
ORL DI,AX
ORL R10,AX
ORL R11,AX`

const x86ScalarArithmeticNativeReferenceC = `
static uint64_t reference(Kernel k, const uint8_t *p) {
    if(k.dead) return seed;
    uint64_t input=0;
    for(unsigned b=0;b<k.width;b++) input|=(uint64_t)p[b]<<(8*b);
    unsigned bits=k.width*8;
    uint64_t mask=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1;
    uint64_t a=seed&mask, sign=UINT64_C(1)<<(bits-1);
    uint64_t value;
    switch(k.operation) {
    case 0: value=a+input+k.carry; break;
    case 1: value=a-input-k.carry; break;
    case 2: value=a&input; break;
    case 3: value=a|input; break;
    default: value=a^input; break;
    }
    value&=mask;
    if(k.flags) {
        unsigned cf=0, of=0;
        if(k.operation<2) {
            cf=k.operation==1?(a<input || (k.carry && a==input)):
                (value<a || (k.carry && value==a));
            of=(((k.operation==1?(a^input):~(a^input))&(a^value)&sign)!=0);
        }
        unsigned ones=0;
        for(unsigned bit=0;bit<8;bit++) ones+=(value>>bit)&1;
        return cf|((value==0)<<1)|(((value&sign)!=0)<<2)|(of<<3)|((ones%%2==0)<<4);
    }
    if(k.width<4) return (seed&~mask)|value;
    return value;
}
`
