package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const fixedLocalGPWorkBlock = "ADDQ $3,AX\nRORQ $7,AX\nIMULQ $3,AX\nMULQ BX\nADCQ $1,DX\nSBBQ $1,AX\nCMPQ AX,DX\n"

func fixedLocalGPWorkSource(block string, repeats int, frame int64, partitioned bool) string {
	body := strings.Repeat(block, repeats)
	if partitioned {
		body = strings.Replace(fixedLocalLayoutPingPong, "loop:\n", "loop:\n"+body, 1)
		body = strings.Replace(body, "ret+16(FP)", "ret+8(FP)", 1)
	} else {
		body += "MOVQ AX,ret+8(FP)\nRET\n"
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$%d-16\nMOVQ a+0(FP),CX\nMOVQ $1,AX\nMOVQ $3,BX\n", frame) + body
}

func TestGoAMD64FixedLocalPartitionGPWork(t *testing.T) {
	source := fixedLocalGPWorkSource(fixedLocalGPWorkBlock, 128, 4096, true)
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal(err)
	}
	fn := file.Funcs[0]
	_, sig := fixedLocalReplayFixture(t, "")
	budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
	proven, err := proveX86FixedLocalAttempt(fn, sig, &budget, true)
	t.Logf("partition GP: steps=%d bytes=%d error=%v", budget.steps, budget.bytes, err)
	if err != nil || proven.x86FixedLocal == nil {
		t.Fatal("complete initialized GP register work must retain bounded frame costs", err)
	}
	used := (1 << 18) - budget.steps
	if used < 16*2*128*7 || budget.bytes <= 0 {
		t.Fatal("both layouts and sixteen phases must retain every real step", used, budget)
	}
	budget = x86FixedLocalBudget{steps: used - 1, bytes: 64 << 20}
	proven, err = proveX86FixedLocalAttempt(fn, sig, &budget, true)
	if !errors.Is(err, ErrProbeNeedsContext) || budget.steps != 0 || !reflect.DeepEqual(proven, fn) {
		t.Fatal("one missing GP step must fail atomically", budget, err)
	}
}

func TestGoAMD64FixedLocalPartitionGPRouting(t *testing.T) {
	rows := []struct {
		name, body string
		valid      bool
	}{
		{"multiply", "MOVQ $2,AX\nMOVQ $3,BX\nMULQ BX\nADDQ DX,AX", true},
		{"mulx", "MOVQ $2,DX\nMOVQ $3,BX\nMULXQ BX,AX,SI\nADDQ SI,AX", true},
		{"carry", "MOVQ $2,AX\nCMPQ AX,AX\nADCQ $1,AX\nSBBQ $1,AX", true},
		{"private add and mask", "MOVQ SP,AX\nADDQ $16,AX\nANDQ $-16,AX\nMOVQ $7,(AX)\nMOVQ (AX),AX", true},
		{"private constant", "MOVQ $16,BX\nMOVQ SP,AX\nADDQ BX,AX\nMOVQ $7,(AX)\nMOVQ (AX),AX", true},
		{"missing AX", "MOVQ $3,BX\nMULQ BX", false},
		{"missing DX", "MOVQ $3,BX\nMULXQ BX,AX,SI", false},
		{"missing carry", "MOVQ $2,AX\nADCQ $1,AX", false},
		{"private partial write", "MOVQ SP,AX\nADDL $8,AX", false},
		{"private escape", "MOVQ SP,AX\nADDQ $8,AX", false},
		{"private offset", "MOVQ SP,AX\nADDQ $72,AX\nMOVQ (AX),AX", false},
		{"private flags", "MOVQ $1,BX\nMOVQ SP,AX\nADDQ $16,AX\nADCQ $1,BX\nMOVQ BX,AX", false},
	}
	var assembly strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&assembly, "TEXT ·Value%d(SB),4,$64-16\n%s\nMOVQ AX,ret+8(FP)\nRET\n", index, row.body)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil || len(file.Funcs) != len(rows) {
		t.Fatal("complete routing inventory changed", err)
	}
	_, sig := fixedLocalReplayFixture(t, "")
	for index, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			fn := file.Funcs[index]
			budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
			proven, err := proveX86FixedLocalAttempt(fn, sig, &budget, true)
			if (err == nil) != row.valid {
				t.Fatal("cost classification changed the original semantic route", err)
			}
			if err != nil && (!errors.Is(err, ErrProbeNeedsContext) || !reflect.DeepEqual(proven, fn)) {
				t.Fatal("rejected GP input changed its error class or published a proof", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPartitionGPWorkProjection(t *testing.T) {
	rows := []struct {
		source string
		cheap  bool
	}{
		{"ADDB $1,AX", true}, {"ADDW $1,AX", true}, {"ADDL $1,AX", true}, {"ADDQ $1,AX", true},
		{"ANDQ $-16,AX", true}, {"ADCQ BX,AX", true}, {"SBBQ BX,AX", true}, {"CMPQ AX,$0", true},
		{"MULB BX", true}, {"MULW BX", true}, {"MULL BX", true}, {"MULQ BX", true},
		{"IMULQ BX", true}, {"MULXQ BX,AX,SI", true}, {"CMOVQEQ BX,AX", true},
		{"ADDQ (SP),AX", false}, {"MULQ (SP)", false}, {"ADDQ a+0(FP),AX", false},
		{"ADDQ value(SB),AX", false}, {"LEAQ (AX)(BX*8),CX", false}, {"BTQ AX,(BX)", false},
		{"PUSHQ AX", false}, {"POPQ AX", false}, {"CALL helper(SB)", false}, {"RET", false},
		{"REP", false}, {"JMP done", false}, {"ADDQ AX", false}, {"UNKNOWN AX", false},
	}
	for _, row := range rows {
		t.Run(row.source, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$64-16\n"+row.source+"\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[len(file.Funcs[0].Instrs)-1]
			effect, got := fixedLocalGPRegisterWork(ins)
			if got != row.cheap {
				t.Fatal("conservative source/effect work projection changed", got)
			}
			if !got && !reflect.DeepEqual(effect, x86TypedByteEffect{}) {
				t.Fatal("failed cost query retained a partial descriptor")
			}
			if !row.cheap {
				return
			}
			for _, metadata := range []string{"encoded", "raw", "address", "segment", "numerical"} {
				changed := ins
				switch metadata {
				case "encoded":
					changed.x86Encoded = true
				case "raw":
					changed.x86SourceRaw = &x86SourceRawInstruction{}
				case "address":
					changed.x86AddressBits = 32
				case "segment":
					changed.x86SegmentPrefix = 0x64
				case "numerical":
					changed.x86NumericalRead = &x86NumericalReadCertificate{}
				}
				if effect, cheap := fixedLocalGPRegisterWork(changed); cheap || !reflect.DeepEqual(effect, x86TypedByteEffect{}) {
					t.Fatal("source/native or numerical-read metadata received a register discount", metadata)
				}
			}
		})
	}
}

func BenchmarkFixedLocalGPWorkProjection(b *testing.B) {
	for _, partitioned := range []bool{false, true} {
		for _, memory := range []bool{false, true} {
			name := fmt.Sprintf("partition=%t/memory=%t", partitioned, memory)
			b.Run(name, func(b *testing.B) {
				block := fixedLocalGPWorkBlock
				if memory {
					block += "MOVQ AX,0(SP)\nMOVQ 0(SP),AX\n"
				}
				file, err := Parse(ArchAMD64, fixedLocalGPWorkSource(block, 8, 64, partitioned))
				if err != nil {
					b.Fatal(err)
				}
				fn := file.Funcs[0]
				_, sig := fixedLocalReplayFixture(b, "")
				run := func() {
					budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
					if _, err := proveX86FixedLocalAttempt(fn, sig, &budget, partitioned); err != nil {
						b.Fatal("benchmark must be a complete accepted proof", err)
					}
				}
				run()
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					run()
				}
			})
		}
	}
}
