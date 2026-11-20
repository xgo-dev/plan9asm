package plan9asm

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func x86SegmentMOVRegisters(arch string, width int) []Reg {
	registers := []Reg{AX, CX, DX, BX, SP, BP, SI, DI}
	if arch == "amd64" {
		registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
	}
	if width == 1 {
		registers = append(registers, AL, CL, DL, BL, AH, CH, DH, BH)
		if arch == "386" {
			// Go synthesizes BP/SI/DI byte rows but rejects direct SP.
			registers = append(append([]Reg{}, registers[:4]...), registers[5:]...)
		} else {
			registers = append(registers, BPB, SIB, DIB, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B)
		}
	}
	return registers
}

func TestX86SegmentMOVCompleteGoGrammarAndAliases(t *testing.T) {
	// This existing independent oracle pins every row of all four actual
	// ymov tables, including the distinct historical signed-imm32 table.
	TestX86GPSIMDTransferCompleteLegacyOriginalTables(t)
	x86OriginalMOVQAliases(t)
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []struct{ name, row string }{
		{"ymovb", "{Zm_r,1,argList{Ymb,Yrb}}"},
		{"ymovw", "{Zm_r,1,argList{Yml,Yrl}}"},
		{"ymovl", "{Zm_r,1,argList{Yml,Yrl}}"},
		{"ymovq", "{Zm_r,1,argList{Yml,Yrl}}"},
	} {
		definition := regexp.MustCompile(`(?s)var ` + table.name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(source))
		if len(definition) != 2 {
			t.Fatal("missing complete actual MOV table", table.name)
		}
		rows := regexp.MustCompile(`//[^\n]*`).ReplaceAllString(definition[1], "")
		rows = strings.Join(strings.Fields(rows), "")
		if strings.Count(rows, table.row) != 1 {
			t.Fatal("actual native memory-to-GP row is missing or duplicated", table.name)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86SegmentMOVRows(arch) {
			for _, segment := range []string{"FS", "GS"} {
				for _, address := range []string{"fixed", "fixed-zero", "base", "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8"} {
					_, memory := x86SegmentMOVAddress(arch, segment, address)
					for _, destination := range x86SegmentMOVRegisters(arch, row.width) {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/%s", arch, row.op, segment, address, destination), func(t *testing.T) {
							ins := x86ScalarLaneInstruction(t, row.op+" "+memory+","+string(destination))
							original := ins
							original.Args = append([]Operand(nil), ins.Args...)
							wantSource := ins.Args[0]
							if strings.HasPrefix(address, "segment-index-scale") {
								wantSource.Mem.Segment, wantSource.Mem.Index, wantSource.Mem.Scale = Reg(segment), "", 0
							}
							form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, arch)
							if !known || err != nil || form.bytes != int64(row.width) || form.destination != destination || !reflect.DeepEqual(form.source, wantSource) || !reflect.DeepEqual(ins, original) {
								t.Fatal("complete typed segment MOV row/alias changed", form, known, err)
							}
						})
					}
				}
				for _, mutation := range []string{"OffRaw", "IndexExt", "scale", "wide-offset", "unmodeled-CS-role", "illegal-source-GP-scaled-index"} {
					name := "outside-modeled-source-role-" + mutation
					if mutation == "unmodeled-CS-role" {
						name = mutation // CS is valid Go syntax, outside this FS/GS role.
					}
					t.Run(arch+"/"+row.op+"/"+segment+"/"+name, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, row.op+" 24("+segment+"),DX")
						switch mutation {
						case "OffRaw":
							ins.Args[0].Mem.OffRaw = "unresolved"
						case "IndexExt":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.IndexExt, ins.Args[0].Mem.Scale = CX, "UXTW", 4
						case "scale":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
						case "wide-offset":
							ins.Args[0].Mem.Off = 1 << 32
						case "unmodeled-CS-role":
							ins.Args[0].Mem.Segment = "CS"
						case "illegal-source-GP-scaled-index":
							ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 4
						}
						if _, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, arch); known && err == nil {
							if mutation == "unmodeled-CS-role" {
								t.Fatal("FS/GS-only source projection borrowed an unmodeled Go segment role")
							}
							t.Fatal("typed segment source accepted a representation outside its modeled source role", mutation)
						}
					})
				}
			}
		}
	}
	for _, alias := range []Reg{AH, CH, DH, BH} {
		want := map[Reg]Reg{AH: SP, CH: BP, DH: SI, BH: DI}[alias]
		ins := x86ScalarLaneInstruction(t, "MOVB -8(R8)(FS),"+string(alias))
		form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, "amd64")
		if !known || err != nil || form.destination != want {
			t.Fatal("Go's actual REX byte-register number was not preserved", alias, form, err)
		}
	}
}

func TestX86SegmentMOVOriginalGoEncodingWitnesses(t *testing.T) {
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	if !producer.schema.indexPrefix386 {
		t.Log("historical selected producer: 386 dynamic Index FS/GS emits no segment override; its object is not evidence of current segment-read execution equivalence")
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, segment := range []string{"FS", "GS"} {
			prefix := byte(0x64)
			if segment == "GS" {
				prefix = 0x65
			}
			for _, row := range x86SegmentMOVRows(arch) {
				t.Run(arch+"/"+row.op+"/"+segment+"/fixed-bytes", func(t *testing.T) {
					want := []byte{prefix}
					if row.width == 2 {
						want = append(want, 0x66)
					} else if row.width == 8 {
						want = append(want, 0x48)
					}
					opcode := byte(0x8b)
					if row.width == 1 {
						opcode = 0x8a
					}
					if arch == "386" {
						want = append(want, opcode, 0x0d, 24, 0, 0, 0, 0xc3)
					} else {
						want = append(want, opcode, 0x0c, 0x25, 24, 0, 0, 0, 0xc3)
					}
					source := "TEXT original(SB),4,$0-0\n" + row.op + " 24(" + segment + "),CX\nRET\n"
					if got := x86OrderingHintGoBytes(t, arch, source); !bytes.Equal(got, want) {
						t.Fatalf("actual full original byte witness differs: %x != %x", got, want)
					}
				})
			}
			for _, witness := range []struct {
				name, instruction string
				bytes             []byte
			}{
				{"base", "MOVB -8(BX)(" + segment + "),CX", append(producer.schema.dynamicPrefix(arch, segment), 0x8a, 0x4b, 0xf8, 0xc3)},
			} {
				t.Run(arch+"/"+segment+"/"+witness.name+"-bytes", func(t *testing.T) {
					got := x86OrderingHintGoBytes(t, arch, "TEXT original(SB),4,$0-0\n"+witness.instruction+"\nRET\n")
					if !bytes.Equal(got, witness.bytes) {
						t.Fatalf("actual complete dynamic-address bytes differ: %x != %x", got, witness.bytes)
					}
				})
			}
			for _, scale := range []string{"1", "2", "4", "8"} {
				t.Run(arch+"/"+segment+"/segment-annotation-scale"+scale, func(t *testing.T) {
					source := "TEXT original(SB),4,$0-0\nMOVL -8(BX)(" + segment + "*" + scale + "),DX\nRET\n"
					want := append(producer.schema.dynamicPrefix(arch, segment), 0x8b, 0x53, 0xf8, 0xc3)
					if got := x86OrderingHintGoBytes(t, arch, source); !bytes.Equal(got, want) {
						t.Fatalf("segment annotation changed actual GP address/scale: %x != %x", got, want)
					}
				})
			}
			t.Run(arch+"/"+segment+"/illegal-GP-scaled-index-source", func(t *testing.T) {
				x86SegmentMOVRejectScaledGPSource(t, arch, segment, producer.schema)
			})
			if arch == "amd64" {
				for index, alias := range []Reg{AH, CH, DH, BH} {
					t.Run(arch+"/"+segment+"/REX-"+string(alias), func(t *testing.T) {
						source := "TEXT original(SB),4,$0-0\nMOVB -8(R8)(" + segment + ")," + string(alias) + "\nRET\n"
						want := []byte{prefix, 0x41, 0x8a, byte(0x60 + 8*index), 0xf8, 0xc3}
						if got := x86OrderingHintGoBytes(t, arch, source); !bytes.Equal(got, want) {
							t.Fatalf("actual REX high-byte alias differs: %x != %x", got, want)
						}
					})
				}
			}
		}
		t.Run(arch+"/complete-register-address-banks", func(t *testing.T) {
			var source strings.Builder
			count := 0
			for _, row := range x86SegmentMOVRows(arch) {
				for _, segment := range []string{"FS", "GS"} {
					for _, address := range []string{"fixed", "fixed-zero", "base", "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8"} {
						_, memory := x86SegmentMOVAddress(arch, segment, address)
						for _, destination := range x86SegmentMOVRegisters(arch, row.width) {
							fmt.Fprintf(&source, "TEXT original%d(SB),4,$0-0\n%s %s,%s\nRET\n", count, row.op, memory, destination)
							count++
						}
					}
				}
			}
			triple := "x86_64-unknown-linux-gnu"
			want := 1610
			if arch == "386" {
				triple, want = "i386-unknown-linux-gnu", 434
			}
			if count != want || strings.Count(source.String(), "TEXT ") != want {
				t.Fatal("independent complete grammar denominator changed", count, want)
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
		})
	}
	for _, op := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		t.Run("386/no-GP-qword/"+op, func(t *testing.T) {
			requireLEANativeGoObject(t, "386", "TEXT invalid(SB),4,$0-0\n"+op+" 24(FS),AX\nRET\n", false)
		})
	}
}

func x86SegmentMOVRejectScaledGPSource(t *testing.T, arch, segment string, schema x86SegmentMOVEncoderSchema) {
	t.Helper()
	// This is an exact actual-Go invalid address tuple, separately from a
	// legal source's missing numerical/native permissions. The generic
	// oracle intentionally does not whitelist positionless asmidx messages.
	source := "TEXT invalid(SB),4,$0-0\nMOVL -8(" + segment + ")(CX*4),DX\nRET\n"
	dir := t.TempDir()
	input, object := filepath.Join(dir, "invalid.s"), filepath.Join(dir, "invalid.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	driver, _ := x86LEAActualSDKDriver(t)
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "tool", "asm", "-p", "segment", "-o", object, input)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goasmoracle.CheckOutcome(input, object, output, nil, err, ctx.Err(), false, 0, func(filename, diagnostic string) bool {
		original, readErr := os.ReadFile(filename)
		return readErr == nil && schema.acceptsScaledDiagnostic(filename, input, original, []byte(source), segment, diagnostic)
	}); failure != nil {
		t.Fatalf("exact invalid original Go address tuple lost its bound source diagnostic: %v\n%s", failure, output)
	}
}
