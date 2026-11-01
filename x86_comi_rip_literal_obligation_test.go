package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86COMIRIPLiteralRow struct {
	op, encoding string
	code         []byte
	width        int
}

func x86COMIRIPLiteralRows(t *testing.T) []x86COMIRIPLiteralRow {
	t.Helper()
	var rows []x86COMIRIPLiteralRow
	var original strings.Builder
	for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		for _, encoding := range []string{"vex2", "vex3", "evex"} {
			width := 4
			if strings.HasSuffix(op, "SD") {
				width = 8
			}
			row := x86COMIRIPLiteralRow{op, encoding, x86RawScalarFlagCompareLiteral(op, encoding), width}
			// Disassemble only the complete physical instruction. RET and
			// the source-local scalar pool are independently retained below.
			x86NumericalNativeRequireMC(t, row.code[:len(row.code)-width-1], 64, 1, "+avx,+avx512f,+avx512vl")
			original.WriteString(x86COMIRIPLiteralSource(row, fmt.Sprint("Original", len(rows)), "PXOR X0,X0\n"))
			rows = append(rows, row)
		}
	}
	if len(rows) != 12 {
		t.Fatal("complete scalar COMI literal directory changed")
	}
	goAssemblerOracleOutput(t, "amd64", original.String(), "", true)
	return rows
}

func x86COMIRIPLiteralSource(row x86COMIRIPLiteralRow, name, setup string) string {
	return "TEXT ·" + name + "(SB),4,$0-0\n" + setup + x86RawDisplacementDirectives(row.code)
}

func x86COMIRIPLiteralNormalized(t *testing.T, source string) (*File, int) {
	t.Helper()
	file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
	if err != nil || len(file.Funcs) != 1 || len(file.Data) != 1 {
		t.Fatal("complete scalar COMI source lost its actual literal pool", err)
	}
	ordinal := -1
	for index, instruction := range file.Funcs[0].Instrs {
		if instruction.x86RIPLiteral {
			if ordinal >= 0 {
				t.Fatal("ambiguous scalar COMI source literal")
			}
			ordinal = index
		}
	}
	if ordinal < 0 || file.Funcs[0].x86RawReplay == nil || file.Funcs[0].x86RawReplay.validate(file.Funcs[0], "amd64") != nil {
		t.Fatal("complete scalar COMI literal lost its immutable producer")
	}
	return file, ordinal
}

func TestX86COMIRIPLiteralCompleteInitializedSources(t *testing.T) {
	for _, row := range x86COMIRIPLiteralRows(t) {
		t.Run(row.op+"/"+row.encoding, func(t *testing.T) {
			source := x86COMIRIPLiteralSource(row, "Value", "PXOR X0,X0\n")
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, target := range x86AddressMemoryTargets("amd64") {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()\n", "amd64", target, api)
						if err != nil || ir == "" {
							t.Fatal("complete initialized scalar COMI literal needs its existing DATA/RET owner", err)
						}
						if strings.Count(ir, "~{flags},~{fpsr},~{memory}") != 1 || !strings.Contains(ir, fmt.Sprintf("elementtype([%d x i8])", row.width)) {
							t.Fatal("scalar COMI literal lost its exact whole native read/MXCSR effect")
						}
					})
				}
			}
		})
	}
}

func TestX86COMIRIPLiteralDoesNotInventInputsOrSourceOwnership(t *testing.T) {
	for _, row := range x86COMIRIPLiteralRows(t) {
		t.Run(row.op+"/"+row.encoding, func(t *testing.T) {
			for _, setup := range []string{"", "MOVB $0,AL\nMOVL AX,X0\n"} {
				source := x86COMIRIPLiteralSource(row, "Value", setup)
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("missing-input-%t/%s", setup != "", api), func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()\n", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("scalar COMI literal supplied missing or partial X0 bytes", err)
						}
					})
				}
			}
			source := x86COMIRIPLiteralSource(row, "Value", "PXOR X0,X0\n")
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, mutation := range []string{"valid", "origin", "arch", "generation", "encoded", "operand", "tuple",
				"short-data", "missing-replay", "producer", "original-bytes", "data-bytes", "data-extent"} {
				t.Run(mutation, func(t *testing.T) {
					file, ordinal := x86COMIRIPLiteralNormalized(t, source)
					original := file.Funcs[0]
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					instruction := &candidate.Instrs[ordinal]
					resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
					signatures := map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}
					context := amd64Ctx{fpScalarSource: candidate, sig: signatures["Value"], fpSourceSig: signatures["Value"],
						goarch: "amd64", targetTriple: "x86_64-unknown-linux-gnu", resolve: resolve,
						fpScalarData: x86LoweredScalarDataReads(file, resolve, signatures, "amd64")}
					switch mutation {
					case "origin":
						instruction.x86SourceRaw = nil
					case "arch":
						instruction.x86SourceRaw.comi.arch = "386"
					case "generation":
						instruction.x86ScalarFlagCompareEVEX = !instruction.x86ScalarFlagCompareEVEX
					case "encoded":
						instruction.x86Encoded = !instruction.x86Encoded
					case "operand":
						instruction.Args[0].Sym = "external(SB)"
					case "tuple":
						instruction.x86RIPMemoryRead.width--
					case "short-data":
						address, valid := x86StaticSBReadAddress(instruction.Args[0], "amd64")
						if !valid || context.fpScalarData[address] != int64(row.width) {
							t.Fatal("original literal lacks its exact independent DATA extent")
						}
						context.fpScalarData[address]--
					case "missing-replay":
						candidate.x86RawReplay = nil
					case "producer":
						candidate.Instrs[1].Raw += " changed"
					case "original-bytes":
						replay := *original.x86RawReplay
						replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
						candidate.x86RawReplay = &replay
					case "data-bytes":
						file.Data[0].Payload = append([]byte(nil), file.Data[0].Payload...)
						file.Data[0].Payload[0] ^= 1
					case "data-extent":
						file.Data[0].Width--
						file.Data[0].Payload = append([]byte(nil), file.Data[0].Payload[:len(file.Data[0].Payload)-1]...)
					}
					var err error
					if strings.HasPrefix(mutation, "data-") {
						if _, err := dataStmtPayload(file.Data[0]); err != nil {
							t.Fatal("literal mutation is not a valid DATA statement", err)
						}
						var ir string
						ir, err = Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: signatures, ResolveSym: resolve})
						if ir != "" {
							t.Fatal("changed literal DATA supplied a public translation")
						}
					} else {
						if mutation != "valid" && mutation != "short-data" && reflect.DeepEqual(candidate, original) {
							t.Fatal("literal mutation did not alter its original source identity")
						}
						context.fpScalarSource = candidate
						err = context.checkLoweredScalarFPResultInitialization()
					}
					if mutation == "valid" {
						if err != nil {
							t.Fatal("existing literal owner lost its complete initialized COMI source", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("COMI literal borrowed missing data or a different source/entry identity", mutation, err)
					}
					if original.x86RawReplay.validate(original, "amd64") != nil {
						t.Fatal("a literal clone mutated its independently sealed original producer")
					}
				})
			}
		})
	}
}
