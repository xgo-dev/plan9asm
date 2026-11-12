package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The independent directory binds all Go broadcast rows, including the two
// mask-register-only names. Only the eighteen scalar/block names read memory.
func x86BroadcastMemoryRows() []string {
	var rows []string
	for _, spec := range x86BroadcastTestDirectory {
		if spec.source == "K" {
			continue
		}
		for _, bank := range spec.destinations {
			rows = append(rows, fmt.Sprintf("%s table<>+0(SB),%c2", spec.name, bank))
			if spec.table != "_yvbroadcastf128" {
				rows = append(rows,
					fmt.Sprintf("%s table<>+0(SB),K3,%c2", spec.name, bank),
					fmt.Sprintf("%s.Z table<>+0(SB),K3,%c2", spec.name, bank))
			}
		}
	}
	return rows
}

func TestX86BroadcastMemoryResultExactSourceBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, spec := range x86BroadcastTestDirectory {
			if spec.source == "K" {
				continue
			}
			for _, role := range []string{"FP", "AUTO", "DATA"} {
				t.Run(arch+"/"+spec.name+"/"+role, func(t *testing.T) {
					address := "x+0(FP)"
					if role == "AUTO" {
						address = fmt.Sprintf("local-%d(SP)", spec.bytes)
					} else if role == "DATA" {
						address = "table<>+0(SB)"
					}
					ins := x86YMMReadSource(t, fmt.Sprintf("%s %s,%c2", spec.name, address, spec.destinations[0]))
					for _, consumer := range x86ResultGPSIMDConsumers {
						for missing := -1; missing < spec.bytes; missing++ {
							state := x86ResultState{fp: make([]bool, spec.bytes), auto: make([]bool, spec.bytes), flags: x86ByteFlagsAll}
							owned := make([]bool, spec.bytes)
							for i := range owned {
								owned[i], state.fp[i], state.auto[i] = true, i != missing, i != missing
							}
							if role == "DATA" {
								extent := spec.bytes
								if missing >= 0 {
									extent = missing
								}
								state.loweredStaticReads = map[x86StaticSBAddress]int64{{symbol: "table<>"}: int64(extent)}
							}
							accepted := consumer.step(ins, &state, owned, int64(spec.bytes), arch)
							if accepted != (missing == -1) {
								t.Fatalf("%s missing byte %d: accepted=%t", consumer.name, missing, accepted)
							}
							if accepted && (state.vectorBytes(2) != ^uint64(0) || state.flags != x86ByteFlagsAll) {
								t.Fatal("broadcast lost VEX/EVEX upper zeroing or changed flags")
							}
						}
					}
				})
			}
		}
	}
}

func TestX86BroadcastSameFileDataThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	rows := x86BroadcastMemoryRows()
	if len(rows) != 104 {
		t.Fatalf("complete independent memory forms changed: %d", len(rows))
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for start := 0; start < len(rows); start += 64 {
				end := start + 64
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch-%d", start/64), func(t *testing.T) {
					var source, declarations strings.Builder
					source.WriteString(x86ScalarResultDataTable)
					for index, row := range rows[start:end] {
						fmt.Fprintf(&declarations, "func broadcast%d() uint32\n", index)
						fmt.Fprintf(&source, "TEXT ·broadcast%d(SB),4,$0-4\n", index)
						if strings.Contains(row, "K3,") {
							source.WriteString("MOVL $5,AX\nKMOVD AX,K3\n")
							if !strings.Contains(row, ".Z ") {
								source.WriteString("VPXORD Z2,Z2,Z2\n")
							}
						}
						source.WriteString(row + "\nVPEXTRD $0,X2,AX\nMOVL AX,ret+0(FP)\nRET\n")
					}
					goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil {
								t.Fatal("same-file DATA cannot supply the complete typed broadcast read", err)
							}
							x86ResultInitializationObject(t, llc, target.triple, ir, "memory-broadcast-"+api)
						})
					}
				})
			}
		})
	}
}

func TestX86BroadcastMemoryResultMaskAndAddressBoundaries(t *testing.T) {
	widths := make(map[string]int)
	for _, spec := range x86BroadcastTestDirectory {
		widths[spec.name] = spec.bytes
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86BroadcastMemoryRows() {
			ins := x86YMMReadSource(t, row)
			name, _, _ := strings.Cut(string(ins.Op), ".")
			width := widths[name]
			for _, consumer := range x86ResultGPSIMDConsumers {
				for _, mutation := range []string{"complete", "short", "foreign symbol", "negative", "address override", "unbound override", "unknown mask", "unknown merge", "native pointer"} {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.writeVector(2, 64, ^uint64(0), false)
					state.masks[3] = true
					address := x86StaticSBAddress{symbol: "table<>"}
					state.loweredStaticReads = map[x86StaticSBAddress]int64{address: int64(width)}
					probe := ins
					probe.Args = append([]Operand(nil), ins.Args...)
					want := mutation == "complete"
					switch mutation {
					case "short":
						state.loweredStaticReads[address]--
					case "foreign symbol":
						probe.Args[0] = x86YMMReadSource(t, "MOVQ foreign(SB),AX").Args[0]
					case "negative":
						probe.Args[0] = x86YMMReadSource(t, "MOVQ table<>-1(SB),AX").Args[0]
					case "address override":
						probe.x86AddressBits = 32
					case "unbound override":
						probe.x86UnboundAddressOverride = true
					case "unknown mask":
						state.masks[3] = false
						want = !strings.Contains(row, "K3,")
					case "unknown merge":
						state.xmm[2], state.vectorUpper[2] = 0, 0
						want = !strings.Contains(row, "K3,") || strings.Contains(row, ".Z ")
					case "native pointer":
						probe.Args[0] = x86YMMReadSource(t, "MOVQ (AX),BX").Args[0]
						state.gp[0], state.pointerGP[0] = 255, true
					}
					if got := consumer.step(probe, &state, nil, 0, arch); got != want {
						t.Fatalf("%s %s %s %s: accepted=%t want=%t", arch, consumer.name, row, mutation, got, want)
					}
				}
			}
		}
	}
}

func TestX86BroadcastDataResultDoesNotGrantStandaloneRead(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86BroadcastMemoryRows() {
			body := "MOVL $1,AX\nKMOVD AX,K3\nVPXORD Z2,Z2,Z2\n" + row +
				"\nVPEXTRD $0,X2,AX\nMOVL AX,ret0+0(FP)\nRET"
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("standalone query acquired DATA permission: %s: %v", row, err)
				}
			}
		}
	}
}
