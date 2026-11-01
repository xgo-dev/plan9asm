package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86ScalarMoveAliasesOriginalGoTablesAndBytes(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		if entry.Opcode != "MOVQL" && entry.Opcode != "MOVLQZX" {
			continue
		}
		classes, code, table := "Yrl,Yml", "0x89", "yrl_ml"
		if entry.Opcode == "MOVLQZX" {
			classes, code, table = "Yml,Yrl", "0x8b", "yml_rl"
		}
		if seen[entry.Opcode] || entry.Kind != "encoding" || entry.Ytab != table || entry.Prefix != "Px" ||
			len(entry.OpBytes) != 1 || entry.OpBytes[0] != code || entry.EscapeAdjustment != 0 ||
			len(entry.Rows) != 1 || entry.Rows[0].RowIndex != 0 || entry.Rows[0].UnmatchedOffset != 0 ||
			entry.Rows[0].ZCase != "Zr_m" && entry.Opcode == "MOVQL" ||
			entry.Rows[0].ZCase != "Zm_r" && entry.Opcode == "MOVLQZX" ||
			entry.Rows[0].ZOffset != 1 || strings.Join(entry.Rows[0].Classes, ",") != classes {
			t.Fatal("complete scalar alias source table changed", entry)
		}
		seen[entry.Opcode] = true
	}
	if len(seen) != 2 {
		t.Fatal("missing an original scalar move alias", seen)
	}
	for _, arch := range []string{"amd64", "386"} {
		cases := []x86OfficialPackedCase{
			{witness: goasmrules.X86PackedBinaryWitness{Instruction: "MOVQL BX,CX", Encoding: []byte{0x89, 0xd9}}},
			{witness: goasmrules.X86PackedBinaryWitness{Instruction: "MOVQL CX,0(SI)", Encoding: []byte{0x89, 0x0e}}},
			{witness: goasmrules.X86PackedBinaryWitness{Instruction: "MOVLQZX BX,CX", Encoding: []byte{0x8b, 0xcb}}},
			{witness: goasmrules.X86PackedBinaryWitness{Instruction: "MOVLQZX 0(SI),CX", Encoding: []byte{0x8b, 0x0e}}},
		}
		if arch == "amd64" {
			cases = append(cases,
				x86OfficialPackedCase{witness: goasmrules.X86PackedBinaryWitness{Instruction: "MOVQL R8,BX", Encoding: []byte{0x44, 0x89, 0xc3}}},
				x86OfficialPackedCase{witness: goasmrules.X86PackedBinaryWitness{Instruction: "MOVLQZX R8,BX", Encoding: []byte{0x41, 0x8b, 0xd8}}})
		}
		var source strings.Builder
		for i := range cases {
			cases[i].symbol = fmt.Sprintf("ScalarAliasBytes%d", i)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", cases[i].symbol)
			cases[i].line = strings.Count(source.String(), "\n") + 1
			fmt.Fprintln(&source, cases[i].witness.Instruction)
			source.WriteString("RET\n")
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
			t.Fatal("original alias direction, width or REX encoding changed", arch, err)
		}
	}
}

func TestX86ScalarMoveAliasesByteEffectsAndPreservedRoles(t *testing.T) {
	for _, operation := range []string{"MOVQL R8,BX", "MOVQL AX,(R8)", "MOVLQZX R8,BX", "MOVLQZX (R8),BX"} {
		instruction := x86ScalarLaneInstruction(t, operation)
		if _, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, "386"); known && err == nil {
			t.Error("386 scalar alias acquired an amd64 register/address bank", operation)
		}
		if after := x86ResultCallerAddressesAfter(instruction, [16]bool{true}, nil, "386"); after != [16]bool{} {
			t.Error("invalid mode32 alias retained a caller-address fact", operation, after)
		}
		goAssemblerOracleOutput(t, "386", "TEXT mode(SB),4,$0-0\n"+operation+"\nRET\n", "", false)
	}
	for _, offset := range []string{"2147483648", "4294967295"} {
		for _, operation := range []string{"MOVQL AX," + offset + "(SI)", "MOVLQZX " + offset + "(SI),BX"} {
			instruction := x86ScalarLaneInstruction(t, operation)
			if _, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, "386"); !known || err != nil {
				t.Error("SCALAR_MOVE_ALIAS_UNSIGNED_OFFSET_GAP", operation, known, err)
			}
			goAssemblerOracleOutput(t, "386", "TEXT offset(SB),4,$0-0\n"+operation+"\nRET\n", "", true)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, operation := range []string{"MOVQL AX,BX", "MOVQL AX,0(SI)", "MOVLQZX AX,BX", "MOVLQZX 0(SI),BX"} {
			instruction := x86ScalarLaneInstruction(t, operation)
			effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch)
			if !known || err != nil || len(effect.operands) != 2 || effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.dynamicMemory {
				t.Error("SCALAR_MOVE_ALIAS_TYPED_EFFECT_GAP", arch, operation, effect, known, err)
				continue
			}
			read, write := effect.operands[0], effect.operands[1]
			if read.index != 0 || !read.read || read.write || read.width != 4 ||
				write.index != 1 || !write.write || write.read ||
				(write.width != 4 && !(arch == "amd64" && instruction.Args[1].Kind == OpReg && write.width == 8)) {
				t.Error("scalar alias lost exact four-byte input/store or GP zero-extension footprint", arch, operation, effect)
			}
		}
		for _, op := range []string{"MOVQL", "MOVLQZX"} {
			t.Run(arch+"/"+op, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, op+" AX,BX")
				canonical := x86ScalarLaneInstruction(t, "MOVL AX,BX")
				original := fmt.Sprintf("%#v", instruction)
				for mask := 0; mask < 256; mask++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.gp[0], state.gp[3], state.pointerGP[3] = uint8(mask), 0x80, true
					want, got := state.clone(), state.clone()
					accepted := x86ResultTransfer(canonical, &want, nil, 0, arch)
					actual := x86ResultTransfer(instruction, &got, nil, 0, arch)
					if actual != accepted || !reflect.DeepEqual(got, want) || accepted != (mask&15 == 15) {
						t.Fatal("SCALAR_MOVE_ALIAS_BYTE_FLOW_GAP", op, arch, mask, actual, accepted, got, want)
					}
					if actual && (got.gp[3] != 0xff || got.pointerGP[3] || got.flags != state.flags || got.direction != state.direction) {
						t.Fatal("scalar alias lost r32 zero extension or changed unrelated roles")
					}
				}
				// A source-width operation must preserve the existing MOVL
				// pointer-bit policy, including a complete mode32 word copy.
				pointer := x86ResultState{flags: x86ByteFlagCF}
				pointer.pointerGP[0] = true
				want, got := pointer.clone(), pointer.clone()
				accepted := x86ResultTransfer(canonical, &want, nil, 0, arch)
				if actual := x86ResultTransfer(instruction, &got, nil, 0, arch); actual != accepted || !reflect.DeepEqual(got, want) {
					t.Fatal("scalar alias invented NUM or lost the existing whole-word pointer role", arch, op, got, want)
				}
				addresses := [16]bool{}
				addresses[2], addresses[3] = true, true
				wantAddresses := x86ResultCallerAddressesAfter(canonical, addresses, nil, arch)
				if gotAddresses := x86ResultCallerAddressesAfter(instruction, addresses, nil, arch); gotAddresses != wantAddresses {
					t.Fatal("SCALAR_MOVE_ALIAS_ADDRESS_FOOTPRINT_GAP", arch, op, gotAddresses, wantAddresses)
				}
				if fmt.Sprintf("%#v", instruction) != original {
					t.Fatal("alias effect changed original Op, Raw or operands")
				}
			})
			if arch == "386" {
				t.Run("386/native-pointer-copy/"+op, func(t *testing.T) {
					// Px copies one complete 32-bit word on this mode. Preserve
					// its actual pointer identity without turning its bits into NUM.
					source := "TEXT ·Value(SB),4,$0-8\nMOVL p+0(FP),AX\n" + op + " AX,SI\nMOVL (SI),BX\nMOVL BX,ret+4(FP)\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *uint32) uint32", arch, "i386-unknown-linux-gnu", api); err != nil || ir == "" {
								t.Fatal("SCALAR_MOVE_ALIAS_WORD_POINTER_GAP", op, api, err)
							}
						})
					}
				})
			}
		}
	}
}

func scalarMoveAliasFunction(name, arch, op string, memory bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	if !memory {
		return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),AX\n%s AX,BX\n%s BX,ret+%d(FP)\nRET\n", name, 2*word, move, op, move, word),
			fmt.Sprintf("func %s(x uintptr) uintptr\n", name)
	}
	if op == "MOVQL" {
		return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),SI\n%s x+%d(FP),AX\nMOVQL AX,1(SI)\nMOVL 1(SI),BX\n%s BX,ret+%d(FP)\nRET\n", name, 3*word, move, move, word, move, 2*word),
			fmt.Sprintf("func %s(p *[8]byte,x uintptr) uintptr\n", name)
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),SI\nMOVLQZX 1(SI),BX\n%s BX,ret+%d(FP)\nRET\n", name, 2*word, move, move, word),
		fmt.Sprintf("func %s(p *[8]byte) uintptr\n", name)
}

func TestX86ScalarMoveAliasesInitializedThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, op := range []string{"MOVQL", "MOVLQZX"} {
				for _, memory := range []bool{false, true} {
					body, declaration := scalarMoveAliasFunction(fmt.Sprintf("ScalarAlias%d", count), target.arch, op, memory)
					source.WriteString(body)
					declarations.WriteString(declaration)
					count++
				}
			}
			if count != 4 {
				t.Fatal("incomplete source/destination alias directions")
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("SCALAR_MOVE_ALIAS_INITIALIZED_GAP", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) { x86PackedStringCompileObject(t, llc, target.triple, ir, level) })
					}
				})
			}
		})
	}
}

func TestX86ScalarMoveAliasesMissingInputAndFormatsRemainRejected(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := goWordSize(arch), "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		triple := x86Legacy127Targets(arch)[0]
		for _, op := range []string{"MOVQL", "MOVLQZX"} {
			for _, sample := range []struct{ name, body string }{
				{"missing-source", op + " AX,BX"},
				{"partial-source", "MOVB $1,AX\n" + op + " AX,BX"},
			} {
				t.Run(arch+"/"+op+"/"+sample.name, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n%s BX,ret+0(FP)\nRET\n", word, sample.body, move)
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uintptr", arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("alias syntax supplied missing numerical input", op, sample.name, api, err)
						}
					}
				})
			}
		}
		for _, operation := range []string{
			"MOVQL $1,BX", "MOVQL (SI),BX", "MOVQL x+0(FP),BX", "MOVQL (SI),(DI)",
			"MOVQL AL,BX", "MOVQL AH,BX", "MOVQL X0,BX", "MOVQL M0,BX", "MOVQL AX,X0", "MOVQL.Z AX,BX",
			"MOVLQZX $1,BX", "MOVLQZX AX,(SI)", "MOVLQZX (SI),(DI)", "MOVLQZX AH,BX", "MOVLQZX M0,BX",
		} {
			t.Run(arch+"/invalid/"+operation, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n%s BX,ret+0(FP)\nRET\n", word, operation, move)
				goAssemblerOracleOutput(t, arch, source, "", false)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uintptr", arch, triple, api); err == nil || ir != "" {
						t.Fatal("alias widened beyond its original directional table", arch, operation, api, err)
					}
				}
			})
		}
	}
}

func TestX86ScalarMoveAliasesNativeAddressAndSourceIdentityBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := goWordSize(arch), "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		triple := x86Legacy127Targets(arch)[0]
		for _, op := range []string{"MOVQL", "MOVLQZX"} {
			source, declaration := scalarMoveAliasFunction("Value", arch, op, true)
			pointerLoad := move + " p+0(FP),SI\n"
			if strings.Count(source, pointerLoad) != 1 {
				t.Fatal("native negative no longer removes exactly one pointer input")
			}
			for name, changed := range map[string]string{
				"unknown-base":  strings.Replace(source, pointerLoad, "", 1),
				"numeric-base":  strings.Replace(source, pointerLoad, "MOVL $42,SI\n", 1),
				"pointer-index": strings.ReplaceAll(source, "1(SI)", "1(SI)(SI*1)"),
			} {
				t.Run(arch+"/"+op+"/"+name, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, changed, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("scalar alias supplied native address authority", op, name, api, err)
						}
					}
				})
			}
			for _, mutation := range []string{"decoded", "raw"} {
				t.Run(arch+"/"+op+"/"+mutation, func(t *testing.T) {
					body := fmt.Sprintf("%s x+0(FP),AX\nMOVL $7,DX\n%s AX,BX\n%s BX,ret+%d(FP)\nRET", move, op, move, word)
					_, file, sig, original := x86ResultInitializationFixture(t, arch, "func Value(x uintptr) uintptr", body)
					goAssemblerOracleOutput(t, arch, original, "", true)
					changed := 0
					for index := range file.Funcs[0].Instrs {
						ins := &file.Funcs[0].Instrs[index]
						if ins.Op != Op(op) {
							continue
						}
						changed++
						switch mutation {
						case "decoded":
							ins.x86Encoded = true
						case "raw":
							ins.x86SourceRaw = new(x86SourceRawInstruction)
						}
					}
					if changed != 1 {
						t.Fatal("source identity negative lost its single original operation")
					}
					options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"Value": sig},
						ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
					ir, err := Translate(file, options)
					if op == "MOVQL" {
						if err == nil || ir != "" {
							t.Fatal("new source alias authenticated an unbound physical producer", op, mutation, err)
						}
						return
					}
					// The existing extension consumer already admits pure NUM
					// register effects with these markers. Preserve that allowance;
					// a marker must still not authorize a new native memory read.
					if err != nil || ir == "" {
						t.Fatal("existing numerical raw extension regressed", mutation, err)
					}
					memoryBody := fmt.Sprintf("%s p+0(FP),AX\nMOVLQZX (AX),BX\n%s BX,ret+%d(FP)\nRET", move, move, word)
					_, memoryFile, memorySig, memorySource := x86ResultInitializationFixture(t, arch, "func Value(p *uint32) uintptr", memoryBody)
					goAssemblerOracleOutput(t, arch, memorySource, "", true)
					for index := range memoryFile.Funcs[0].Instrs {
						ins := &memoryFile.Funcs[0].Instrs[index]
						if ins.Op == "MOVLQZX" {
							ins.x86Encoded = mutation == "decoded"
							if mutation == "raw" {
								ins.x86SourceRaw = new(x86SourceRawInstruction)
							}
						}
					}
					options.Sigs = map[string]FuncSig{"Value": memorySig}
					if ir, err := Translate(memoryFile, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("numerical raw extension acquired native read authority", mutation, err)
					}
				})
			}
		}
	}
}
