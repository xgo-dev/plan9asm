package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent yxmov whole128 directory; MOVOA is cmd/asm's MOVO alias.
// The complete original opcode/prefix/zcase oracle is separately retained by
// TestX86GoCallerLegacyMoveCompleteGoRows, not derived from production's map.
var x86PrivateLegacyReadNames = []string{
	"MOVOU", "MOVOA", "MOVO", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD",
}

func x86PrivateLegacyReadOriginal(t *testing.T, body string) (*File, FuncSig, Options) {
	t.Helper()
	assembly := "TEXT ·kernel(SB),4,$0-32\nMOVQ a+0(FP),DI\n" + body + "\nBYTE $0xc3\n"
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigs["caller.kernel"]
	if sig.Ret != Void || len(sig.Frame.Results) != 0 || len(sig.Args) != 4 ||
		sig.x86CallerRegions == nil || !x86CallerRegionSourceMatches(sig, file.Funcs[0], "amd64") {
		t.Fatal("actual source and same pointer-only Void signature prerequisite is missing")
	}
	for _, argument := range sig.Args {
		if argument != Ptr {
			t.Fatal("fixture changed the existing four-pointer caller domain")
		}
	}
	return file, sig, Options{Goarch: "amd64", ResolveSym: resolve, Sigs: sigs}
}

func x86PrivateLegacyReadProved(t *testing.T, body string, width int64) (Func, FuncSig) {
	t.Helper()
	file, sig, options := x86PrivateLegacyReadOriginal(t, body)
	normalized, err := normalizeX86RawFile(file, "amd64", options)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Funcs) != 1 || !x86CallerNormalizedSourceMatches(normalized.Funcs[0], sig) {
		t.Fatal("whole normalized source does not match its exact caller signature")
	}
	fn := normalized.Funcs[0]
	found := 0
	for ordinal, ins := range fn.Instrs {
		// Native pointer imports have their own exact FP/physical-stack
		// certificate. Select the actual DI-to-X numerical source role first.
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != DI ||
			ins.Args[1].Kind != OpReg || !isAMD64XReg(ins.Args[1].Reg) {
			continue
		}
		access, present := ins.x86CallerMemory[0]
		if !present || access.write || access.width != width || !x86CallerMemoryCertified(ins, 0) {
			t.Fatalf("instruction %d lacks its exact numerical-source read%d certificate", ordinal, width)
		}
		found++
	}
	if found != 1 {
		t.Fatalf("source has %d certified reads, want exactly one", found)
	}
	return fn, sig
}

func TestX86PrivateLegacyReadObserverCompleteSourceForms(t *testing.T) {
	// Input is the existing numerical slice-origin/nonalias contract, not an
	// allocation or native-pointer extent. The independent producer must pass
	// before these leaves can diagnose the private observer.
	for _, op := range x86PrivateLegacyReadNames {
		for _, destination := range []string{"X1", "X0"} {
			t.Run(op+"/register_"+destination, func(t *testing.T) {
				body := "MOVOU (DI),X0\n" + op + " X0," + destination + "\nPEXTRD $3," + destination + ",AX"
				fn, sig := x86PrivateLegacyReadProved(t, body, 16)
				if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("public declaration-only Void query acquired caller memory: %v", err)
				}
				if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
					t.Errorf("private observer lost a same-source exact read16 before %s register transfer: %v", op, err)
				}
			})
		}
	}
	for _, op := range []string{"MOVOU", "MOVUPS", "MOVUPD"} {
		for _, address := range []string{"(DI)", "4(DI)", "4(DI)(BX*2)"} {
			t.Run(op+"/read_"+address, func(t *testing.T) {
				body := "MOVQ $1,BX\n" + op + " " + address + ",X0\nPEXTRD $3,X0,AX"
				fn, sig := x86PrivateLegacyReadProved(t, body, 16)
				if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
					t.Errorf("private observer discarded a proved full-width source read: %v", err)
				}
			})
		}
	}
}

func TestX86PrivateLegacyReadObserverExistingByteCounterparts(t *testing.T) {
	// These are ordinary logical byte-effect models, never caller producers.
	// In particular, logical FP/AUTO bytes do not prove native alignment/backing.
	forms := []string{
		"X0,X1", "X0,X0", "a+0(FP),X1", "X0,ret0+16(FP)",
		"value-32(SP),X1", "X0,value-16(SP)",
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86PrivateLegacyReadNames {
			for _, operands := range forms {
				t.Run(arch+"/"+op+"/"+operands, func(t *testing.T) {
					ins := x86CallerLegacyMoveInstruction(t, op+" "+operands)
					effect, known, err := x86TypedLegacyPackedMoveByteEffect(ins.Op, ins, arch)
					if !known || err != nil || len(effect.operands) != 2 || effect.flagsRead != 0 ||
						effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.dynamicMemory {
						t.Fatalf("whole128 descriptor differs from the independent move rows: %+v/%v", effect, err)
					}
					for index, operand := range effect.operands {
						if operand.index != index || operand.width != 16 || operand.read != (index == 0) ||
							operand.write != (index == 1) || !reflect.DeepEqual(operand.operand, ins.Args[index]) {
							t.Fatal("typed effect changed source/destination, direction or exact width")
						}
					}
					owned := make([]bool, 32)
					state := x86ResultState{fp: make([]bool, 32), auto: make([]bool, 32), flags: x86ByteFlagCF | x86ByteFlagOF}
					for offset := range owned {
						owned[offset] = true
						state.fp[offset], state.auto[offset] = offset < 16, offset < 16
					}
					state.xmm[0] = 0xffff
					for _, transfer := range []func(Instr, *x86ResultState, []bool, int64, string) bool{x86ResultTransfer, x86ScalarFPResultTransfer} {
						copy := state.clone()
						if !transfer(ins, &copy, owned, 16, arch) || copy.flags != state.flags {
							t.Fatal("existing full-byte transition failed or changed numerical flags")
						}
						if !x86ResultRead(ins.Args[1], 16, &copy, owned, arch) {
							t.Fatal("complete move failed to define exactly its observed destination")
						}
					}
				})
			}
			for missing := 0; missing < 16; missing++ {
				t.Run(fmt.Sprintf("%s/%s/missing-byte%d", arch, op, missing), func(t *testing.T) {
					ins := x86CallerLegacyMoveInstruction(t, op+" X0,X1")
					state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagOF}
					state.xmm[0], state.xmm[1] = 0xffff&^(uint16(1)<<uint(missing)), 0xffff
					before := state.clone()
					if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(before, state) {
						t.Fatal("private observer fabricated an unknown source byte from old destination")
					}
				})
			}
		}
	}
	// Wider aliases belong to the caller's existing bank, not to an expanded
	// private observer state. A low128 copy must preserve both upper canaries.
	for _, op := range x86PrivateLegacyReadNames {
		ins := x86CallerLegacyMoveInstruction(t, op+" X0,X1")
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": 0xffff, "Z1": 1<<20 | 1<<48}}
		if !x86CallerVectorMoveStep(&ins, &state, nil) || state.vectors["Z1"] != 1<<20|1<<48|0xffff {
			t.Fatal("legacy register transition changed upper Y/Z aliases", op)
		}
	}
}

func x86PrivateLegacyReadClone(fn Func) Func {
	fn.Instrs = append([]Instr(nil), fn.Instrs...)
	for index := range fn.Instrs {
		ins := &fn.Instrs[index]
		ins.Args = append([]Operand(nil), ins.Args...)
		copy := make(map[int]x86CallerMemoryAccess)
		for operand, access := range ins.x86CallerMemory {
			access.args = append([]Operand(nil), access.args...)
			copy[operand] = access
		}
		ins.x86CallerMemory = copy
	}
	return fn
}

func TestX86PrivateLegacyReadObserverExactAuthorityRequired(t *testing.T) {
	for _, op := range []string{"MOVOU", "MOVUPS", "MOVUPD"} {
		fn, signature := x86PrivateLegacyReadProved(t, op+" (DI),X0\nPEXTRD $3,X0,AX", 16)
		_, other := x86PrivateLegacyReadProved(t, op+" (DI),X0\nPEXTRD $3,X0,AX", 16)
		t.Run(op+"/instruction-only", func(t *testing.T) {
			for _, ins := range fn.Instrs {
				if ins.Op != Op(op) {
					continue
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.pointerGP[7], state.gp[7] = true, 0xff
				for _, transfer := range []func(Instr, *x86ResultState, []bool, int64, string) bool{x86ResultTransfer, x86ScalarFPResultTransfer} {
					copy := state.clone()
					if transfer(ins, &copy, nil, 0, "amd64") {
						t.Fatal("instruction certificate or opaque pointer bits alone acquired numerical pointee bytes")
					}
				}
			}
		})
		for _, change := range []string{
			"missing-caller", "missing-source", "other-private-owner", "different-signature", "different-function",
			"different-ordinal", "changed-source-byte", "operand-offset", "move-width", "read-to-store",
			"missing-access", "access-width", "access-direction", "access-operands", "address-override", "JSON-copy",
		} {
			t.Run(op+"/"+change, func(t *testing.T) {
				changed, sig := x86PrivateLegacyReadClone(fn), signature
				for index := range changed.Instrs {
					ins := &changed.Instrs[index]
					if ins.Op != Op(op) {
						continue
					}
					access := ins.x86CallerMemory[0]
					switch change {
					case "operand-offset":
						ins.Args[0].Mem.Off++
					case "move-width":
						ins.Op = "MOVSD"
					case "read-to-store":
						ins.Args[0], ins.Args[1] = ins.Args[1], ins.Args[0]
					case "missing-access":
						delete(ins.x86CallerMemory, 0)
					case "access-width":
						access.width = 8
					case "access-direction":
						access.write = true
					case "access-operands":
						access.args[0].Mem.Off++
					case "address-override":
						ins.x86AddressBits = 32
					case "changed-source-byte":
						ins.Raw += " // changed original source"
					}
					if strings.HasPrefix(change, "access-") {
						ins.x86CallerMemory[0] = access
					}
				}
				switch change {
				case "missing-caller":
					sig.x86CallerRegions = nil
				case "missing-source":
					changed.x86SourceStack = nil
				case "other-private-owner":
					sig.x86CallerRegions = other.x86CallerRegions
				case "different-signature":
					sig.Name += ".changed"
				case "different-function":
					changed.Sym += ".changed"
				case "different-ordinal":
					prefix := append([]Instr(nil), changed.Instrs[:2]...)
					prefix = append(prefix, Instr{Op: "NOP", Raw: "NOP"})
					changed.Instrs = append(prefix, changed.Instrs[2:]...)
				case "JSON-copy":
					data, err := json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
					changed = Func{}
					if err := json.Unmarshal(data, &changed); err != nil {
						t.Fatal(err)
					}
				}
				if err := checkX86ScalarFPResultInitialization(changed, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("private observer borrowed changed or missing exact source/read authority: %v", err)
				}
			})
		}
	}
}

func TestX86PrivateLegacyReadObserverKeepsIndependentDomains(t *testing.T) {
	// Actual Go accepts these forms; failure must remain at the named proof
	// stage, not be represented as unsupported Go syntax or observer success.
	for _, op := range []string{"MOVOA", "MOVO", "MOVAPS", "MOVAPD", "MOVHPD", "MOVHPS", "MOVLPD", "MOVLPS"} {
		t.Run(op+"/producer-denied", func(t *testing.T) {
			file, _, options := x86PrivateLegacyReadOriginal(t, op+" (DI),X0")
			if _, err := normalizeX86RawFile(file, "amd64", options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("aligned memory or unregistered half move borrowed a caller proof: %v", err)
			}
		})
	}
	for _, op := range []string{"MOVOU", "MOVUPS", "MOVUPD"} {
		t.Run(op+"/fresh-store-denied", func(t *testing.T) {
			body := "MOVOU (DI),X0\nMOVQ res+16(FP),DX\n" + op + " X0,(DX)"
			file, _, options := x86PrivateLegacyReadOriginal(t, body)
			if _, err := normalizeX86RawFile(file, "amd64", options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("whole128 write exceeded the existing fresh scalar envelope: %v", err)
			}
		})
	}
	for _, scalar := range []struct {
		op    string
		width int64
	}{{"MOVSS", 4}, {"MOVSD", 8}} {
		t.Run(scalar.op+"/separate-private-domain", func(t *testing.T) {
			fn, sig := x86PrivateLegacyReadProved(t, scalar.op+" (DI),X0", scalar.width)
			if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("whole128 seam widened a separate scalar native-read domain: %v", err)
			}
		})
	}
	t.Run("dead-wider-transport-preserves-unknown-state", func(t *testing.T) {
		fn, sig := x86PrivateLegacyReadProved(t, "MOVOU (DI),X0\nVMOVUPS Y0,Y1", 16)
		// The complete vector domain propagates unknown upper bytes; merely
		// copying them to an unused register does not assert initialization.
		// The separate live upper-byte consumer regression must still reject
		// the same low-X source through all three translation APIs.
		if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
			t.Fatalf("dead register transport lost its exact low128 read proof: %v", err)
		}
	})
	for _, body := range []string{"MOVOU (BX),X0", "MOVOU ·data(SB),X0"} {
		t.Run(body+"/unknown-native-origin", func(t *testing.T) {
			file, _, options := x86PrivateLegacyReadOriginal(t, body)
			if _, err := normalizeX86RawFile(file, "amd64", options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown native origin acquired a numerical read proof: %v", err)
			}
		})
	}
}
