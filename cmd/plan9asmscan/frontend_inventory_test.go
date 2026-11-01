package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func frontendFixture(t *testing.T, arch string) string {
	t.Helper()
	root := t.TempDir()
	obj := filepath.Join(root, "src/cmd/internal/obj")
	writeEncoderFixture(t, filepath.Join(obj, "link.go"), `package obj
const (
 AXXX As = iota; ACALL; ADUFFCOPY; ADUFFZERO; AEND; AFUNCDATA; AJMP; ANOP
 APCALIGN; APCALIGNMAX; APCDATA; ARET; AGETCALLERPC; ATEXT; AUNDEF; A_ARCHSPECIFIC
)
const (
 ABase386 = (1+iota)<<11; ABaseARM; ABaseAMD64; ABasePPC64; ABaseARM64
 ABaseMIPS; ABaseLoong64; ABaseRISCV; ABaseS390X; ABaseWasm
)
`)
	writeEncoderFixture(t, filepath.Join(obj, "util.go"), `package obj
var Anames = []string{"XXX","CALL","DUFFCOPY","DUFFZERO","END","FUNCDATA","JMP","NOP","PCALIGN","PCALIGNMAX","PCDATA","RET","GETCALLERPC","TEXT","UNDEF"}
`)
	dir, base, constructor := arch, "ARM", "archArm"
	opcodes, enum, extra := `"ADD","MOV","LAST"`, "AADD; AMOV; ALAST", ""
	aliases := `instructions["B"] = obj.AJMP
 instructions["BL"] = obj.ACALL
 instructions["MCR"] = aMCR`
	switch arch {
	case "386", "amd64":
		dir, base, constructor = "x86", "AMD64", "archX86"
		opcodes, enum = `"ADD","MOVQ","LAST"`, "AADD; AMOVQ; ALAST"
		aliases = `instructions["MOVD"] = x86.AMOVQ
 instructions["ADD"] = x86.AADD`
	case "arm64":
		base, constructor = "ARM64", "archArm64"
		opcodes, enum = `"B","BL","MOV"`, "AB; ABL; AMOV"
		aliases = `instructions["B"] = arm64.AB
 instructions["BL"] = arm64.ABL`
		extra = `package arm64
var sveAnames = []string{"SVESTART","ZADD","LAST"}
func init() { Anames = append(Anames, sveAnames...) }
`
	case "wasm":
		base, constructor = "Wasm", "archWasm"
		opcodes, enum = `"Call","Nop","End","Last","ReservedFD00","LAST"`, "ACall; ANop; AEnd; ALast; AReservedFD00; ALAST"
		aliases = ""
	}
	parts := strings.Split(enum, ";")
	parts[0] += " = obj.ABase" + base + " + obj.A_ARCHSPECIFIC + iota"
	enumFile := "a.out.go"
	if dir == "x86" {
		enumFile = "aenum.go"
	}
	writeEncoderFixture(t, filepath.Join(obj, dir, enumFile), "package "+dir+"\nimport \"cmd/internal/obj\"\nconst ("+strings.Join(parts, ";")+")\n")
	writeEncoderFixture(t, filepath.Join(obj, dir, "anames.go"), "package "+dir+"\nimport \"cmd/internal/obj\"\nvar Anames = []string{obj.A_ARCHSPECIFIC:"+opcodes+"}\nvar cnames = []string{\"REG\",\"FAKE\"}\n")
	if extra != "" {
		writeEncoderFixture(t, filepath.Join(obj, dir, "anames_gen.go"), extra)
	}
	asmArch := filepath.Join(root, "src/cmd/asm/internal/arch")
	writeEncoderFixture(t, filepath.Join(asmArch, "arm.go"), "package arch\nimport \"cmd/internal/obj/arm\"\nconst aMCR = arm.ALAST + 1\n")
	writeEncoderFixture(t, filepath.Join(asmArch, "arch.go"), fmt.Sprintf(`package arch
import ("cmd/internal/obj"; "cmd/internal/obj/%s")
func %s() *Arch {
 instructions := make(map[string]obj.As)
 for i,s := range obj.Anames { instructions[s] = obj.As(i) }
 for i,s := range %s.Anames {
  if obj.As(i) >= obj.A_ARCHSPECIFIC { instructions[s] = obj.As(i) + obj.ABase%s }
 }
 %s
 return &Arch{Instructions:instructions}
}
func Set(GOARCH string, shared bool) *Arch {
 switch GOARCH {
 case "386": return archX86(&x86.Link386)
 case "amd64": return archX86(&x86.Linkamd64)
 case "arm": return archArm()
 case "arm64": return archArm64()
 case "wasm": return archWasm()
 }
 return nil
}
`, dir, constructor, dir, base, aliases))
	writeEncoderFixture(t, filepath.Join(root, "src/cmd/asm/internal/asm/parse.go"), `package asm
func (p *Parser) pseudo(word string, operands [][]Token) bool {
 switch word {
 case "DATA": p.asmData(operands)
 case "FUNCDATA": p.asmFuncData(operands)
 case "GLOBL": p.asmGlobl(operands)
 case "PCDATA": p.asmPCData(operands)
 case "PCALIGN": p.asmPCAlign(operands)
 case "TEXT": p.asmText(operands)
 default: return false
 }
 return true
}
`)
	return root
}

func frontendEntries(t *testing.T, inventory *frontendInventory) map[string]frontendName {
	t.Helper()
	if inventory == nil || inventory.SchemaVersion != 1 || inventory.Scope != "go_assembler_frontend_source_registration" {
		t.Fatalf("unexpected inventory identity: %+v", inventory)
	}
	entries := map[string]frontendName{}
	sources := map[string]bool{}
	for _, source := range inventory.Sources {
		digest, err := hex.DecodeString(source.SHA256)
		if err != nil || len(digest) != 32 || filepath.IsAbs(source.Source) {
			t.Fatalf("invalid source hash proof: %+v", source)
		}
		sources[source.Source] = true
	}
	for _, entry := range inventory.Entries {
		if _, duplicate := entries[entry.Spelling]; duplicate {
			t.Fatalf("duplicate exact spelling %q", entry.Spelling)
		}
		if entry.Canonical == "" || entry.CanonicalNamespace == "" || len(entry.Origins) == 0 {
			t.Fatalf("missing canonical/origin proof: %+v", entry)
		}
		for _, origin := range entry.Origins {
			if filepath.IsAbs(origin.Source) || origin.Line < 1 || !sources[origin.Source] {
				t.Fatalf("source proof must be relative and positioned: %+v", origin)
			}
		}
		entries[entry.Spelling] = entry
	}
	return entries
}

func frontendRoles(entry frontendName) []string {
	var roles []string
	for _, origin := range entry.Origins {
		roles = append(roles, origin.Role)
	}
	return roles
}

func TestFrontendInventoryCompletenessEveryArchitecture(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			inventory, err := loadFrontendInventory(frontendFixture(t, arch), arch)
			if err != nil {
				t.Fatal(err)
			}
			entries := frontendEntries(t, inventory)
			call := entries["CALL"]
			if call.AsID == nil || *call.AsID != 1 || call.Canonical != "CALL" || call.CanonicalNamespace != "obj" || !reflect.DeepEqual(frontendRoles(call), []string{"common"}) {
				t.Fatalf("portable CALL mapping = %+v", call)
			}
			if !reflect.DeepEqual(frontendRoles(entries["TEXT"]), []string{"common", "pseudo"}) {
				t.Fatalf("TEXT must retain both registration roles: %+v", entries["TEXT"])
			}
			if entries["DATA"].AsID != nil || entries["DATA"].CanonicalNamespace != "pseudo" || !reflect.DeepEqual(frontendRoles(entries["DATA"]), []string{"pseudo"}) {
				t.Fatalf("DATA has no obj.As and must remain a pseudo: %+v", entries["DATA"])
			}
			if !entries["XXX"].Sentinel || !entries["LAST"].Sentinel || !strings.Contains(strings.Join(frontendRoles(entries["LAST"]), ","), "sentinel") {
				t.Fatal("source sentinels must be explicitly identified, never silently discarded")
			}
			if _, leaked := entries["REG"]; leaked {
				t.Fatal("operand-class strings are not frontend names")
			}
			switch arch {
			case "386", "amd64":
				if entries["MOVD"].Canonical != "MOVQ" || entries["MOVD"].CanonicalNamespace != "x86" || !reflect.DeepEqual(frontendRoles(entries["ADD"]), []string{"arch", "alias"}) {
					t.Fatalf("x86 alias/canonical roles were lost: %+v", entries)
				}
			case "arm":
				if *entries["B"].AsID != *entries["JMP"].AsID || entries["B"].CanonicalNamespace != "obj" || entries["MCR"].CanonicalNamespace != "asm" {
					t.Fatalf("ARM common and private frontend aliases were lost: %+v", entries)
				}
			case "arm64":
				if entries["ZADD"].AsID == nil || !entries["SVESTART"].Sentinel || entries["B"].CanonicalNamespace != "arm64" {
					t.Fatalf("ARM64 registered append/aliases were lost: %+v", entries)
				}
			case "wasm":
				for _, pair := range [][2]string{{"Call", "CALL"}, {"Nop", "NOP"}, {"End", "END"}, {"Last", "LAST"}} {
					left, right := entries[pair[0]], entries[pair[1]]
					if left.AsID == nil || right.AsID == nil || *left.AsID == *right.AsID || left.Spelling == right.Spelling {
						t.Fatalf("case-sensitive names were collapsed: %s/%s", pair[0], pair[1])
					}
				}
				if !entries["ReservedFD00"].Sentinel {
					t.Fatal("reserved wasm entry was silently promoted to executable opcode")
				}
			}
		})
	}
}

func TestFrontendInventoryFailsClosedForRegistrationChanges(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		for _, mutation := range []struct{ name, old, new string }{
			{"missing_common", "for i,s := range obj.Anames { instructions[s] = obj.As(i) }", ""},
			{"altered_common", "instructions[s] = obj.As(i) }", "instructions[s] = obj.As(i)+1 }"},
			{"altered_arch_guard", ">= obj.A_ARCHSPECIFIC", "> obj.A_ARCHSPECIFIC"},
			{"map_escape", "return &Arch", "hidden := instructions; _ = hidden; return &Arch"},
			{"unknown_helper", "return &Arch", "addNames(instructions); return &Arch"},
			{"delete_name", "return &Arch", "delete(instructions,\"NOP\"); return &Arch"},
			{"conditional_alias", "return &Arch", "if unknown { instructions[\"HIDDEN\"] = obj.ANOP }; return &Arch"},
			{"dynamic_alias", "return &Arch", "instructions[unknown] = obj.ANOP; return &Arch"},
			{"unresolved_alias", "return &Arch", "instructions[\"BAD\"] = obj.UNKNOWN; return &Arch"},
			{"literal_alias", "return &Arch", "instructions[\"LITERAL\"] = 1; return &Arch"},
			{"conflicting_alias", "return &Arch", "instructions[\"CONFLICT\"] = obj.ACALL; instructions[\"CONFLICT\"] = obj.ANOP; return &Arch"},
			{"wrong_import_origin", "\"cmd/internal/obj\"", "obj \"other/obj\""},
			{"redirected_Set", "case \"" + arch + "\": return", "case \"" + arch + "\": return otherConstructor(); case \"unused\": return"},
			{"early_alias", "for i,s := range obj.Anames", "instructions[\"EARLY\"] = obj.ACALL; for i,s := range obj.Anames"},
			{"early_return", "for i,s := range obj.Anames", "if unknown { return nil }; for i,s := range obj.Anames"},
			{"dead_alias", "return &Arch{Instructions:instructions}", "return &Arch{Instructions:instructions}; instructions[\"DEAD\"] = obj.ACALL"},
			{"shadowed_namespace", "instructions := make(map[string]obj.As)", "obj := fake; instructions := make(map[string]obj.As)"},
		} {
			t.Run(arch+"/"+mutation.name, func(t *testing.T) {
				root := frontendFixture(t, arch)
				path := filepath.Join(root, "src/cmd/asm/internal/arch/arch.go")
				source, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				changed := strings.Replace(string(source), mutation.old, mutation.new, 1)
				if changed == string(source) {
					t.Fatal("mutation did not alter fixture")
				}
				writeEncoderFixture(t, path, changed)
				if _, err := loadFrontendInventory(root, arch); err == nil {
					t.Fatal("unknown/incomplete frontend registration was accepted")
				}
			})
		}
	}
}

func TestFrontendInventoryRequiresParserPseudosAndRegisteredAppend(t *testing.T) {
	for _, relative := range []string{"src/cmd/internal/obj/util.go", "src/cmd/asm/internal/asm/parse.go", "src/cmd/asm/internal/arch/arch.go"} {
		t.Run(relative, func(t *testing.T) {
			root := frontendFixture(t, "arm64")
			writeEncoderFixture(t, filepath.Join(root, relative), "package fixture\n")
			if _, err := loadFrontendInventory(root, "arm64"); err == nil {
				t.Fatal("missing registration source accepted")
			}
		})
	}
	root := frontendFixture(t, "arm64")
	writeEncoderFixture(t, filepath.Join(root, "src/cmd/internal/obj/arm64/anames_gen.go"), "package arm64\nvar sveAnames = []string{\"HIDDEN\"}\n")
	if _, err := loadFrontendInventory(root, "arm64"); err == nil {
		t.Fatal("unregistered supplement accepted")
	}
}

func TestFrontendInventoryRejectsUnmodeledArrayAndPseudoChanges(t *testing.T) {
	for _, mutation := range []struct{ name, path, old, replacement string }{
		{"common_escape", "src/cmd/internal/obj/util.go", "", "\nvar escaped = Anames\n"},
		{"common_mutation", "src/cmd/internal/obj/util.go", "", "\nfunc init(){ Anames[1] = \"HIDDEN\" }\n"},
		{"arch_mutation_other_file", "src/cmd/internal/obj/arm64/extra.go", "", "package arm64\nfunc init(){ Anames[15] = \"HIDDEN\" }\n"},
		{"sve_extra_mutation", "src/cmd/internal/obj/arm64/anames_gen.go", "func init() { Anames = append(Anames, sveAnames...) }", "func init() { Anames = append(Anames, sveAnames...); Anames = Anames[:1] }"},
		{"pseudo_catch_all", "src/cmd/asm/internal/asm/parse.go", "default: return false", "default: return true"},
		{"pseudo_missing_default", "src/cmd/asm/internal/asm/parse.go", "default: return false", ""},
		{"pseudo_missing_DATA", "src/cmd/asm/internal/asm/parse.go", "case \"DATA\": p.asmData(operands)", ""},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			root := frontendFixture(t, "arm64")
			path := filepath.Join(root, mutation.path)
			source, err := os.ReadFile(path)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			changed := string(source) + mutation.replacement
			if mutation.old != "" {
				changed = strings.Replace(string(source), mutation.old, mutation.replacement, 1)
			}
			writeEncoderFixture(t, path, changed)
			if _, err := loadFrontendInventory(root, "arm64"); err == nil {
				t.Fatal("unmodeled array/pseudo mutation was accepted")
			}
		})
	}
}

func TestFrontendInventoryActualGoSourceNamespaces(t *testing.T) {
	for _, arch := range namespaceArchitectures {
		t.Run(arch, func(t *testing.T) {
			count := actualGoNamespaceCounts(t, arch).frontend
			inventory, err := loadFrontendInventory(runtime.GOROOT(), arch)
			if err != nil {
				t.Fatal(err)
			}
			entries := frontendEntries(t, inventory)
			if len(entries) != count {
				t.Fatalf("actual frontend source names=%d, want %d including explicit sentinels", len(entries), count)
			}
			if arch == "wasm" && (entries["Call"].CanonicalNamespace != "wasm" || entries["CALL"].CanonicalNamespace != "obj") {
				t.Fatal("wasm/common call identities conflated")
			}
			data, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "runtime_verified") || strings.Contains(string(data), "supported_forms") {
				t.Fatal("registration inventory must not imply semantic proof")
			}
		})
	}
}

func TestFrontendInventoryJSONDoesNotChangeCoverageFields(t *testing.T) {
	inventory, err := loadFrontendInventory(frontendFixture(t, "wasm"), "wasm")
	if err != nil {
		t.Fatal(err)
	}
	before := report{OfficialOpcodes: 463, SupportedForms: 0, ContextForms: 120, CoverageFingerprint: "existing-fingerprint"}
	data, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "frontend_inventory") {
		t.Fatal("unrequested inventory must remain absent")
	}
	after := before
	after.FrontendInventory = inventory
	data, err = json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Official  int                `json:"official_opcodes"`
		Inventory *frontendInventory `json:"frontend_inventory"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Official != 463 || decoded.Inventory == nil || len(decoded.Inventory.Entries) != len(inventory.Entries) {
		t.Fatal("JSON lost separate frontend inventory/architecture-specific denominator")
	}
	after.FrontendInventory = nil
	if !reflect.DeepEqual(before, after) {
		t.Fatal("inventory attachment modified existing coverage fields")
	}
}
