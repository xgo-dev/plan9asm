package plan9asm

import (
	"encoding/hex"
	"fmt"
	"go/format"
	"regexp"
	"strconv"
	"strings"
)

type amd64ArgumentOracleCarrier struct {
	parameter string
	offset    int64
	register  Reg
	width     int64
}

type amd64ArgumentOracleFixture struct {
	name, parameters, arguments string
	carriers                    []amd64ArgumentOracleCarrier
}

func amd64ArgumentOracleFixtures() []amd64ArgumentOracleFixture {
	fixtures := []amd64ArgumentOracleFixture{
		{"Strings", "a,b string", "a,b", []amd64ArgumentOracleCarrier{
			{"a", 0, AX, 8}, {"a", 8, BX, 8}, {"b", 0, CX, 8}, {"b", 8, DI, 8},
		}},
		{"Slices", "a,b []byte", "a,b", []amd64ArgumentOracleCarrier{
			{"a", 0, AX, 8}, {"a", 8, BX, 8}, {"a", 16, CX, 8},
			{"b", 0, DI, 8}, {"b", 8, SI, 8}, {"b", 16, "R8", 8},
		}},
		{"Mixed", "f float64,a byte,b bool,c float32,d uint16,p *byte", "f,a,b,c,d,p", []amd64ArgumentOracleCarrier{
			{"f", 0, "X0", 8}, {"a", 0, AX, 1}, {"b", 0, BX, 1},
			{"c", 0, "X1", 4}, {"d", 0, CX, 2}, {"p", 0, DI, 8},
		}},
		{"Nested", "a struct { B byte; F [1]float32; N uint16 },last uint64", "a,last", []amd64ArgumentOracleCarrier{
			{"a", 0, AX, 1}, {"a", 4, "X0", 4}, {"a", 8, BX, 2}, {"last", 0, CX, 8},
		}},
		{"Widths", "a byte,b uint16,c uint32,d uint64,e bool,f float32,g float64", "a,b,c,d,e,f,g", []amd64ArgumentOracleCarrier{
			{"a", 0, AX, 1}, {"b", 0, BX, 2}, {"c", 0, CX, 4}, {"d", 0, DI, 8},
			{"e", 0, SI, 1}, {"f", 0, "X0", 4}, {"g", 0, "X1", 8},
		}},
	}
	gp := []Reg{AX, BX, CX, DI, SI, "R8", "R9", "R10", "R11"}
	for _, bank := range []string{"GP", "FP"} {
		fixture := amd64ArgumentOracleFixture{name: bank + "Bank"}
		count, typ, width := 9, "uint64", int64(8)
		if bank == "FP" {
			count, typ = 15, "float64"
		}
		var parameters, arguments []string
		for index := 0; index < count; index++ {
			name := fmt.Sprintf("a%d", index)
			parameters = append(parameters, name+" "+typ)
			arguments = append(arguments, name)
			register := Reg(fmt.Sprintf("X%d", index))
			if bank == "GP" {
				register = gp[index]
			}
			fixture.carriers = append(fixture.carriers, amd64ArgumentOracleCarrier{name, 0, register, width})
		}
		fixture.parameters, fixture.arguments = strings.Join(parameters, ","), strings.Join(arguments, ",")
		fixtures = append(fixtures, fixture)
		rollback := fixture
		rollback.name, rollback.carriers = bank+"Rollback", append([]amd64ArgumentOracleCarrier(nil), fixture.carriers[:count-1]...)
		parameters, arguments = parameters[:count-1], arguments[:count-1]
		if bank == "GP" {
			parameters = append(parameters, "spilled struct { F float64; A,B uint64 }", "next float64", "last uint64")
			arguments = append(arguments, "spilled", "next", "last")
			rollback.carriers = append(rollback.carriers, amd64ArgumentOracleCarrier{"next", 0, "X0", 8}, amd64ArgumentOracleCarrier{"last", 0, "R11", 8})
		} else {
			parameters = append(parameters, "spilled struct { P *byte; Z complex128 }", "next uint64", "last float64")
			arguments = append(arguments, "spilled", "next", "last")
			rollback.carriers = append(rollback.carriers, amd64ArgumentOracleCarrier{"next", 0, AX, 8}, amd64ArgumentOracleCarrier{"last", 0, "X14", 8})
		}
		rollback.parameters, rollback.arguments = strings.Join(parameters, ","), strings.Join(arguments, ",")
		fixtures = append(fixtures, rollback)
	}
	return fixtures
}

func amd64ArgumentOracleSource(fixtures []amd64ArgumentOracleFixture) ([]byte, error) {
	var source strings.Builder
	source.WriteString("package carrieroracle\n")
	for _, fixture := range fixtures {
		fmt.Fprintf(&source, "//go:noinline\nfunc Target%s(%s) uint64 { return 1 }\n", fixture.name, fixture.parameters)
		fmt.Fprintf(&source, "//go:noinline\nfunc Caller%s(%s) uint64 { return Target%s(%s) }\n", fixture.name, fixture.parameters, fixture.name, fixture.arguments)
	}
	return format.Source([]byte(source.String()))
}

type amd64ArgumentCompilerFunction struct {
	spills []amd64ArgumentOracleCarrier
	code   []byte
	calls  map[string]int64
}

var (
	amd64ArgumentCompilerText  = regexp.MustCompile(`\bTEXT\s+([^\s(]+)\(SB\),\s+([A-Za-z0-9_|]+),`)
	amd64ArgumentCompilerStore = regexp.MustCompile(`\b(MOVB|MOVW|MOVL|MOVQ|MOVSS|MOVSD)\s+([A-Z0-9]+),\s+[^\s,]+\.([A-Za-z][A-Za-z0-9_]*)\+(-?[0-9]+)\((?:SP|FP)\)`)
	amd64ArgumentCompilerBytes = regexp.MustCompile(`^\s+0x([0-9a-f]+)\s+((?:[0-9a-f]{2} ){1,16})`)
	amd64ArgumentCompilerCall  = regexp.MustCompile(`^\s+rel ([0-9]+)\+4 t=R_CALL ([^\s+]+)\+0\s*$`)
)

// This test-only listing reader observes receiving spill stores, not actual
// incoming stack arguments or a public storage/entry certificate. -N/-l are
// confined to the independent ordinary compiler fixture, never the SDK profile.
func amd64ArgumentCompilerFunctions(listing []byte) (map[string]*amd64ArgumentCompilerFunction, error) {
	if len(listing) == 0 || len(listing) > 32<<20 {
		return nil, fmt.Errorf("missing/oversized compiler listing")
	}
	functions := make(map[string]*amd64ArgumentCompilerFunction)
	var current *amd64ArgumentCompilerFunction
	for _, line := range strings.Split(string(listing), "\n") {
		if row := amd64ArgumentCompilerText.FindStringSubmatch(line); row != nil {
			flags := make(map[string]bool)
			for _, flag := range strings.Split(row[2], "|") {
				if flags[flag] {
					return nil, fmt.Errorf("duplicate compiler TEXT flag")
				}
				flags[flag] = true
				switch flag {
				case "ABIInternal", "NOSPLIT", "NOFRAME", "DUPOK":
				default:
					return nil, fmt.Errorf("unregistered compiler TEXT flag %s", flag)
				}
			}
			if !flags["ABIInternal"] {
				return nil, fmt.Errorf("compiler argument fixture has a non-ABIInternal entry")
			}
			if functions[row[1]] != nil || len(functions) >= 256 {
				return nil, fmt.Errorf("duplicate/oversized compiler TEXT inventory")
			}
			current = &amd64ArgumentCompilerFunction{calls: make(map[string]int64)}
			functions[row[1]] = current
		} else if len(line) != 0 && line[0] != ' ' && line[0] != '\t' {
			current = nil // A new named data or TEXT record, not the prior body.
		}
		if current == nil {
			continue
		}
		if row := amd64ArgumentCompilerStore.FindStringSubmatch(line); row != nil {
			register := Reg(row[2])
			if base, valid := amd64FullRegBase(register); valid {
				register = base
			}
			offset, err := strconv.ParseInt(row[4], 10, 64)
			if err != nil || len(current.spills) >= 4096 {
				return nil, fmt.Errorf("invalid compiler argument store")
			}
			width := map[string]int64{"MOVB": 1, "MOVW": 2, "MOVL": 4, "MOVQ": 8, "MOVSS": 4, "MOVSD": 8}[row[1]]
			current.spills = append(current.spills, amd64ArgumentOracleCarrier{row[3], offset, register, width})
		}
		if row := amd64ArgumentCompilerBytes.FindStringSubmatch(line); row != nil {
			offset, err := strconv.ParseInt(row[1], 16, 64)
			bytes, decode := hex.DecodeString(strings.ReplaceAll(row[2], " ", ""))
			if err != nil || decode != nil || offset != int64(len(current.code)) || len(current.code) > 1<<20 {
				return nil, fmt.Errorf("noncontiguous compiler code")
			}
			current.code = append(current.code, bytes...)
		}
		if row := amd64ArgumentCompilerCall.FindStringSubmatch(line); row != nil {
			offset, err := strconv.ParseInt(row[1], 10, 64)
			if _, duplicate := current.calls[row[2]]; err != nil || duplicate {
				return nil, fmt.Errorf("duplicate/invalid compiler call")
			}
			current.calls[row[2]] = offset
		}
	}
	return functions, nil
}
