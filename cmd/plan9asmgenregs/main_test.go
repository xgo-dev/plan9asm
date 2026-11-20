package main

import (
	"strings"
	"testing"
)

func TestGenerateSystemRegistersPreservesPhysicalFieldsAndAccess(t *testing.T) {
	source := []byte(`
{"MIDR_EL1", REG_MIDR_EL1, 0x180000, SR_READ},
{"DBGBVR0_EL1", REG_DBGBVR0_EL1, 0x80, SR_READ | SR_WRITE},
{"OSLAR_EL1", REG_OSLAR_EL1, 0x10080, SR_WRITE},
`)
	generated, err := generateSystemRegisters(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		`"MIDR_EL1":   {encoding: 0x4000, readable: true, writable: false}`,
		`"DBGBVR0_EL1": {encoding: 0x4, readable: true, writable: true}`,
		`"OSLAR_EL1":  {encoding: 0x804, readable: false, writable: true}`,
	} {
		// Formatting alignment is not part of the generator's schema.
		normalize := func(text string) string { return strings.Join(strings.Fields(text), " ") }
		if !strings.Contains(normalize(string(generated)), normalize(value)) {
			t.Fatalf("generated source omitted %s:\n%s", value, generated)
		}
	}
}

func TestGenerateSystemRegistersFailsClosed(t *testing.T) {
	for _, source := range []string{
		"not a register table",
		`{"ZERO", REG_ZERO, 0x0, SR_READ},`,
		`{"BAD", REG_BAD, 0x100001, SR_READ},`,
		`{"BAD", REG_BAD, 0x200000, SR_READ},`,
		`{"BAD", REG_BAD, 0x100080, UNKNOWN},`,
		`{"DUP", REG_DUP, 0x100080, SR_READ}, {"DUP", REG_DUP, 0x100080, SR_READ},`,
		`{"VALID", REG_VALID, 0x100080, SR_READ}, {"LOST", REG_LOST, 0xXYZ, SR_READ},`,
	} {
		if generated, err := generateSystemRegisters([]byte(source)); err == nil {
			t.Fatalf("invalid source generated a partial table:\n%s", generated)
		}
	}
}
