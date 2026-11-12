//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func windowsUnwindObjectFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	directory, driver, _ := fixture(t)
	assembly := "TEXT ·Value(SB),4,$160-16\nMOVQ a+0(FP),AX\nMOVQ AX,ret+8(FP)\nRET\n" +
		"TEXT ·Void(SB),4,$160-8\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nRET\n"
	name, object := filepath.Join(directory, "unwind.s"), filepath.Join(directory, "unwind.o")
	if err := os.WriteFile(name, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	run(t, driver, directory, fixtureEnv(t, "windows/amd64"), "tool", "asm", "-p", fixtureModule,
		"-o", object, name)
	data, err := readRegular(object, archiveLimit)
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := readRegular(filepath.Join(filepath.Dir(filepath.Dir(driver)), builtinSourceRole), archiveLimit)
	if err != nil {
		t.Fatal(err)
	}
	// The independent selected-SDK reader supplies all TEXT aux and source PCs;
	// it neither calls the production decoder nor grants a live source role.
	oracle := officialReaderForSource(t, driver, sdkTextReaderSource)
	raw := run(t, oracle, directory, fixtureEnv(t, "windows/amd64"), object)
	var actual []TextMember
	if err := json.Unmarshal(raw, &actual); err != nil || len(actual) != 1 {
		t.Fatal("independent original Windows Go object reader failed", err)
	}
	observed, err := ObserveWindowsAMD64AssemblyUnwind(data, builtin)
	if err != nil || !reflect.DeepEqual(observed.Texts, actual[0].Texts) {
		t.Fatal("complete Windows TEXT metadata differs from independent SDK reader", err)
	}
	return data, builtin
}

func TestGoStaticStorageWindowsUnwindActualExceptionHandlerRefusal(t *testing.T) {
	directory, driver, _ := fixture(t)
	name, object := filepath.Join(directory, "handler.s"), filepath.Join(directory, "handler.o")
	assembly := "TEXT ·asmcgocall_landingpad(SB),4,$160-0\nRET\n"
	if err := os.WriteFile(name, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	listing := run(t, driver, directory, fixtureEnv(t, "windows/amd64"), "tool", "asm", "-S",
		"-p", "runtime", "-o", object, name)
	if !bytes.Contains(listing, []byte("R_PEIMAGEOFF runtime.sehtramp")) {
		t.Fatal("actual original handler control lacks its real PE-image relocation")
	}
	data, err := readRegular(object, archiveLimit)
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := readRegular(filepath.Join(filepath.Dir(filepath.Dir(driver)), builtinSourceRole), archiveLimit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveWindowsAMD64AssemblyUnwind(data, builtin); !errors.Is(err, ErrContext) ||
		!strings.Contains(err.Error(), "exception-handler") {
		t.Fatal("actual native handler metadata entered ordinary closed-local observation", err)
	}
	t.Logf("ACTUAL_WINDOWS_HANDLER_OBJECT bytes=%d sha256=%s hex=%x\n%s", len(data), digest(data), data, listing)
}

func TestGoStaticStorageWindowsUnwindCompleteSchemaAndGuards(t *testing.T) {
	data, builtin := windowsUnwindObjectFixture(t)
	observed, err := ObserveWindowsAMD64AssemblyUnwind(data, builtin)
	if err != nil || len(observed.Texts) != 2 || len(observed.Unwind) != 1 ||
		observed.Unwind[0].PushEnd != 1 || observed.Unwind[0].PrologueEnd != 4 ||
		!bytes.Equal(observed.Unwind[0].Data, []byte{1, 4, 2, 5, 4, 3, 1, 0x50, 0, 0, 0, 0}) {
		t.Fatal("complete original two-TEXT shared SEH observation differs", err)
	}
	start := bytes.Index(data, []byte("\n!\n")) + 3
	body := data[start:]
	offset := func(block int) int { return start + int(binary.LittleEndian.Uint32(body[20+block*4:])) }
	index := int(observed.Unwind[0].Index)
	metadataSymbol := offset(3) + index*21
	metadataData := offset(16) + int(binary.LittleEndian.Uint32(data[offset(13)+index*4:]))
	metadataName := start + int(binary.LittleEndian.Uint32(data[metadataSymbol+4:]))
	metadataAux := func(text TextRecord) int {
		from := int(binary.LittleEndian.Uint32(data[offset(12)+int(text.Index)*4:]))
		to := int(binary.LittleEndian.Uint32(data[offset(12)+(int(text.Index)+1)*4:]))
		for index := from; index < to; index++ {
			if data[offset(15)+index*9] == 14 {
				return offset(15) + index*9
			}
		}
		t.Fatal("actual original TEXT omitted its SEH auxiliary")
		return 0
	}
	aux := metadataAux(observed.Texts[0])
	textSymbol := offset(3) + int(observed.Texts[0].Index)*21
	mutations := map[string]func([]byte) []byte{
		"wrong target":          func(v []byte) []byte { return bytes.Replace(v, []byte("windows amd64"), []byte("linuxxx amd64"), 1) },
		"extra EOF":             func(v []byte) []byte { return append(v, 0) },
		"truncated EOF":         func(v []byte) []byte { return v[:len(v)-1] },
		"wrong object flag":     func(v []byte) []byte { v[start+16] = 0; return v },
		"wrong kind":            func(v []byte) []byte { v[metadataSymbol+10] = 24; return v },
		"wrong ABI":             func(v []byte) []byte { v[metadataSymbol+8] = 1; return v },
		"missing local flag":    func(v []byte) []byte { v[metadataSymbol+11] = 1; return v },
		"extra symbol flag":     func(v []byte) []byte { v[metadataSymbol+11] |= 4; return v },
		"extra TEXT flag":       func(v []byte) []byte { v[textSymbol+11] |= 1; return v },
		"extra flag2":           func(v []byte) []byte { v[metadataSymbol+12] = 1; return v },
		"wrong size":            func(v []byte) []byte { v[metadataSymbol+13] = 13; return v },
		"wrong alignment":       func(v []byte) []byte { v[metadataSymbol+17] = 8; return v },
		"missing namespace":     func(v []byte) []byte { v[metadataName] = 'x'; return v },
		"noncanonical base64":   func(v []byte) []byte { v[metadataName+11] = '_'; return v },
		"unbound byte change":   func(v []byte) []byte { v[metadataData+1]++; return v },
		"missing TEXT link":     func(v []byte) []byte { v[aux] = 12; return v },
		"duplicate TEXT link":   func(v []byte) []byte { copy(v[aux-9:aux], v[aux:aux+9]); return v },
		"zero TEXT link":        func(v []byte) []byte { clear(v[aux+1 : aux+9]); return v },
		"wrong reference block": func(v []byte) []byte { binary.LittleEndian.PutUint32(v[aux+1:], 2147483647); return v },
		"wrong hashed kind":     func(v []byte) []byte { binary.LittleEndian.PutUint32(v[aux+5:], 0); return v },
		"out-of-bounds link":    func(v []byte) []byte { binary.LittleEndian.PutUint32(v[aux+5:], 65536); return v },
		"foreign link":          func(v []byte) []byte { binary.LittleEndian.PutUint32(v[aux+1:], 65536); return v },
		"unused malformed reference": func(v []byte) []byte {
			binary.LittleEndian.PutUint32(v[offset(7)+4:], 0xffffffff)
			return v
		},
		"non-TEXT SEH owner": func(v []byte) []byte {
			v[offset(3)+int(observed.Texts[0].Index)*21+10] = 24
			return v
		},
		"SEH relocation role": func(v []byte) []byte {
			binary.LittleEndian.PutUint32(v[offset(11)+(index+1)*4:], 1)
			return v
		},
		"SEH auxiliary role": func(v []byte) []byte {
			from := binary.LittleEndian.Uint32(v[offset(12)+index*4:])
			binary.LittleEndian.PutUint32(v[offset(12)+(index+1)*4:], from+1)
			return v
		},
		"orphan hashed metadata": func(v []byte) []byte { return windowsUnwindWithOrphan(t, v, observed.Unwind[0]) },
	}
	for _, byteIndex := range []int{0, 2, 3, 5, 7, 8, 9, 10, 11} {
		mutations["canonical-name grammar byte "+string(rune('A'+byteIndex))] = func(v []byte) []byte {
			v[metadataData+byteIndex] ^= 1
			copy(v[metadataName:], "go:sehuw.12."+base64.StdEncoding.EncodeToString(v[metadataData:metadataData+12]))
			return v
		}
	}
	for _, offsetCase := range []struct {
		name                     string
		prologue, setFrame, push byte
	}{{"zero prologue", 0, 0, 1}, {"zero push", 4, 4, 0}, {"offset order", 4, 4, 4}, {"header and node differ", 4, 5, 1}} {
		mutations[offsetCase.name] = func(v []byte) []byte {
			v[metadataData+1], v[metadataData+4], v[metadataData+6] = offsetCase.prologue, offsetCase.setFrame, offsetCase.push
			copy(v[metadataName:], "go:sehuw.12."+base64.StdEncoding.EncodeToString(v[metadataData:metadataData+12]))
			return v
		}
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := change(append([]byte(nil), data...))
			if _, err := ObserveWindowsAMD64AssemblyUnwind(changed, builtin); !errors.Is(err, ErrContext) {
				t.Fatal("changed complete Windows metadata was accepted", err)
			}
		})
	}
	t.Run("changed builtin schema", func(t *testing.T) {
		if _, err := ObserveWindowsAMD64AssemblyUnwind(data, append(append([]byte(nil), builtin...), '\n')); !errors.Is(err, ErrContext) {
			t.Fatal("caller builtin schema replaced the original selected SDK", err)
		}
	})
}

// Rebuild the complete indexed object with one valid but unreferenced hashed
// SEH definition. Existing class-relative references remain unchanged; every
// object block, index tail and data extent still covers the exact EOF.
func windowsUnwindWithOrphan(t *testing.T, data []byte, metadata WindowsAMD64UnwindRecord) []byte {
	t.Helper()
	start := bytes.Index(data, []byte("\n!\n")) + 3
	body := data[start:]
	var offsets [19]int
	for index := range offsets {
		offsets[index] = int(binary.LittleEndian.Uint32(body[20+index*4:]))
	}
	blocks := make([][]byte, 18)
	for index := range blocks {
		blocks[index] = append([]byte(nil), body[offsets[index]:offsets[index+1]]...)
	}
	insert := (len(blocks[3]) + len(blocks[4]) + len(blocks[5])) / 21
	payload := append([]byte(nil), metadata.Data...)
	payload[1], payload[4] = 5, 5
	name := "go:sehuw.12." + base64.StdEncoding.EncodeToString(payload)
	symbol := append([]byte(nil), body[offsets[3]+int(metadata.Index)*21:offsets[3]+(int(metadata.Index)+1)*21]...)
	binary.LittleEndian.PutUint32(symbol, uint32(len(name)))
	binary.LittleEndian.PutUint32(symbol[4:], uint32(offsets[0]))
	blocks[5] = append(blocks[5], symbol...)
	blocks[10] = append(blocks[10], make([]byte, 16)...)
	dataPosition := int(binary.LittleEndian.Uint32(blocks[13][insert*4:]))
	blocks[16] = append(append(append([]byte(nil), blocks[16][:dataPosition]...), payload...), blocks[16][dataPosition:]...)
	for _, index := range []int{11, 12, 13} {
		old := blocks[index]
		updated := append([]byte(nil), old[:(insert+1)*4]...)
		value := binary.LittleEndian.Uint32(old[insert*4:])
		if index == 13 {
			value += 12
		}
		updated = binary.LittleEndian.AppendUint32(updated, value)
		for pos := (insert + 1) * 4; pos < len(old); pos += 4 {
			value := binary.LittleEndian.Uint32(old[pos:])
			if index == 13 {
				value += 12
			}
			updated = binary.LittleEndian.AppendUint32(updated, value)
		}
		blocks[index] = updated
	}
	rebuilt := append(append([]byte(nil), body[:offsets[0]]...), []byte(name)...)
	for index, block := range blocks {
		binary.LittleEndian.PutUint32(rebuilt[20+index*4:], uint32(len(rebuilt)))
		rebuilt = append(rebuilt, block...)
	}
	binary.LittleEndian.PutUint32(rebuilt[20+18*4:], uint32(len(rebuilt)))
	return append(append([]byte(nil), data[:start]...), rebuilt...)
}
