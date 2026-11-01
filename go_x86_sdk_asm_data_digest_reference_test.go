package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Freeze the pre-field-plan encoder as an independent test-only reference.
// Keep its original buffering and per-occurrence reflection for paired encoder
// benchmarks. It must not call current encoder methods or reuse its field plans.
// This oracle authenticates serialization bytes, never a live source or lease.
func sdkASMDataDigestLegacy(state any) ([32]byte, error) {
	encoder := sdkASMDataDigestLegacyEncoder{hash: sha256.New()}
	encoder.text("plan9asm.sdk-asm-data-state.v1")
	if err := encoder.value(reflect.ValueOf(state), 0); err != nil {
		return [32]byte{}, err
	}
	encoder.flush()
	var sum [32]byte
	copy(sum[:], encoder.hash.Sum(sum[:0]))
	return sum, nil
}

type sdkASMDataDigestLegacyEncoder struct {
	hash    hash.Hash
	scratch [4096]byte
	used    int
}

func (encoder *sdkASMDataDigestLegacyEncoder) flush() {
	_, _ = encoder.hash.Write(encoder.scratch[:encoder.used])
	encoder.used = 0
}

func (encoder *sdkASMDataDigestLegacyEncoder) number(value uint64) {
	if len(encoder.scratch)-encoder.used < 8 {
		encoder.flush()
	}
	binary.LittleEndian.PutUint64(encoder.scratch[encoder.used:encoder.used+8], value)
	encoder.used += 8
}

func (encoder *sdkASMDataDigestLegacyEncoder) text(value string) {
	encoder.number(uint64(len(value)))
	for len(value) != 0 {
		if encoder.used == len(encoder.scratch) {
			encoder.flush()
		}
		count := copy(encoder.scratch[encoder.used:], value)
		encoder.used += count
		value = value[count:]
	}
}

func (encoder *sdkASMDataDigestLegacyEncoder) bytes(value []byte) {
	if len(value) > len(encoder.scratch) {
		encoder.flush()
		_, _ = encoder.hash.Write(value)
		return
	}
	for len(value) != 0 {
		if encoder.used == len(encoder.scratch) {
			encoder.flush()
		}
		count := copy(encoder.scratch[encoder.used:], value)
		encoder.used += count
		value = value[count:]
	}
}

var sdkASMDataDigestLegacyTime = reflect.TypeOf(time.Time{})
var sdkASMDataDigestLegacyRawJSON = reflect.TypeOf(json.RawMessage{})

func (encoder *sdkASMDataDigestLegacyEncoder) value(value reflect.Value, depth int) error {
	if depth > 64 || !value.IsValid() {
		return fmt.Errorf("SDK ASM DATA digest has an invalid or recursive state")
	}
	encoder.number(uint64(value.Kind()))
	if value.Type() == sdkASMDataDigestLegacyTime {
		raw, err := value.Interface().(time.Time).MarshalJSON()
		if err != nil {
			return err
		}
		encoder.text(string(raw))
		return nil
	}
	if value.Type() == sdkASMDataDigestLegacyRawJSON && !value.IsNil() && !json.Valid(value.Bytes()) {
		return fmt.Errorf("SDK ASM DATA digest has invalid retained JSON")
	}
	switch value.Kind() {
	case reflect.Bool:
		var bit uint64
		if value.Bool() {
			bit = 1
		}
		encoder.number(bit)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		encoder.number(uint64(value.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		encoder.number(value.Uint())
	case reflect.String:
		encoder.text(value.String())
	case reflect.Ptr, reflect.Map, reflect.Slice:
		if value.IsNil() {
			encoder.number(0)
			return nil
		}
		encoder.number(1)
		if value.Kind() == reflect.Ptr {
			return encoder.value(value.Elem(), depth+1)
		}
		encoder.number(uint64(value.Len()))
		if value.Kind() == reflect.Slice {
			if value.Type().Elem().Kind() == reflect.Uint8 {
				encoder.bytes(value.Bytes())
				return nil
			}
			return encoder.elements(value, depth)
		}
		if value.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("SDK ASM DATA digest has a non-string map key")
		}
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, key := range keys {
			encoder.text(key.String())
			if err := encoder.value(value.MapIndex(key), depth+1); err != nil {
				return err
			}
		}
	case reflect.Array:
		encoder.number(uint64(value.Len()))
		return encoder.elements(value, depth)
	case reflect.Struct:
		typ := value.Type()
		encoder.text(typ.String())
		for i := 0; i < value.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" || strings.Split(field.Tag.Get("json"), ",")[0] == "-" {
				continue
			}
			encoder.text(field.Name)
			if err := encoder.value(value.Field(i), depth+1); err != nil {
				return err
			}
		}
		encoder.text("")
	default:
		return fmt.Errorf("SDK ASM DATA digest has an unsupported state kind: %s", value.Kind())
	}
	return nil
}

func (encoder *sdkASMDataDigestLegacyEncoder) elements(value reflect.Value, depth int) error {
	for i := 0; i < value.Len(); i++ {
		if err := encoder.value(value.Index(i), depth+1); err != nil {
			return err
		}
	}
	return nil
}

type sdkASMDataDigestRecordedHash struct {
	hash.Hash
	stream bytes.Buffer
}

func (record *sdkASMDataDigestRecordedHash) Write(data []byte) (int, error) {
	_, _ = record.stream.Write(data)
	return record.Hash.Write(data)
}

func sdkASMDataDigestReferenceBytes(t *testing.T, state any) ([]byte, [32]byte) {
	t.Helper()
	oldRecord := &sdkASMDataDigestRecordedHash{Hash: sha256.New()}
	old := sdkASMDataDigestLegacyEncoder{hash: oldRecord}
	old.text("plan9asm.sdk-asm-data-state.v1")
	if err := old.value(reflect.ValueOf(state), 0); err != nil {
		t.Fatal("old reference rejected fixture", err)
	}
	old.flush()
	newRecord := &sdkASMDataDigestRecordedHash{Hash: sha256.New()}
	current := sdkASMDataDigestEncoder{hash: newRecord}
	current.text("plan9asm.sdk-asm-data-state.v1")
	if err := current.value(reflect.ValueOf(state), 0); err != nil {
		t.Fatal("current encoder rejected reference fixture", err)
	}
	current.flush()
	if !bytes.Equal(oldRecord.stream.Bytes(), newRecord.stream.Bytes()) {
		t.Fatal("current encoder changed complete serialized bytes")
	}
	want := sha256.Sum256(oldRecord.stream.Bytes())
	for _, digest := range []func(any) ([32]byte, error){sdkASMDataDigestLegacy, digestSDKASMDataState} {
		got, err := digest(state)
		if err != nil || got != want {
			t.Fatal("digest disagrees with complete reference stream", err)
		}
	}
	return oldRecord.stream.Bytes(), want
}

type sdkASMDataDigestGoldenRecord struct {
	Name    string `json:"renamed,omitempty"`
	Raw     json.RawMessage
	Count   *uint32
	Flags   [2]bool
	Values  map[string][]byte
	Ignored string `json:"-,omitempty"`
	private func()
}

func TestGoX86SDKASMDataDigestReferenceBytes(t *testing.T) {
	state, _ := sdkASMDataDigestFixture(t)
	for _, test := range []struct {
		name  string
		value any
	}{
		{"complete-schema", *state},
		{"large-bytes", bytes.Repeat([]byte{0, 0xff, 7}, 3000)},
		{"large-string", strings.Repeat("MOVQ\x00", 1600)},
		{"repeated-schema", []sdkCPPPositionToken{{Text: "one"}, {Text: "two"}, {Text: "three"}}},
		{"time", time.Date(2030, 1, 2, 3, 4, 5, 6, time.UTC)},
		{"map-nil", map[int]string(nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			sdkASMDataDigestReferenceBytes(t, test.value)
		})
	}
}

func TestGoX86SDKASMDataDigestReferenceRejectsInvalidState(t *testing.T) {
	type node struct{ Next *node }
	cycle := &node{}
	cycle.Next = cycle
	depth64 := reflect.ValueOf(uint8(3))
	for i := 0; i < 64; i++ {
		pointer := reflect.New(depth64.Type())
		pointer.Elem().Set(depth64)
		depth64 = pointer
	}
	sdkASMDataDigestReferenceBytes(t, depth64.Interface())
	depth65 := reflect.New(depth64.Type())
	depth65.Elem().Set(depth64)
	for _, value := range []any{
		nil, json.RawMessage("{"), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		map[int]string{}, func() {}, cycle, depth65.Interface(),
	} {
		for _, digest := range []func(any) ([32]byte, error){sdkASMDataDigestLegacy, digestSDKASMDataState} {
			if _, err := digest(value); err == nil {
				t.Errorf("invalid state accepted: %T", value)
			}
		}
	}
}

// Golden streams are literal protocol fixtures, independently framed with
// little-endian uint64 tags/lengths. They are not regenerated from either Go
// encoder. Keep the compound Go type and declaration order stable.
func TestGoX86SDKASMDataDigestGoldenBytes(t *testing.T) {
	count := uint32(7)
	compound := sdkASMDataDigestGoldenRecord{
		Name: "a\x00", Raw: json.RawMessage(`{"k":1}`), Count: &count,
		Flags: [2]bool{true, false}, Values: map[string][]byte{"b": {}, "a": nil},
		Ignored: "excluded", private: func() {},
	}
	for _, test := range []struct {
		name, encoded, sum string
		value              any
	}{
		{
			name: "bool-true", value: true,
			encoded: "1e00000000000000706c616e3961736d2e73646b2d61736d2d646174612d7374" +
				"6174652e763101000000000000000100000000000000",
			sum: "a7ca0cf50980801b48cfde05316093a73ba349f84a1580529cb77e85165e7732",
		},
		{
			name: "nil-bytes", value: []byte(nil),
			encoded: "1e00000000000000706c616e3961736d2e73646b2d61736d2d646174612d7374" +
				"6174652e763117000000000000000000000000000000",
			sum: "1283314f719a9d8efdbe11714dcffeb3e243caa2fdfd8ad0640bb81c08bc0ab6",
		},
		{
			name: "empty-bytes", value: []byte{},
			encoded: "1e00000000000000706c616e3961736d2e73646b2d61736d2d646174612d7374" +
				"6174652e7631170000000000000001000000000000000000000000000000",
			sum: "efd01bacb8219cb04227a6770ed3cd64ee98acc9e302336b93020df80ceb04e2",
		},
		{
			name: "compound", value: compound,
			encoded: "1e00000000000000706c616e3961736d2e73646b2d61736d2d646174612d7374" +
				"6174652e763119000000000000002500000000000000706c616e3961736d2e73" +
				"646b41534d44617461446967657374476f6c64656e5265636f72640400000000" +
				"0000004e616d6518000000000000000200000000000000610003000000000000" +
				"005261771700000000000000010000000000000007000000000000007b226b22" +
				"3a317d0500000000000000436f756e7416000000000000000100000000000000" +
				"0a0000000000000007000000000000000500000000000000466c616773110000" +
				"0000000000020000000000000001000000000000000100000000000000010000" +
				"00000000000000000000000000060000000000000056616c7565731500000000" +
				"0000000100000000000000020000000000000001000000000000006117000000" +
				"0000000000000000000000000100000000000000621700000000000000010000" +
				"000000000000000000000000000000000000000000",
			sum: "1c6fba47b7b9ab2601df8bcff515c93c9355cda8090e5f1519cddc7888ac6648",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			want, err := hex.DecodeString(test.encoded)
			if err != nil {
				t.Fatal(err)
			}
			got, sum := sdkASMDataDigestReferenceBytes(t, test.value)
			if !bytes.Equal(got, want) || fmt.Sprintf("%x", sum) != test.sum {
				t.Fatal("serialization differs from fixed independent golden")
			}
		})
	}
}
