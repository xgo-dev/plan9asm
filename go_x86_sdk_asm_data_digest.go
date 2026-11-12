package plan9asm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"reflect"
	"sort"
	"strings"
	"time"
)

// The state seal is private, not a serialized observation protocol. Stream the
// complete current state instead of making base64/JSON copies of object and
// listing payloads on every live check. No observation or payload digest is
// cached. Kind tags, field names and length frames keep the encoding unambiguous.
func digestSDKASMDataState(state any) ([32]byte, error) {
	encoder := sdkASMDataDigestEncoder{hash: sha256.New()}
	encoder.text("plan9asm.sdk-asm-data-state.v1")
	if err := encoder.value(reflect.ValueOf(state), 0); err != nil {
		return [32]byte{}, err
	}
	encoder.flush()
	var sum [32]byte
	copy(sum[:], encoder.hash.Sum(sum[:0]))
	return sum, nil
}

type sdkASMDataDigestEncoder struct {
	hash    hash.Hash
	scratch [4096]byte
	used    int
	structs map[reflect.Type]sdkASMDataDigestStruct
}

type sdkASMDataDigestStruct struct {
	name   string
	fields []sdkASMDataDigestField
}

type sdkASMDataDigestField struct {
	index int
	name  string
}

// Plans contain immutable, direct type metadata and live for one digest only.
// Every value, payload and validity check still reads the current state; plans
// do not retain reflect.Values or recursively build plans for field types.
func (encoder *sdkASMDataDigestEncoder) structPlan(typ reflect.Type) sdkASMDataDigestStruct {
	if plan, ok := encoder.structs[typ]; ok {
		return plan
	}
	plan := sdkASMDataDigestStruct{name: typ.String()}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "-" {
			plan.fields = append(plan.fields, sdkASMDataDigestField{index: i, name: field.Name})
		}
	}
	if encoder.structs == nil {
		encoder.structs = make(map[reflect.Type]sdkASMDataDigestStruct)
	}
	encoder.structs[typ] = plan
	return plan
}

func (encoder *sdkASMDataDigestEncoder) flush() {
	_, _ = encoder.hash.Write(encoder.scratch[:encoder.used]) // SHA256 writes cannot fail.
	encoder.used = 0
}

func (encoder *sdkASMDataDigestEncoder) number(value uint64) {
	if len(encoder.scratch)-encoder.used < 8 {
		encoder.flush()
	}
	binary.LittleEndian.PutUint64(encoder.scratch[encoder.used:encoder.used+8], value)
	encoder.used += 8
}

func (encoder *sdkASMDataDigestEncoder) text(value string) {
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

func (encoder *sdkASMDataDigestEncoder) bytes(value []byte) {
	// Large existing payloads go directly to SHA256; only metadata is buffered.
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

var sdkASMDataDigestTime = reflect.TypeOf(time.Time{})
var sdkASMDataDigestRawJSON = reflect.TypeOf(json.RawMessage{})

func (encoder *sdkASMDataDigestEncoder) value(value reflect.Value, depth int) error {
	if depth > 64 || !value.IsValid() {
		return fmt.Errorf("SDK ASM DATA digest has an invalid or recursive state")
	}
	encoder.number(uint64(value.Kind()))
	if value.Type() == sdkASMDataDigestTime {
		// Keep time's original JSON role, including its range validation and
		// exclusion of process-local monotonic clock metadata.
		raw, err := value.Interface().(time.Time).MarshalJSON()
		if err != nil {
			return err
		}
		encoder.text(string(raw))
		return nil
	}
	if value.Type() == sdkASMDataDigestRawJSON && !value.IsNil() && !json.Valid(value.Bytes()) {
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
		plan := encoder.structPlan(value.Type())
		encoder.text(plan.name)
		for _, field := range plan.fields {
			encoder.text(field.name)
			if err := encoder.value(value.Field(field.index), depth+1); err != nil {
				return err
			}
		}
		encoder.text("") // End this struct independently of its parent's next field.
	default:
		return fmt.Errorf("SDK ASM DATA digest has an unsupported state kind: %s", value.Kind())
	}
	return nil
}

func (encoder *sdkASMDataDigestEncoder) elements(value reflect.Value, depth int) error {
	for i := 0; i < value.Len(); i++ {
		if err := encoder.value(value.Index(i), depth+1); err != nil {
			return err
		}
	}
	return nil
}
