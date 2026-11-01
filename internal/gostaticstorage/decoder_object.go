package gostaticstorage

import "strings"

// DecoderObjectFormatSourceHashes returns observation-format pins, not source
// authority. The producer must independently read and retain these SDK files.
func DecoderObjectFormatSourceHashes() map[string]string {
	result := make(map[string]string, len(formatSources))
	for name, hash := range formatSources {
		result[name] = hash
	}
	return result
}

// ObserveDecoderARM64Object checks the complete ordinary tool-asm object used
// by the decoder oracle. It is a byte-kind observation, not a source, native
// TEXT entry, relocation/linkability or execution permission. The command has
// no -p flag, so the original Go writer requires FromAssembly|Unlinkable (12).
func ObserveDecoderARM64Object(data []byte, symbol string) error {
	if len(data) == 0 || len(data) > archiveLimit ||
		!strings.HasPrefix(symbol, "<unlinkable>.probe") || strings.ContainsAny(symbol, "\x00\r\n") {
		return contextError("invalid decoder object extent or expected symbol")
	}
	body, err := objectBody(data, "linux/arm64")
	if err != nil {
		return err
	}
	object, err := checkedObject(body, 12, false)
	if err != nil {
		return err
	}
	symbols, err := object.indexedSymbols()
	if err != nil {
		return err
	}
	texts := 0
	for _, observed := range symbols {
		if observed.Namespace == TextSymbolNonpkgReference || observed.Kind != 1 {
			continue
		}
		texts++
		if observed.Name != symbol || observed.Size == 0 || int(observed.Index) >= object.count {
			return contextError("decoder object does not define this exact nonempty probe TEXT")
		}
		start, end := object.indices[2][observed.Index], object.indices[2][observed.Index+1]
		if end-start != observed.Size {
			return contextError("decoder TEXT extent differs from its complete object data")
		}
	}
	if texts != 1 {
		return contextError("decoder object must contain exactly one current probe TEXT")
	}
	return nil
}
