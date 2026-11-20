package plan9asm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type sdkAMD64FrameNativeRecord = goAMD64NativeHeader

type sdkAMD64FrameNativeObservation struct {
	Source                         string
	OriginalListing, MappedListing []byte
	Records                        []sdkAMD64FrameNativeRecord
}

// Both native listings share one explicit SDK-primary representation bound.
// Ordinary/CPU source, CPP, event and token budgets are unchanged. Charge a
// complete command result before retaining its command or frame projection.
const sdkAMD64FrameListingBytes = 16 << 20

func (source *GoX86SDKASMDataSource) retainSDKFrameListingBytes(bytes int) error {
	if bytes < 0 || source.frameListingBytes < 0 || bytes > sdkAMD64FrameListingBytes-source.frameListingBytes {
		return sdkASMDataContext("SDK-primary native listings exceed their explicit byte bound")
	}
	source.frameListingBytes += bytes
	source.observation.FrameListingBytes = source.frameListingBytes
	return nil
}

// FuncInfo.Locals is int32, but the official listing writer prints uint64.
// Decode its canonical sign extension without interpreting it as an extent.
func goAMD64FrameSignedLocals(raw string) (int64, error) {
	bits, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return 0, err
	}
	value := int64(int32(bits))
	if uint64(value) != bits {
		return 0, fmt.Errorf("noncanonical signed int32 locals: %s", raw)
	}
	return value, nil
}

func sdkAMD64FrameNativeRecords(listing []byte, texts []gostaticstorage.TextRecord) ([]sdkAMD64FrameNativeRecord, error) {
	return sdkAMD64FrameNativeRecordsInOrder(listing, texts, nil)
}

func sdkAMD64FrameNativeRecordsForSource(listing []byte, texts []gostaticstorage.TextRecord, order []gostaticstorage.ASMSourceText) ([]sdkAMD64FrameNativeRecord, error) {
	if len(order) != len(texts) {
		return nil, sdkASMDataContext("SDK-primary native source/object ordinal association is incomplete")
	}
	indices := make([]int, len(order))
	seen := make(map[int]bool, len(order))
	for ordinal, association := range order {
		index := association.ObjectOrdinal
		if association.SourceOrdinal != ordinal || index < 0 || index >= len(texts) || seen[index] {
			return nil, sdkASMDataContext("SDK-primary native source/object ordinal association is duplicate or unbound")
		}
		text := texts[index]
		if association.Name != text.Name || association.ABI != text.ABI || association.Namespace != text.Namespace ||
			association.Relative != text.Relative || association.Index != text.Index {
			return nil, sdkASMDataContext("SDK-primary native source/object physical association differs")
		}
		indices[ordinal], seen[index] = index, true
	}
	return sdkAMD64FrameNativeRecordsInOrder(listing, texts, indices)
}

// nil indices is the existing format-only diagnostic helper. Production SDK
// capture always supplies the independently source-derived association; no
// original TextRecord is reordered or rewritten to resemble source evidence.
func sdkAMD64FrameNativeRecordsInOrder(listing []byte, texts []gostaticstorage.TextRecord, indices []int) ([]sdkAMD64FrameNativeRecord, error) {
	var records []sdkAMD64FrameNativeRecord
	scanner := bufio.NewScanner(bytes.NewReader(listing))
	scanner.Buffer(nil, 4<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, " STEXT ") && !strings.Contains(line, " STEXTFIPS ") {
			continue // Complete native objects validate every other record.
		}
		header, valid := parseGoAMD64NativeHeader(line)
		if !valid || len(records) >= len(texts) {
			return nil, sdkASMDataContext("SDK-primary native frame header has an unbound role or inventory")
		}
		index := len(records)
		if indices != nil {
			index = indices[index]
		}
		text := texts[index]
		if text.Size < 0 || header.Symbol != text.Name || header.Kind != text.Kind ||
			header.Size != uint64(text.Size) || header.Size != uint64(len(text.Code)) ||
			header.objectFlags() != text.Flags&0x19 {
			return nil, sdkASMDataContext("SDK-primary complete native frame/object TEXT differs")
		}
		if indices != nil && header.Static != (text.ABI == 65535) {
			return nil, sdkASMDataContext("SDK-primary native listing static/ABI source role differs")
		}
		records = append(records, header)
	}
	if err := scanner.Err(); err != nil || len(records) != len(texts) {
		return nil, sdkASMDataContext("SDK-primary native frame inventory is incomplete: %v", err)
	}
	return records, nil
}

func (source *GoX86SDKASMDataSource) captureSDKFrameListings(ctx context.Context) error {
	for _, role := range []string{"src/internal/abi/symtab.go", "src/cmd/asm/internal/asm/asm.go", "src/cmd/internal/obj/objfile.go"} {
		if _, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(role))); err != nil {
			return err
		}
	}
	for ordinal, input := range source.observation.ObjectInputs.Sources {
		var objects, listings [2][]byte
		paths := [2]string{filepath.Join(source.request.Directory, input.Name), filepath.Join(source.guard.owned, fmt.Sprintf("expanded-%d.s", ordinal))}
		for role, path := range paths {
			object := filepath.Join(source.guard.owned, fmt.Sprintf("frame-%d-%d.o", ordinal, role))
			args := append(source.asmArguments(source.guard.owned), "-S", "-o", object, path)
			listing, err := source.run(ctx, args...)
			if err != nil {
				return err
			}
			objects[role], err = source.guard.read(object)
			if err != nil {
				return err
			}
			if _, err := source.artifact(fmt.Sprintf("frame-%d-%d.listing", ordinal, role), listing); err != nil {
				return err
			}
			listings[role] = listing
		}
		original, mapped, err := gostaticstorage.ObserveX86SDKASMDataListingObjects(source.observation.ObjectInputs, ordinal, objects[0], objects[1])
		if err != nil {
			return sdkASMDataContext("SDK-primary original/mapped/archive complete frame object join: %v", err)
		}
		order := source.observation.Objects.Sources[ordinal].TextOrder
		first, err := sdkAMD64FrameNativeRecordsForSource(listings[0], original, order)
		if err != nil {
			return err
		}
		second, err := sdkAMD64FrameNativeRecordsForSource(listings[1], mapped, order)
		if err != nil || !reflect.DeepEqual(first, second) {
			return sdkASMDataContext("SDK-primary original/mapped complete native frame metadata differs: %v", err)
		}
		source.observation.Frames = append(source.observation.Frames, sdkAMD64FrameNativeObservation{
			Source: input.Name, OriginalListing: listings[0], MappedListing: listings[1], Records: first,
		})
	}
	return nil
}
